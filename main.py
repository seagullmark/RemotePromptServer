"""FastAPI application exposing the Remote Job Server API."""
from __future__ import annotations

import asyncio
import uuid
import json
import logging
from pathlib import Path
from typing import List, Optional

from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Header,
    Query,
    Request,
    Response,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from contextlib import asynccontextmanager

from config import setup_logging, settings, get_ssl_paths, is_certificate_fallback_warning
from cert_generator import (
    ensure_certificate_exists,
    get_certificate_fingerprint,
    get_certificate_info,
    regenerate_certificate,
    revoke_certificate,
    print_certificate_banner,
)
from qr_generator import (
    generate_qr_png_base64,
    generate_config_payload,
    print_qr_banner,
    ensure_qr_code_exists,
)
from bonjour_publisher import (
    start_bonjour_service_async,
    stop_bonjour_service_async,
    update_bonjour_fingerprint,
)
from database import SessionLocal, init_db
from job_manager import JobManager
from models import Device, DeviceSession, Job, Room, Thread, utcnow
from session_manager import SessionManager
from sse_manager import sse_manager
from utils.path_validator import validate_workspace_path
from utils.settings_validator import (
    ALLOWED_VALUES,
    RESERVED_FLAGS,
    DANGEROUS_FLAGS,
    SHELL_META_CHARS,
    ValidationError,
    validate_settings,
)
from auth_helpers import verify_room_ownership
from file_operations import (
    list_files,
    read_file,
    read_image_file,
    read_pdf_file,
    write_file,
    write_image_file,
    ImageWriteResult,
    WriteResult,
)
from file_security import ALLOWED_IMAGE_EXTENSIONS, FileSizeExceeded, InvalidExtension, InvalidPath

# Setup logging BEFORE any manager initialization
setup_logging()

LOGGER = logging.getLogger(__name__)

# Global state for SSL mode tracking
_current_ssl_mode: str = "unknown"
_current_cert_fingerprint: str = ""
_pending_cert_restart: bool = False
_pending_cert_fingerprint: str = ""


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: D417 - FastAPI lifespan signature
    global _current_ssl_mode, _current_cert_fingerprint
    global _pending_cert_restart, _pending_cert_fingerprint

    init_db()

    # Initialize SSL certificate
    try:
        cert_path, key_path, mode_used = get_ssl_paths()
        _current_ssl_mode = mode_used

        # For self-signed mode, ensure certificate exists
        if mode_used == "self_signed" and settings.ssl_auto_generate:
            cert_path, key_path, fingerprint = ensure_certificate_exists(
                hostname=settings.server_hostname,
                san_ips=settings.get_san_ips_list(),
            )
            _current_cert_fingerprint = fingerprint
        else:
            _current_cert_fingerprint = get_certificate_fingerprint(cert_path)

        # Reset pending state on startup (new certificate is now active)
        _pending_cert_restart = False
        _pending_cert_fingerprint = ""

        LOGGER.info(
            "[SSL] Using %s certificate: %s",
            mode_used,
            cert_path,
        )

        # Print banner for self-signed certificates
        server_url = f"https://{settings.server_hostname}:{settings.server_port}"
        if mode_used == "self_signed":
            print_certificate_banner(cert_path, server_url)

        # Generate QR code image file (always, for iOS app scanning)
        qr_path = ensure_qr_code_exists(
            server_url=server_url,
            api_key=settings.api_key,
            fingerprint=_current_cert_fingerprint,
            server_name=settings.bonjour_service_name,
        )
        LOGGER.info("[QR] QR code saved to: %s", qr_path)

        # Show QR code in terminal if enabled (via SHOW_QR_ON_STARTUP=true)
        if settings.show_qr_on_startup:
            print_qr_banner(
                server_url=server_url,
                api_key=settings.api_key,
                fingerprint=_current_cert_fingerprint,
                server_name=settings.bonjour_service_name,
            )

    except RuntimeError as e:
        LOGGER.error("[SSL] Failed to initialize certificates: %s", e)
        raise

    # Start Bonjour service for local network discovery
    if settings.bonjour_enabled:
        try:
            # hostname=None で socket.gethostname() を自動使用
            # server_hostname は SSL/TLS 証明書用であり、Bonjour には不適切
            await start_bonjour_service_async(
                port=settings.server_port,
                hostname=None,  # 自動取得
                server_name=settings.bonjour_service_name,
                fingerprint=_current_cert_fingerprint,
                ssl_mode=_current_ssl_mode,
            )
            LOGGER.info("[Bonjour] Service published: _remoteprompt._tcp")
        except Exception as e:
            LOGGER.warning("[Bonjour] Failed to start service: %s", e)
            # Bonjour failure is not fatal, continue startup

    yield

    # Cleanup: Stop Bonjour service
    if settings.bonjour_enabled:
        try:
            await stop_bonjour_service_async()
            LOGGER.info("[Bonjour] Service stopped")
        except Exception as e:
            LOGGER.warning("[Bonjour] Error stopping service: %s", e)


app = FastAPI(title="Remote Job Server", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

session_manager = SessionManager()
job_manager = JobManager(session_manager=session_manager, sse_manager=sse_manager)
ALLOWED_RUNNERS = {"claude", "codex", "gemini"}
MAX_SETTINGS_BYTES = 10_240  # 10KB


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class RegisterDeviceRequest(BaseModel):
    device_id: str
    device_token: str


class CreateJobRequest(BaseModel):
    runner: str
    input_text: str
    device_id: str
    room_id: Optional[str] = None
    notify_token: Optional[str] = None
    thread_id: Optional[str] = None


class CreateRoomRequest(BaseModel):
    device_id: str
    name: str
    workspace_path: str
    icon: str = "folder"


class UpdateRoomRequest(BaseModel):
    device_id: str
    name: str
    workspace_path: str
    icon: str = "folder"


class JobSummary(BaseModel):
    id: str
    runner: str
    status: str


class ThreadResponse(BaseModel):
    id: str
    room_id: str
    name: str
    device_id: str
    has_unread: bool = False
    unread_runners: List[str] = []  # v4.3.1: runner別未読リスト
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class CreateThreadRequest(BaseModel):
    name: Optional[str] = None


class UpdateThreadRequest(BaseModel):
    name: Optional[str] = None


def verify_api_key(x_api_key: str = Header(...)) -> None:
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid API Key")


def ensure_room_owned(room_id: str, device_id: str, db: Session) -> Room:
    room = db.query(Room).filter_by(id=room_id).first()
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")
    if room.device_id != device_id:
        raise HTTPException(status_code=403, detail="Room not owned by device")
    return room


def _get_or_create_default_thread(db: Session, room: Room, runner: str) -> Thread:
    # v4.2: runnerカラム削除により、最古のThreadを返す（runner不問）
    thread = (
        db.query(Thread)
        .filter_by(room_id=room.id)
        .order_by(Thread.created_at.asc())
        .first()
    )
    if thread:
        LOGGER.info("[COMPAT] Using default thread %s for room=%s (runner=%s)", thread.id, room.id, runner)
        return thread

    # デフォルトThread作成（runnerカラムなし）
    thread = Thread(
        room_id=room.id,
        name=f"{runner.title()} 会話",
        device_id=room.device_id,
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    db.add(thread)
    db.commit()
    db.refresh(thread)
    LOGGER.warning("[COMPAT] Created default thread %s for room=%s runner=%s", thread.id, room.id, runner)
    return thread


# ========== Room Management APIs ==========


@app.get("/rooms")
def get_rooms(
    device_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> List[dict]:
    # sort_orderでソート（小さい順）、同じ場合はupdated_atで降順
    rooms = db.query(Room).filter_by(device_id=device_id).order_by(Room.sort_order.asc(), Room.updated_at.desc()).all()

    # v4.3.2: 各Roomの未読スレッド数を取得
    result = []
    for room in rooms:
        room_dict = room.to_dict()
        unread_count = db.query(Thread).filter(
            Thread.room_id == room.id,
            Thread.has_unread == True,  # noqa: E712
        ).count()
        room_dict["unread_count"] = unread_count
        result.append(room_dict)
    return result


@app.post("/rooms")
def create_room(
    req: CreateRoomRequest,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> dict:
    try:
        validated_path = validate_workspace_path(req.workspace_path)
    except ValueError as exc:
        LOGGER.warning("[ROOM] Failed to create room: %s (device_id=%s, workspace_path=%s)", 
                      str(exc), req.device_id, req.workspace_path)
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # 新しいRoomは最後に追加（既存の最大sort_order + 1）
    max_order = db.query(Room).filter_by(device_id=req.device_id).count()

    room = Room(
        id=str(uuid.uuid4()),
        name=req.name,
        workspace_path=validated_path,
        icon=req.icon,
        device_id=req.device_id,
        sort_order=max_order,
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    db.add(room)
    db.commit()
    db.refresh(room)
    return room.to_dict()


@app.delete("/rooms/{room_id}")
def delete_room(
    room_id: str,
    device_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> dict:
    room = db.query(Room).filter_by(id=room_id).first()
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")
    if room.device_id != device_id:
        raise HTTPException(status_code=403, detail="Forbidden")

    db.query(DeviceSession).filter_by(room_id=room_id).delete()
    db.query(Job).filter_by(room_id=room_id).delete()
    db.delete(room)
    db.commit()
    return {"status": "ok"}


@app.put("/rooms/{room_id}")
def update_room(
    room_id: str,
    req: UpdateRoomRequest,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> dict:
    """ルームの名前、ワークスペースパス、アイコンを更新する。"""
    room = db.query(Room).filter_by(id=room_id).first()
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")
    if room.device_id != req.device_id:
        raise HTTPException(status_code=403, detail="Forbidden")

    try:
        validated_path = validate_workspace_path(req.workspace_path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    room.name = req.name
    room.workspace_path = validated_path
    room.icon = req.icon
    room.updated_at = utcnow()
    db.commit()
    db.refresh(room)
    return room.to_dict()


class ReorderRoomsRequest(BaseModel):
    """Request body for reordering rooms."""
    device_id: str
    room_ids: List[str]  # 新しい順序でのRoom IDリスト


@app.put("/rooms/reorder")
def reorder_rooms(
    req: ReorderRoomsRequest,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> dict:
    """Room の並び順を更新する。room_ids の順序で sort_order を設定。"""
    # 全Roomを取得して所有権確認
    rooms = db.query(Room).filter(Room.id.in_(req.room_ids)).all()
    room_map = {r.id: r for r in rooms}

    for room in rooms:
        if room.device_id != req.device_id:
            raise HTTPException(status_code=403, detail="Forbidden")

    # 並び順を更新
    for idx, room_id in enumerate(req.room_ids):
        if room_id in room_map:
            room_map[room_id].sort_order = idx

    db.commit()
    return {"status": "ok"}


# ========== Room Settings APIs ==========


@app.get("/rooms/{room_id}/settings")
async def get_room_settings(
    room_id: str,
    device_id: str = Query(...),
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> dict:
    room = await verify_room_ownership(room_id=room_id, device_id=device_id, db=db)
    try:
        parsed = json.loads(room.settings) if room.settings else None
    except json.JSONDecodeError:
        parsed = None
    return {"room_id": room_id, "settings": parsed}


@app.put("/rooms/{room_id}/settings")
async def update_room_settings(
    room_id: str,
    request: Request,
    device_id: str = Query(...),
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> dict:
    room = await verify_room_ownership(room_id=room_id, device_id=device_id, db=db)

    body = await request.body()
    if len(body) > MAX_SETTINGS_BYTES:
        raise HTTPException(status_code=413, detail="Settings JSON exceeds 10KB limit")

    # null または空ボディ: 設定リセット
    if not body or body.strip() == b"null":
        room.settings = None
        room.updated_at = utcnow()
        db.commit()
        return {"room_id": room_id, "settings": None}

    try:
        payload = json.loads(body.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="Request body must be UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {exc.msg}") from exc

    settings_obj = payload if payload is not None else None
    try:
        sanitized = validate_settings(settings_obj)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    room.settings = json.dumps(sanitized) if sanitized is not None else None
    room.updated_at = utcnow()
    db.commit()
    return {"room_id": room_id, "settings": sanitized}


# ========== Thread Management APIs ==========


@app.get("/rooms/{room_id}/threads", response_model=List[ThreadResponse])
def list_threads(
    room_id: str,
    device_id: str = Query(...),
    limit: int = Query(50, ge=1, description="Maximum number of threads to return (default: 50, max: 200)"),
    offset: int = Query(0, ge=0, description="Number of threads to skip (default: 0)"),
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> List[ThreadResponse]:
    # v4.2: limitの最大値検証（200超過時400エラー）
    if limit > 200:
        raise HTTPException(status_code=400, detail="limit must not exceed 200")

    room = ensure_room_owned(room_id, device_id, db)
    query = db.query(Thread).filter_by(room_id=room.id)

    # v4.1: ページネーション適用
    threads = (
        query
        .order_by(Thread.updated_at.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return [ThreadResponse(**t.to_dict()) for t in threads]


@app.post("/rooms/{room_id}/threads", response_model=ThreadResponse)
def create_thread(
    room_id: str,
    req: CreateThreadRequest,
    device_id: str = Query(...),
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> ThreadResponse:
    room = ensure_room_owned(room_id, device_id, db)

    name = (req.name or "無題").strip()
    if not name or len(name) > 100:
        raise HTTPException(status_code=400, detail="Name must be 1-100 characters")

    thread = Thread(
        room_id=room.id,
        name=name,
        device_id=room.device_id,
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    db.add(thread)
    db.commit()
    db.refresh(thread)
    LOGGER.info("[NEW] Created thread %s room=%s", thread.id, room.id)
    return ThreadResponse(**thread.to_dict())


@app.patch("/threads/{thread_id}", response_model=ThreadResponse)
def update_thread(
    thread_id: str,
    req: UpdateThreadRequest,
    device_id: str = Query(...),
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> ThreadResponse:
    thread = db.query(Thread).filter_by(id=thread_id).first()
    if not thread:
        raise HTTPException(status_code=404, detail="Thread not found")
    room = ensure_room_owned(thread.room_id, device_id, db)
    if req.name is not None:
        name = req.name.strip()
        if not name or len(name) > 100:
            raise HTTPException(status_code=400, detail="Name must be 1-100 characters")
        thread.name = name
    thread.updated_at = utcnow()
    db.commit()
    db.refresh(thread)
    LOGGER.info("[NEW] Updated thread %s room=%s", thread.id, room.id)
    return ThreadResponse(**thread.to_dict())


@app.delete("/threads/{thread_id}", status_code=204)
def delete_thread(
    thread_id: str,
    device_id: str = Query(...),
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> Response:
    thread = db.query(Thread).filter_by(id=thread_id).first()
    if not thread:
        raise HTTPException(status_code=404, detail="Thread not found")
    ensure_room_owned(thread.room_id, device_id, db)
    db.delete(thread)
    db.commit()
    LOGGER.info("[NEW] Deleted thread %s", thread_id)
    return Response(status_code=204)


@app.put("/threads/{thread_id}/read", response_model=ThreadResponse)
def mark_thread_read(
    thread_id: str,
    device_id: str = Query(...),
    runner: Optional[str] = Query(None),  # v4.3.1: 特定runnerを既読にする（なければ全て既読）
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> ThreadResponse:
    """Mark a thread as read (clear unread flag for specific runner or all)."""
    import json
    thread = db.query(Thread).filter_by(id=thread_id).first()
    if not thread:
        raise HTTPException(status_code=404, detail="Thread not found")
    ensure_room_owned(thread.room_id, device_id, db)

    # v4.3.1: runner指定時はそのrunnerだけを既読に、なければ全て既読
    if runner:
        unread_list = []
        if thread.unread_runners:
            try:
                unread_list = json.loads(thread.unread_runners)
            except (json.JSONDecodeError, TypeError):
                unread_list = []
        if runner in unread_list:
            unread_list.remove(runner)
        thread.unread_runners = json.dumps(unread_list)
        thread.has_unread = len(unread_list) > 0
        LOGGER.info("[READ] Thread %s marked runner=%s as read (remaining=%s)", thread_id, runner, unread_list)
    else:
        thread.unread_runners = "[]"
        thread.has_unread = False
        LOGGER.info("[READ] Thread %s marked all as read", thread_id)

    db.commit()
    db.refresh(thread)
    return ThreadResponse(**thread.to_dict())


# ========== File Browser APIs ==========


@app.get("/rooms/{room_id}/files")
async def list_room_files(
    room_id: str,
    device_id: str = Query(...),
    path: str = Query(""),
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> List[dict]:
    room = await verify_room_ownership(room_id=room_id, device_id=device_id, db=db)
    try:
        return list_files(workspace_path=room.workspace_path, relative_path=path)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Directory not found")
    except (InvalidPath, InvalidExtension) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/rooms/{room_id}/files/{filepath:path}")
async def get_room_file(
    room_id: str,
    filepath: str,
    device_id: str = Query(...),
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> Response:
    room = await verify_room_ownership(room_id=room_id, device_id=device_id, db=db)

    # ファイル拡張子に応じて読み込み方法を切り替え
    suffix = "." + filepath.lower().rsplit(".", 1)[-1] if "." in filepath else ""
    is_pdf = suffix == ".pdf"
    is_image = suffix in ALLOWED_IMAGE_EXTENSIONS

    # 画像のMIMEタイプ
    image_mime_types = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".heic": "image/heic",
    }

    try:
        if is_pdf:
            content = read_pdf_file(workspace_path=room.workspace_path, file_path=filepath)
            return Response(content=content, media_type="application/pdf")
        elif is_image:
            content = read_image_file(workspace_path=room.workspace_path, file_path=filepath)
            mime_type = image_mime_types.get(suffix, "application/octet-stream")
            return Response(content=content, media_type=mime_type)
        else:
            content = read_file(workspace_path=room.workspace_path, file_path=filepath)
            return Response(content=content, media_type="text/plain; charset=utf-8")
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="File not found")
    except FileSizeExceeded as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except (InvalidPath, InvalidExtension) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except PermissionError:
        raise HTTPException(status_code=403, detail="Permission denied")


@app.put("/rooms/{room_id}/files/{filepath:path}")
async def put_room_file(
    room_id: str,
    filepath: str,
    request: Request,
    device_id: str = Query(...),
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> dict:
    room = await verify_room_ownership(room_id=room_id, device_id=device_id, db=db)

    try:
        body_bytes = await request.body()
        content = body_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="Request body must be UTF-8") from exc

    try:
        result: WriteResult = write_file(
            workspace_path=room.workspace_path, file_path=filepath, content=content
        )
    except FileSizeExceeded as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except (InvalidPath, InvalidExtension) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="File or directory not found")
    except PermissionError:
        raise HTTPException(status_code=403, detail="Permission denied")

    return {
        "message": "File saved",
        "path": filepath,
        "size": result.size,
        "backup_created": result.backup_created,
    }


@app.post("/rooms/{room_id}/files/upload")
async def upload_image_file(
    room_id: str,
    file: UploadFile = File(...),
    device_id: str = Form(...),
    directory_path: str = Form(""),
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> dict:
    """Upload an image file to the specified directory.

    If a file with the same name exists, appends _1, _2, etc. to the filename.
    Supported formats: PNG, JPEG, GIF, HEIC
    """
    room = await verify_room_ownership(room_id=room_id, device_id=device_id, db=db)

    # ファイル名を取得
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required")

    # ファイルデータを読み込み
    try:
        data = await file.read()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to read file: {exc}") from exc

    LOGGER.info(
        "[UPLOAD] room_id=%s, filename=%s, directory_path='%s', data_size=%d",
        room_id, file.filename, directory_path, len(data)
    )

    try:
        result: ImageWriteResult = write_image_file(
            workspace_path=room.workspace_path,
            directory_path=directory_path,
            filename=file.filename,
            data=data,
        )
    except FileSizeExceeded as exc:
        LOGGER.error("[UPLOAD] FileSizeExceeded: %s", exc)
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except (InvalidPath, InvalidExtension) as exc:
        LOGGER.error("[UPLOAD] InvalidPath/Extension: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        LOGGER.error("[UPLOAD] FileNotFoundError: %s", exc)
        raise HTTPException(status_code=404, detail="Directory not found")
    except PermissionError as exc:
        LOGGER.error("[UPLOAD] PermissionError: %s", exc)
        raise HTTPException(status_code=403, detail="Permission denied")

    return {
        "message": "Image uploaded",
        "path": result.saved_path,
        "size": result.size,
    }


@app.post("/register_device")
def register_device(
    req: RegisterDeviceRequest,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> dict:
    device = db.query(Device).filter_by(device_id=req.device_id).first()
    if device:
        device.device_token = req.device_token
        device.updated_at = utcnow()
    else:
        device = Device(
            device_id=req.device_id,
            device_token=req.device_token,
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        db.add(device)
    db.commit()
    return {"status": "registered"}


@app.post("/jobs", response_model=JobSummary)
def create_job(
    req: CreateJobRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> JobSummary:
    if req.runner not in ALLOWED_RUNNERS:
        raise HTTPException(status_code=400, detail="Unsupported runner")
    if not req.room_id:
        raise HTTPException(status_code=400, detail="room_id is required")
    room = ensure_room_owned(req.room_id, req.device_id, db)

    if req.thread_id:
        thread = db.query(Thread).filter_by(id=req.thread_id).first()
        if not thread:
            raise HTTPException(status_code=404, detail="Thread not found")
        if thread.room_id != room.id:
            raise HTTPException(status_code=400, detail="Thread does not belong to room")
        # v4.2: thread.runner チェック削除 - 同一Thread内でrunner自由切替可能
        thread_id = thread.id
        LOGGER.info("[NEW] /jobs using thread_id=%s room=%s runner=%s", thread_id, room.id, req.runner)
    else:
        if not settings.threads_compat_mode:
            raise HTTPException(status_code=400, detail="thread_id is required when THREADS_COMPAT_MODE=false")
        thread = _get_or_create_default_thread(db, room, req.runner)
        thread_id = thread.id

    # v4.3.2: ジョブ送信時、送信runnerの未読をクリア（自分で見ているので）
    if thread:
        unread_list = []
        if thread.unread_runners:
            try:
                unread_list = json.loads(thread.unread_runners)
            except (json.JSONDecodeError, TypeError):
                unread_list = []
        if req.runner in unread_list:
            unread_list.remove(req.runner)
            thread.unread_runners = json.dumps(unread_list)
            thread.has_unread = len(unread_list) > 0
            db.commit()
            LOGGER.info("[JOB] Cleared unread for runner=%s on thread=%s", req.runner, thread_id)
    try:
        room_settings = json.loads(room.settings) if room.settings else None
    except json.JSONDecodeError:
        room_settings = None
    try:
        job = job_manager.create_job(
            runner=req.runner,
            input_text=req.input_text,
            device_id=req.device_id,
            room_id=req.room_id,
            workspace_path=room.workspace_path,
            settings=room_settings,
            thread_id=thread_id,
            notify_token=req.notify_token,
            background_tasks=background_tasks,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return JobSummary(id=job["id"], runner=job["runner"], status=job["status"])


@app.get("/jobs")
def list_jobs(
    limit: int = 20,
    status: Optional[str] = None,
    device_id: Optional[str] = None,
    _: None = Depends(verify_api_key),
) -> List[dict]:
    return job_manager.get_jobs(limit=limit, status=status, device_id=device_id)


@app.get("/jobs/{job_id}")
def get_job(job_id: str, _: None = Depends(verify_api_key)) -> dict:
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@app.get("/jobs/{job_id}/stream", dependencies=[Depends(verify_api_key)])
async def stream_job_status(job_id: str, request: Request) -> StreamingResponse:
    """Stream job status updates via Server-Sent Events."""

    async def event_generator():
        # 初期スナップショット送信（高速完了レース対策）
        job_dict = job_manager.get_job(job_id)
        if job_dict:
            initial_payload = {
                "status": job_dict.get("status"),
                "started_at": job_dict.get("started_at"),  # Already ISO8601 string from to_dict()
                "finished_at": job_dict.get("finished_at"),  # Already ISO8601 string from to_dict()
                "exit_code": job_dict.get("exit_code"),
            }
            yield f"data: {json.dumps(initial_payload)}\n\n"
            LOGGER.info(
                "[SSE-INITIAL] job_id=%s, sent snapshot status=%s",
                job_id,
                job_dict.get("status"),
            )

            if job_dict.get("status") in {"success", "failed"}:
                LOGGER.info(
                    "[SSE-INITIAL] job_id=%s, terminal state (%s), closing stream",
                    job_id,
                    job_dict.get("status"),
                )
                return

        try:
            async for message in sse_manager.subscribe(job_id):
                if await request.is_disconnected():
                    LOGGER.info("Client disconnected during SSE stream for job %s", job_id)
                    break
                yield message
        finally:
            LOGGER.info("SSE event_generator completed for job %s", job_id)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/messages")
def get_messages(
    device_id: str,
    room_id: str,
    runner: str,
    thread_id: Optional[str] = Query(None),
    limit: int = 20,
    offset: int = 0,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> List[dict]:
    room = ensure_room_owned(room_id, device_id, db)
    query = db.query(Job).filter_by(device_id=device_id, room_id=room_id, runner=runner)

    if thread_id:
        thread = db.query(Thread).filter_by(id=thread_id).first()
        if not thread:
            raise HTTPException(status_code=404, detail="Thread not found")
        if thread.room_id != room.id:
            raise HTTPException(status_code=400, detail="Thread does not belong to room")
        # v4.2: thread.runner チェック削除 - 同一Thread内でrunner自由切替可能
        query = query.filter(Job.thread_id == thread_id)
        LOGGER.info("[NEW] /messages thread_id=%s room=%s runner=%s", thread_id, room.id, runner)
    else:
        if not settings.threads_compat_mode:
            raise HTTPException(status_code=400, detail="thread_id is required when THREADS_COMPAT_MODE=false")
        LOGGER.info("[COMPAT] /messages without thread_id room=%s runner=%s", room.id, runner)

    jobs = query.order_by(Job.created_at.desc()).limit(limit).offset(offset).all()
    return [job.to_dict() for job in reversed(jobs)]


@app.delete("/sessions")
def delete_session(
    device_id: str,
    room_id: str,
    runner: str,
    thread_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> dict:
    ensure_room_owned(room_id, device_id, db)

    if thread_id:
        deleted = (
            db.query(DeviceSession)
            .filter_by(device_id=device_id, room_id=room_id, runner=runner, thread_id=thread_id)
            .delete()
        )
    else:
        if not settings.threads_compat_mode:
            raise HTTPException(status_code=400, detail="thread_id is required when THREADS_COMPAT_MODE=false")
        deleted = (
            db.query(DeviceSession)
            .filter_by(device_id=device_id, room_id=room_id, runner=runner)
            .delete()
        )

    db.commit()
    return {"status": "ok", "deleted": deleted}


@app.get("/unread_count")
def get_unread_count(
    device_id: str = Query(...),
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
) -> dict:
    """Get total unread thread count for a device."""
    count = db.query(Thread).join(Room).filter(
        Room.device_id == device_id,
        Thread.has_unread == True,  # noqa: E712
    ).count()
    return {"device_id": device_id, "unread_count": count}


@app.get("/health")
def health() -> dict:
    """Health check endpoint with certificate status."""
    result = {
        "status": "ok",
        "ssl_mode": _current_ssl_mode,
        "certificate_fallback_warning": is_certificate_fallback_warning(),
        "certificate_fingerprint": _current_cert_fingerprint,
    }
    if _pending_cert_restart:
        result["pending_restart"] = True
        result["pending_fingerprint"] = _pending_cert_fingerprint
    return result


# ========== Certificate Management APIs ==========

# Rate limiting state for certificate API
_cert_api_access_log: dict = {}  # IP -> list of timestamps
_cert_regenerate_last_time: dict = {}  # IP -> last regenerate timestamp


def _check_cert_rate_limit(request: Request, limit: int = 10, window: int = 60) -> None:
    """Check rate limit for certificate API (10 requests/minute/IP)."""
    from time import time
    client_ip = request.client.host if request.client else "unknown"
    now = time()

    if client_ip not in _cert_api_access_log:
        _cert_api_access_log[client_ip] = []

    # Clean old entries
    _cert_api_access_log[client_ip] = [
        t for t in _cert_api_access_log[client_ip] if now - t < window
    ]

    if len(_cert_api_access_log[client_ip]) >= limit:
        LOGGER.warning("[AUDIT] Rate limit exceeded for /server/certificate from %s", client_ip)
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again later.")

    _cert_api_access_log[client_ip].append(now)


def _check_regenerate_rate_limit(request: Request) -> None:
    """Check rate limit for certificate regeneration (1 request/hour/IP)."""
    from time import time
    client_ip = request.client.host if request.client else "unknown"
    now = time()

    if client_ip in _cert_regenerate_last_time:
        elapsed = now - _cert_regenerate_last_time[client_ip]
        if elapsed < 3600:  # 1 hour
            remaining = int(3600 - elapsed)
            LOGGER.warning(
                "[AUDIT] Regenerate rate limit for %s, %d seconds remaining",
                client_ip, remaining
            )
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded. Try again in {remaining} seconds."
            )


@app.get("/server/certificate")
def get_server_certificate(request: Request) -> dict:
    """Get server certificate information (no auth required for initial connection).

    Rate limited to 10 requests/minute/IP to prevent DoS.

    Note: Returns the certificate currently in use by TLS handshake, not the file on disk.
    After regeneration, this will still return the old certificate until server restart.
    """
    _check_cert_rate_limit(request)

    client_ip = request.client.host if request.client else "unknown"
    LOGGER.info("[AUDIT] Certificate info requested from %s", client_ip)

    # Return the certificate actually in use (loaded at startup), not the file on disk
    # This ensures consistency between API response and TLS handshake
    return {
        "fingerprint": _current_cert_fingerprint,
        "ssl_mode": _current_ssl_mode,
        "is_self_signed": _current_ssl_mode == "self_signed",
        "pending_restart": _pending_cert_restart,
        "pending_fingerprint": _pending_cert_fingerprint if _pending_cert_restart else None,
    }


@app.get("/server/qrcode")
def get_server_qrcode(
    request: Request,
    _: None = Depends(verify_api_key),
    format: str = Query("png", description="Output format: 'png' (base64) or 'json' (payload only)"),
) -> dict:
    """Get QR code for server configuration (requires API key).

    This endpoint generates a QR code containing server connection information
    that can be scanned by the iOS app for quick setup.

    Args:
        format: Output format - 'png' returns base64 PNG image, 'json' returns raw payload

    Returns:
        QR code data in requested format
    """
    client_ip = request.client.host if request.client else "unknown"
    LOGGER.info("[AUDIT] QR code requested from %s", client_ip)

    # Build server URL
    server_url = f"https://{settings.server_hostname}:{settings.server_port}"

    if format == "json":
        # Return just the payload data
        payload = generate_config_payload(
            server_url=server_url,
            api_key=settings.api_key,
            fingerprint=_current_cert_fingerprint,
            server_name=settings.bonjour_service_name,
        )
        return {
            "format": "json",
            "payload": payload,
        }
    else:
        # Return base64 PNG image
        qr_base64 = generate_qr_png_base64(
            server_url=server_url,
            api_key=settings.api_key,
            fingerprint=_current_cert_fingerprint,
            server_name=settings.bonjour_service_name,
        )
        return {
            "format": "png",
            "image": f"data:image/png;base64,{qr_base64}",
            "server_url": server_url,
            "fingerprint": _current_cert_fingerprint,
        }


class RegenerateCertificateRequest(BaseModel):
    reason: str = "scheduled_rotation"  # or "compromised"


@app.post("/server/certificate/regenerate")
async def regenerate_server_certificate(
    req: RegenerateCertificateRequest,
    request: Request,
    _: None = Depends(verify_api_key),
) -> dict:
    """Regenerate server certificate (admin only).

    Security constraints:
    - Requires API Key authentication
    - Rate limited to 1 request/hour/IP
    - Audit logged

    Note: The new certificate will only be used after server restart.
    Until then, /server/certificate and /health will show the old fingerprint
    but indicate pending_restart=True with the new fingerprint.
    """
    global _pending_cert_restart, _pending_cert_fingerprint

    from time import time
    from datetime import datetime, timezone

    client_ip = request.client.host if request.client else "unknown"

    # Rate limit check
    _check_regenerate_rate_limit(request)

    # Only allow for self-signed mode
    if _current_ssl_mode != "self_signed":
        raise HTTPException(
            status_code=400,
            detail="Certificate regeneration only available in self_signed mode"
        )

    # Audit log
    LOGGER.warning(
        "[AUDIT] Certificate regenerated: reason=%s, ip=%s, timestamp=%s",
        req.reason,
        client_ip,
        datetime.now(timezone.utc).isoformat(),
    )

    try:
        cert_path, key_path, old_fingerprint, new_fingerprint = regenerate_certificate(
            hostname=settings.server_hostname,
            san_ips=settings.get_san_ips_list(),
        )

        # Update rate limit timestamp
        _cert_regenerate_last_time[client_ip] = time()

        # Mark pending restart state (do NOT update _current_cert_fingerprint)
        # The current TLS context still uses the old certificate until restart
        _pending_cert_restart = True
        _pending_cert_fingerprint = new_fingerprint

        # Update Bonjour TXT record with new fingerprint
        # Note: This updates the advertised fingerprint immediately, but the actual
        # TLS certificate won't change until server restart
        if settings.bonjour_enabled:
            update_bonjour_fingerprint(new_fingerprint)
            LOGGER.info("Bonjour TXT fingerprint updated to new certificate")

        # Broadcast SSE notification with proper SSE format
        event_data = {
            "old_fingerprint": old_fingerprint,
            "new_fingerprint": new_fingerprint,
            "reason": req.reason,
            "effective_after_restart": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await sse_manager.broadcast_event("certificate_changed", event_data)

        return {
            "old_fingerprint": old_fingerprint,
            "new_fingerprint": new_fingerprint,
            "regenerated_at": datetime.now(timezone.utc).isoformat(),
            "restart_required": True,
            "current_in_use": old_fingerprint,
        }

    except Exception as e:
        LOGGER.error("Failed to regenerate certificate: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to regenerate certificate: {e}")


@app.get("/events", dependencies=[Depends(verify_api_key)])
async def global_events_stream(request: Request) -> StreamingResponse:
    """Global SSE endpoint for certificate and system events.

    Subscribes to global events like:
    - certificate_changed
    - certificate_revoked
    - certificate_mode_changed

    Requires API Key authentication.
    """
    async def event_generator():
        queue: asyncio.Queue = asyncio.Queue()
        sse_manager._global_subscribers.add(queue)
        LOGGER.info("[SSE-GLOBAL] New subscriber connected")

        try:
            while True:
                if await request.is_disconnected():
                    LOGGER.info("[SSE-GLOBAL] Client disconnected")
                    break

                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=30.0)
                    if payload is None:
                        break

                    # Send with proper SSE format including event name
                    event_name = payload.get("event", "message")
                    data = payload.get("data", payload)
                    yield f"event: {event_name}\ndata: {json.dumps(data)}\n\n"
                    LOGGER.debug("[SSE-GLOBAL] Sent event: %s", event_name)

                except asyncio.TimeoutError:
                    # Send heartbeat
                    yield ":ping\n\n"

        finally:
            sse_manager._global_subscribers.discard(queue)
            LOGGER.info("[SSE-GLOBAL] Subscriber disconnected")

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


if __name__ == "__main__":
    import uvicorn
    from config import settings
    
    cert_path, key_path, mode_used = get_ssl_paths()
    
    # 証明書ファイルが存在しない場合は作成
    if not Path(cert_path).exists() or not Path(key_path).exists():
        if mode_used == "self_signed" and settings.ssl_auto_generate:
            LOGGER.info("[SSL] Certificate files not found, generating...")
            cert_path, key_path, fingerprint = ensure_certificate_exists(
                hostname=settings.server_hostname,
                san_ips=settings.get_san_ips_list(),
            )
            LOGGER.info("[SSL] Certificate generated: %s", cert_path)
        else:
            LOGGER.error("[SSL] Certificate files not found: %s, %s", cert_path, key_path)
            raise FileNotFoundError(f"SSL certificate files not found: {cert_path}, {key_path}")
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=settings.server_port,
        ssl_keyfile=key_path,
        ssl_certfile=cert_path,
        log_level=settings.log_level.lower(),
    )
