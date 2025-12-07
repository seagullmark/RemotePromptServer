"""Database configuration for the Remote Job Server."""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text

from config import settings
from db import Base

DATABASE_URL = settings.database_url


engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)

# v4.1: SQLite FOREIGN KEY制約を有効化（デフォルトOFFのため）
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_conn, connection_record):
    """Enable FOREIGN KEY constraints for SQLite connections."""
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


@contextmanager
def session_scope() -> Generator:
    """Provide a transactional scope for DB operations."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    """Create database tables based on model metadata."""
    # Import inside function to ensure models register with the Base metadata.
    from models import Device, DeviceSession, Job, Room, Thread  # pylint: disable=import-outside-toplevel

    # SQLiteデータベースファイルのディレクトリが存在しない場合は作成
    if DATABASE_URL.startswith("sqlite:///"):
        db_path = DATABASE_URL.replace("sqlite:///", "")
        # 相対パスの場合
        if db_path.startswith("./"):
            db_path = db_path[2:]
        db_file = Path(db_path)
        db_dir = db_file.parent
        if db_dir != Path(".") and not db_dir.exists():
            db_dir.mkdir(parents=True, exist_ok=True)

    Base.metadata.create_all(bind=engine)
    _ensure_room_settings_column()
    _ensure_thread_columns()


def _ensure_room_settings_column() -> None:
    """SQLite用: roomsテーブルにsettings列が無ければ追加する。

    Alembicを使わない簡易マイグレーション。既存環境の互換性を保つため、
    起動時にのみ実行する。
    """

    with engine.begin() as conn:
        result = conn.execute(text("PRAGMA table_info(rooms)"))
        columns = [row[1] for row in result.fetchall()]
        if "settings" not in columns:
            conn.execute(text("ALTER TABLE rooms ADD COLUMN settings TEXT"))
        if "sort_order" not in columns:
            conn.execute(text("ALTER TABLE rooms ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0"))


def _ensure_thread_columns() -> None:
    """Add thread_id support to jobs and device_sessions if missing.

    - jobs: add nullable thread_id column and index (if not exists).
    - device_sessions: rebuild table to include thread_id and update unique index
      to (device_id, room_id, runner, thread_id).
    """

    with engine.begin() as conn:
        # jobs.thread_id
        jobs_cols = [row[1] for row in conn.execute(text("PRAGMA table_info(jobs)"))]
        if "thread_id" not in jobs_cols:
            conn.execute(text("ALTER TABLE jobs ADD COLUMN thread_id TEXT"))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS idx_jobs_room_thread ON jobs (room_id, thread_id)"
            ))

        # device_sessions.thread_id + unique index rebuild if absent
        ds_cols = [row[1] for row in conn.execute(text("PRAGMA table_info(device_sessions)"))]
        if "thread_id" not in ds_cols:
            conn.executescript(
                """
                PRAGMA foreign_keys=off;
                CREATE TABLE device_sessions_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    room_id TEXT NOT NULL,
                    runner TEXT NOT NULL,
                    thread_id TEXT,
                    session_id TEXT NOT NULL,
                    created_at DATETIME NOT NULL,
                    updated_at DATETIME NOT NULL,
                    UNIQUE(device_id, room_id, runner, thread_id)
                );
                INSERT INTO device_sessions_new (
                    id, device_id, room_id, runner, thread_id, session_id, created_at, updated_at
                )
                SELECT id, device_id, room_id, runner, NULL, session_id, created_at, updated_at
                FROM device_sessions;
                DROP TABLE device_sessions;
                ALTER TABLE device_sessions_new RENAME TO device_sessions;
                CREATE INDEX IF NOT EXISTS idx_device_room_runner_thread
                    ON device_sessions (device_id, room_id, runner, thread_id);
                PRAGMA foreign_keys=on;
                """
            )
