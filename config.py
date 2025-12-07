"""Application configuration and logging helpers."""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import json
from typing import List, Literal, Optional, Tuple, Union

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    api_key: str = "dev-api-key"
    database_url: str = "sqlite:///./data/jobs.db"
    log_level: str = "INFO"
    allowed_origins: Union[str, List[str]] = "http://127.0.0.1:8443"  # 文字列またはリストとして定義
    threads_compat_mode: bool = True  # thread_id省略を許可する互換モード（Phase A/Bで使用）

    # APNs Push Notification Configuration
    apns_key_id: str = ""
    apns_team_id: str = ""
    apns_key_path: str = ""
    apns_bundle_id: str = ""
    apns_environment: str = "sandbox"

    # Remote Notification Server (VPS)
    notification_server_url: str = ""  # Optional: your notification relay server URL

    # SSL/TLS Certificate Configuration
    ssl_mode: Literal["commercial", "self_signed", "auto"] = "auto"
    ssl_auto_fallback_enabled: bool = False  # Require explicit opt-in for fallback
    ssl_cert_path: str = "./certs/self_signed/server.crt"
    ssl_key_path: str = "./certs/self_signed/server.key"
    ssl_auto_generate: bool = True
    server_hostname: str = "localhost"
    server_san_ips: str = "127.0.0.1"  # Comma-separated IPs for SAN
    server_port: int = 8443

    # Commercial certificate paths (Let's Encrypt)
    commercial_cert_path: str = "./certs/commercial/fullchain.pem"
    commercial_key_path: str = "./certs/commercial/privkey.pem"

    # Bonjour (mDNS/DNS-SD) Configuration
    bonjour_enabled: bool = True  # Enable Bonjour service discovery
    bonjour_service_name: str = "RemotePrompt Server"  # Service name shown to clients

    # Startup QR Code Display
    show_qr_on_startup: bool = False  # Show QR code in terminal on server startup

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_parse_none_str="",
        # 環境変数名のマッピング
        env_prefix="",
    )

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def normalize_allowed_origins(cls, value):
        # 空文字列やNoneの場合はデフォルト値を使用
        if value is None or value == "":
            return "http://127.0.0.1:8443"
        # 既にリストの場合はそのまま返す
        if isinstance(value, list):
            return value
        # 文字列の場合はそのまま返す（JSONパースは試みない）
        if isinstance(value, str):
            return value
        # その他の型の場合は文字列に変換
        return str(value)

    @model_validator(mode="after")
    def convert_allowed_origins_to_list(self):
        """allowed_originsをリストに変換する。"""
        # 文字列をリストに変換して保存
        if isinstance(self.allowed_origins, str):
            if not self.allowed_origins.strip():
                self.allowed_origins = ["http://127.0.0.1:8443"]
            else:
                self.allowed_origins = [
                    origin.strip() 
                    for origin in self.allowed_origins.split(",") 
                    if origin.strip()
                ]
        return self

    @field_validator("server_san_ips", mode="before")
    @classmethod
    def normalize_san_ips(cls, value):
        if isinstance(value, list):
            return ",".join(value)
        return value

    def get_san_ips_list(self) -> List[str]:
        """Get SAN IPs as a list."""
        return [ip.strip() for ip in self.server_san_ips.split(",") if ip.strip()]


settings = Settings()

# SSL certificate state tracking (set once at startup, never reset)
_certificate_fallback_warning: bool = False
_ssl_paths_initialized: bool = False
_cached_ssl_paths: Optional[Tuple[str, str, str]] = None


def get_ssl_paths() -> Tuple[str, str, str]:
    """Get SSL certificate paths based on configuration.

    Returns:
        Tuple of (cert_path, key_path, mode_used)

    Raises:
        RuntimeError: If commercial certificate not found and fallback disabled

    Note: The fallback warning state is set only on the first call and never reset.
    This ensures /health consistently reports the fallback status.
    """
    global _certificate_fallback_warning, _ssl_paths_initialized, _cached_ssl_paths

    # Return cached result if already initialized (prevents resetting fallback warning)
    if _ssl_paths_initialized and _cached_ssl_paths is not None:
        return _cached_ssl_paths

    mode = settings.ssl_mode.lower()
    logger = logging.getLogger(__name__)

    if mode == "commercial":
        logger.info("[SSL] Mode: commercial (forced)")
        _cached_ssl_paths = (settings.commercial_cert_path, settings.commercial_key_path, "commercial")
        _ssl_paths_initialized = True
        return _cached_ssl_paths

    if mode == "self_signed":
        logger.info("[SSL] Mode: self_signed (forced)")
        _cached_ssl_paths = (settings.ssl_cert_path, settings.ssl_key_path, "self_signed")
        _ssl_paths_initialized = True
        return _cached_ssl_paths

    # auto mode
    commercial_exists = Path(settings.commercial_cert_path).exists()

    if commercial_exists:
        logger.info("[SSL] Mode: auto -> using commercial certificate")
        _cached_ssl_paths = (settings.commercial_cert_path, settings.commercial_key_path, "commercial")
        _ssl_paths_initialized = True
        return _cached_ssl_paths

    # Commercial not found - check if fallback is enabled
    if not settings.ssl_auto_fallback_enabled:
        error_msg = (
            "Commercial certificate not found. "
            "Set SSL_AUTO_FALLBACK_ENABLED=true or SSL_MODE=self_signed "
            "to use self-signed certificate."
        )
        logger.error("[SSL] %s", error_msg)
        raise RuntimeError(error_msg)

    # Fallback to self-signed with warning
    logger.warning(
        "[SSL] SECURITY: Falling back to self-signed certificate. "
        "Existing clients may need to re-verify."
    )
    _certificate_fallback_warning = True
    _cached_ssl_paths = (settings.ssl_cert_path, settings.ssl_key_path, "self_signed")
    _ssl_paths_initialized = True
    return _cached_ssl_paths


def is_certificate_fallback_warning() -> bool:
    """Check if certificate fallback warning is active."""
    return _certificate_fallback_warning


def setup_logging() -> None:
    """Configure application-wide logging."""
    logger = logging.getLogger()
    if logger.handlers:
        return

    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    logger.setLevel(level)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # logsディレクトリが存在しない場合は作成
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    file_handler = RotatingFileHandler(
        "logs/server.log", maxBytes=10 * 1024 * 1024, backupCount=5
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)

    console = logging.StreamHandler()
    console.setFormatter(formatter)
    console.setLevel(level)

    logger.addHandler(file_handler)
    logger.addHandler(console)

    # Enable debug logging for aioapns and h2
    logging.getLogger("aioapns").setLevel(logging.DEBUG)
    logging.getLogger("h2").setLevel(logging.DEBUG)
