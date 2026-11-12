"""Application configuration loaded from environment variables."""

from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
import os

BACKEND_DIR = Path(__file__).resolve().parents[1]
DEFAULT_CORS_ORIGINS = (
    "http://localhost:5173",
    "http://127.0.0.1:5173",
)


def _load_environment() -> None:
    env_path = BACKEND_DIR / ".env"
    if env_path.is_file():
        load_dotenv(env_path, override=False)


def _positive_int(raw: str | None, default: int) -> int:
    try:
        value = int((raw or "").strip())
        return value if value > 0 else default
    except ValueError:
        return default


def _split_origins(raw: str | None) -> list[str]:
    if not raw or not raw.strip():
        return list(DEFAULT_CORS_ORIGINS)
    origins = [item.strip() for item in raw.split(",") if item.strip()]
    return origins or list(DEFAULT_CORS_ORIGINS)


def _flag(raw: str | None) -> bool:
    return (raw or "").strip().lower() in {"1", "true", "yes", "on"}


class Settings:
    def __init__(self) -> None:
        _load_environment()
        self.mongodb_uri = os.getenv("MONGODB_URI", "").strip()
        self.mongodb_database = os.getenv("MONGODB_DATABASE", "").strip()
        self.threat_intel_mode = os.getenv("THREAT_INTEL_MODE", "offline").strip()
        if self.threat_intel_mode not in {"offline", "local"}:
            raise RuntimeError("THREAT_INTEL_MODE must be 'offline' or 'local'.")
        self.allowed_origins = _split_origins(os.getenv("ALLOWED_ORIGINS"))
        self.api_prefix = "/api/v1"
        self.jwt_secret = os.getenv("JWT_SECRET", "").strip()
        self.jwt_expire_minutes = _positive_int(os.getenv("JWT_EXPIRE_MINUTES"), 60)
        self.admin_username = os.getenv("ADMIN_USERNAME", "").strip().lower()
        self.admin_password = os.getenv("ADMIN_PASSWORD", "").strip()
        self.admin_password_reset = _flag(os.getenv("ADMIN_PASSWORD_RESET"))
        self.threat_intel_file = os.getenv("THREAT_INTEL_FILE", "").strip()
        if self.threat_intel_file:
            intelligence_path = Path(self.threat_intel_file)
            if not intelligence_path.is_absolute():
                intelligence_path = BACKEND_DIR / intelligence_path
            self.threat_intel_file = str(intelligence_path)
        upload_dir = os.getenv("UPLOAD_DIR", "uploads").strip() or "uploads"
        upload_path = Path(upload_dir)
        self.upload_dir = upload_path if upload_path.is_absolute() else BACKEND_DIR / upload_path
        self.max_upload_mb = _positive_int(os.getenv("MAX_UPLOAD_MB"), 25)
        self.max_upload_bytes = self.max_upload_mb * 1024 * 1024
        self.retention_hours = _positive_int(os.getenv("RETENTION_HOURS"), 24)
        self.shutdown_grace_seconds = _positive_int(os.getenv("SHUTDOWN_GRACE_SECONDS"), 15)
        self.mongodb_socket_timeout_ms = _positive_int(os.getenv("MONGODB_SOCKET_TIMEOUT_MS"), 5000)
        if len(self.jwt_secret) < 32:
            raise RuntimeError("JWT_SECRET must contain at least 32 characters.")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
