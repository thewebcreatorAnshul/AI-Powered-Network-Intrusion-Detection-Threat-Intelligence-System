"""Bounded capture staging with generated names and cleanup."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import UploadFile

from app.config import Settings, get_settings


class UploadTooLargeError(ValueError):
    error_code = "upload_too_large"


def ensure_upload_dir(settings: Settings | None = None) -> Path:
    settings = settings or get_settings()
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    return settings.upload_dir


def generated_storage_path(settings: Settings | None = None) -> Path:
    directory = ensure_upload_dir(settings)
    return directory / f"{uuid4().hex}.pcap"


def safe_original_filename(name: str | None) -> str:
    raw = (name or "capture").replace("\\", "/")
    base = Path(raw).name.strip() or "capture"
    return base[:255]


def save_upload_stream(upload: UploadFile, destination: Path, max_bytes: int) -> int:
    total = 0
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with destination.open("wb") as handle:
            while True:
                chunk = upload.file.read(65_536)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise UploadTooLargeError()
                handle.write(chunk)
    except Exception:
        delete_staged_file(destination)
        raise
    if total <= 0:
        delete_staged_file(destination)
    return total


def delete_staged_file(path: Path | None) -> None:
    if path is None:
        return
    try:
        path.unlink(missing_ok=True)
    except OSError:
        return


def cleanup_stale_uploads(settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    directory = settings.upload_dir
    if not directory.is_dir():
        return
    cutoff = datetime.now(timezone.utc) - timedelta(hours=settings.retention_hours)
    cutoff_ts = cutoff.timestamp()
    for item in directory.iterdir():
        if not item.is_file():
            continue
        try:
            if item.stat().st_mtime < cutoff_ts:
                item.unlink(missing_ok=True)
        except OSError:
            continue
