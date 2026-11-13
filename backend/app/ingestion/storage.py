"""Bounded capture staging with generated names and cleanup."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4
import os
import logging

from fastapi import UploadFile

from app.config import Settings, get_settings

logger = logging.getLogger(__name__)


class UploadTooLargeError(ValueError):
    error_code = "upload_too_large"


def ensure_upload_dir(settings: Settings | None = None) -> Path:
    settings = settings or get_settings()
    directory = settings.upload_dir
    if os.name != "nt" and directory.is_symlink():
        raise ValueError("UPLOAD_DIR must not be a symbolic link.")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        if directory.is_symlink():
            raise ValueError("UPLOAD_DIR must not be a symbolic link.")
        directory.chmod(0o700)
    return directory


def generated_storage_path(settings: Settings | None = None) -> Path:
    directory = ensure_upload_dir(settings)
    return directory / f"{uuid4().hex}.pcap"


def safe_original_filename(name: str | None) -> str:
    raw = (name or "capture").replace("\\", "/")
    base = Path(raw).name.strip() or "capture"
    return base[:255]


def save_upload_stream(upload: UploadFile, destination: Path, max_bytes: int) -> int:
    total = 0
    descriptor = None
    created = False
    try:
        if os.name != "nt" and destination.parent.is_symlink():
            raise ValueError("Staged-file directory must not be a symbolic link.")
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt" and destination.parent.is_symlink():
            raise ValueError("Staged-file directory must not be a symbolic link.")
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        created = True
        handle = os.fdopen(descriptor, "wb")
        descriptor = None
        with handle:
            while True:
                chunk = upload.file.read(65_536)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise UploadTooLargeError()
                handle.write(chunk)
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        if created:
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
    from pymongo.errors import PyMongoError

    from app.database import get_database

    jobs = get_database()["analysis_jobs"]
    cutoff = datetime.now(timezone.utc) - timedelta(hours=settings.retention_hours)
    cutoff_ts = cutoff.timestamp()
    for item in directory.iterdir():
        if not item.is_file():
            continue
        try:
            if item.stat().st_mtime < cutoff_ts:
                referenced = jobs.find_one({
                    "storage_name": item.name,
                    "$or": [{"status": "queued"}, {"status": "running"}],
                })
                if referenced is not None:
                    continue
                item.unlink(missing_ok=True)
        except PyMongoError:
            logger.warning("Skipping remaining stale upload cleanup because job references are unavailable.")
            return
        except OSError:
            continue
