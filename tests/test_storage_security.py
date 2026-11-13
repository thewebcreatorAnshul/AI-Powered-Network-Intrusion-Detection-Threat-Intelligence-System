from io import BytesIO
import os
from types import SimpleNamespace

import pytest
from starlette.datastructures import UploadFile

from app.ingestion.storage import ensure_upload_dir, generated_storage_path, save_upload_stream


def test_staged_directory_and_capture_file_are_private_on_posix(tmp_path):
    settings = SimpleNamespace(upload_dir=tmp_path / "staged")
    destination = generated_storage_path(settings)
    upload = UploadFile(filename="sample.pcap", file=BytesIO(b"capture bytes"))

    assert save_upload_stream(upload, destination, max_bytes=100) == len(b"capture bytes")
    assert destination.read_bytes() == b"capture bytes"
    if os.name != "nt":
        assert destination.parent.stat().st_mode & 0o777 == 0o700
        assert destination.stat().st_mode & 0o777 == 0o600


def test_staged_file_collision_does_not_overwrite_existing_capture(tmp_path):
    destination = tmp_path / "uploads" / "collision.pcap"
    destination.parent.mkdir()
    destination.write_bytes(b"existing capture")
    upload = UploadFile(filename="new.pcap", file=BytesIO(b"replacement"))

    with pytest.raises(FileExistsError):
        save_upload_stream(upload, destination, max_bytes=100)

    assert destination.read_bytes() == b"existing capture"


def test_oversized_stream_is_removed_after_private_creation(tmp_path):
    destination = tmp_path / "uploads" / "oversized.pcap"
    upload = UploadFile(filename="large.pcap", file=BytesIO(b"too large"))

    from app.ingestion.storage import UploadTooLargeError

    with pytest.raises(UploadTooLargeError):
        save_upload_stream(upload, destination, max_bytes=3)

    assert not destination.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX symbolic-link permissions and semantics")
def test_configured_upload_directory_symlink_is_rejected(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    upload_dir = tmp_path / "uploads-link"
    upload_dir.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="UPLOAD_DIR"):
        ensure_upload_dir(SimpleNamespace(upload_dir=upload_dir))

    assert list(outside.iterdir()) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX symbolic-link permissions and semantics")
def test_staged_file_parent_symlink_is_rejected(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    staged_parent = tmp_path / "staged-link"
    staged_parent.symlink_to(outside, target_is_directory=True)
    destination = staged_parent / "capture.pcap"
    upload = UploadFile(filename="capture.pcap", file=BytesIO(b"capture"))

    with pytest.raises(ValueError, match="Staged-file directory"):
        save_upload_stream(upload, destination, max_bytes=100)

    assert list(outside.iterdir()) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX symbolic-link permissions and semantics")
def test_upload_via_symlink_cannot_overwrite_file_outside_upload_directory(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    protected_file = outside / "capture.pcap"
    protected_file.write_bytes(b"original bytes")
    staged_parent = tmp_path / "staged-link"
    staged_parent.symlink_to(outside, target_is_directory=True)
    upload = UploadFile(filename="capture.pcap", file=BytesIO(b"replacement bytes"))

    with pytest.raises(ValueError, match="Staged-file directory"):
        save_upload_stream(upload, staged_parent / protected_file.name, max_bytes=100)

    assert protected_file.read_bytes() == b"original bytes"
    assert list(outside.iterdir()) == [protected_file]
