"""Documented source-adapter interface for authorized capture inputs."""

from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path


class CaptureError(ValueError):
    """Safe, client-facing capture validation or parse failure."""

    error_code = "invalid_capture"
    message = "The capture could not be parsed."


class EmptyCaptureError(CaptureError):
    error_code = "empty_capture"
    message = "The capture is empty."


class UnsupportedCaptureError(CaptureError):
    error_code = "unsupported_capture"
    message = "The capture format is not supported. Upload a PCAP or PCAPNG file."


class CaptureProcessingLimitError(CaptureError):
    error_code = "capture_processing_limit"
    message = "The capture exceeds the configured analysis processing limits."


class InvalidCaptureError(CaptureError):
    error_code = "invalid_capture"
    message = "The capture could not be parsed."


class SourceAdapter(ABC):
    """Boundary for ingesting authorized traffic sources.

    Implementations must validate input, yield normalized records without packet
    payloads, and describe source metadata. Live network capture is out of scope.
    """

    source_type: str

    @abstractmethod
    def validate(self, path: Path) -> None:
        """Reject empty, unsupported, or unparseable captures before a job is queued."""

    @abstractmethod
    def iter_records(self, path: Path) -> Iterator[dict]:
        """Yield normalized packet or flow records without payloads."""

    @abstractmethod
    def metadata(self, path: Path) -> dict:
        """Return safe source metadata such as format and declared limits."""
