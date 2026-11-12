"""In-process analysis-job processor for this milestone.

Limitation: there is no separate worker or message queue. After a capture is
validated and a job is persisted as queued, this processor runs in the API
process, transitions the job to running, then to completed or failed. HTTP
clients receive the post-ingestion state; a completed job means parse/ingest
finished, not signature or ML detection.
"""

from pathlib import Path
from threading import Condition, Event, Thread
import logging
import time

from pymongo.errors import PyMongoError

from app.config import get_settings
from app.database import required_indexes_ready
from app.alerts import (
    build_alert_intent,
    enqueue_alert_intent,
    relay_pending_alert_intents_for_job,
)
from app.detection.engine import analyze_records
from app.intelligence import enrich_findings
from app.ingestion.base import CaptureError, InvalidCaptureError
from app.ingestion.pcap import get_source_adapter
from app.ingestion.storage import delete_staged_file
from app.jobs import (
    JOB_LEASE_SECONDS,
    claim_job,
    get_job_by_id,
    mark_job_completed,
    mark_job_failed,
    renew_job_lease,
)

logger = logging.getLogger(__name__)
LEASE_HEARTBEAT_INTERVAL_SECONDS = 60
HEARTBEAT_STOP_POLL_SECONDS = 0.1
HEARTBEAT_JOIN_TIMEOUT_SECONDS = 10
_heartbeat_condition = Condition()
_active_heartbeat_threads: set[Thread] = set()


class MissingStagedCaptureError(CaptureError):
    error_code = "missing_capture"
    message = "The staged capture file is missing."


def wait_for_active_heartbeats(timeout: float | None = None) -> bool:
    """Wait until all lease heartbeats have stopped, bounded when requested."""
    deadline = None if timeout is None else time.monotonic() + timeout
    with _heartbeat_condition:
        while _active_heartbeat_threads:
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                return False
            _heartbeat_condition.wait(remaining)
    return True


class LeaseHeartbeat:
    def __init__(self, job_id, claim_token: str, cancel_event: Event | None = None) -> None:
        self.job_id = job_id
        self.claim_token = claim_token
        self.cancel_event = cancel_event
        self.interval = min(LEASE_HEARTBEAT_INTERVAL_SECONDS, JOB_LEASE_SECONDS / 3)
        self._stop = Event()
        self.lost = Event()
        self._thread = Thread(target=self._run, name="analysis-lease-heartbeat", daemon=True)

    def start(self) -> None:
        with _heartbeat_condition:
            _active_heartbeat_threads.add(self._thread)
        try:
            self._thread.start()
        except Exception:
            with _heartbeat_condition:
                _active_heartbeat_threads.discard(self._thread)
                _heartbeat_condition.notify_all()
            raise

    def _run(self) -> None:
        try:
            next_renewal = time.monotonic() + self.interval
            while not self._stop.is_set():
                if self.cancel_event is not None and self.cancel_event.is_set():
                    return
                remaining = next_renewal - time.monotonic()
                if remaining > 0:
                    if self._stop.wait(min(remaining, HEARTBEAT_STOP_POLL_SECONDS)):
                        return
                    continue
                if not self.renew():
                    return
                next_renewal = time.monotonic() + self.interval
        finally:
            with _heartbeat_condition:
                _active_heartbeat_threads.discard(self._thread)
                _heartbeat_condition.notify_all()

    def renew(self) -> bool:
        if self.lost.is_set() or (self.cancel_event is not None and self.cancel_event.is_set()):
            return False
        try:
            if renew_job_lease(self.job_id, self.claim_token):
                return True
        except Exception:
            logger.warning("Analysis job lease renewal failed; worker is relinquishing the job.")
        self.lost.set()
        return False

    def stop_and_wait(self, timeout: float = HEARTBEAT_JOIN_TIMEOUT_SECONDS) -> bool:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=timeout)
        stopped = not self._thread.is_alive()
        if not stopped:
            logger.warning(
                "Lease heartbeat for analysis job %s has not exited yet; database cleanup will wait.",
                self.job_id,
            )
        return stopped


def staged_path_for_job(job: dict) -> Path:
    upload_dir = get_settings().upload_dir.resolve()
    storage_name = job.get("storage_name")
    if not isinstance(storage_name, str) or not storage_name:
        raise MissingStagedCaptureError()
    path = (upload_dir / storage_name).resolve()
    if path.parent != upload_dir:
        raise InvalidCaptureError()
    if not path.is_file():
        raise MissingStagedCaptureError()
    return path


def process_analysis_job(job: dict, cancel_event: Event | None = None) -> dict:
    if not required_indexes_ready():
        return get_job_by_id(str(job["_id"])) or job
    if cancel_event is not None and cancel_event.is_set():
        return job
    updated = claim_job(job["_id"])
    if updated is None:
        return get_job_by_id(str(job["_id"])) or job
    return process_claimed_analysis_job(updated, cancel_event=cancel_event)


def process_claimed_analysis_job(updated: dict, cancel_event: Event | None = None) -> dict:
    if not required_indexes_ready():
        return get_job_by_id(str(updated["_id"])) or updated
    if cancel_event is not None and cancel_event.is_set():
        return updated
    claim_token = updated["claim_token"]
    heartbeat = LeaseHeartbeat(updated["_id"], claim_token, cancel_event)
    terminal_update_succeeded = False
    completed_job = None
    try:
        heartbeat.start()
        if heartbeat.lost.is_set() or (cancel_event is not None and cancel_event.is_set()):
            return get_job_by_id(str(updated["_id"])) or updated
        storage_path = staged_path_for_job(updated)
        adapter = get_source_adapter(updated.get("source_type", "pcap"))
        adapter.validate(storage_path)
        records = []
        for record in adapter.iter_records(storage_path):
            if heartbeat.lost.is_set() or (cancel_event is not None and cancel_event.is_set()):
                return get_job_by_id(str(updated["_id"])) or updated
            records.append(record)
        if cancel_event is not None and cancel_event.is_set():
            return updated
        metadata = adapter.metadata(storage_path)
        features, findings = analyze_records(records)
        if heartbeat.lost.is_set() or (cancel_event is not None and cancel_event.is_set()):
            return get_job_by_id(str(updated["_id"])) or updated
        settings = get_settings()
        findings, enrichment = enrich_findings(findings, settings.threat_intel_mode, settings.threat_intel_file)
        alert_keys = set()
        for finding in findings:
            if cancel_event is not None and cancel_event.is_set():
                return updated
            if not heartbeat.renew():
                return get_job_by_id(str(updated["_id"])) or updated
            intent = build_alert_intent(updated, finding)
            if not enqueue_alert_intent(updated["_id"], claim_token, intent):
                return get_job_by_id(str(updated["_id"])) or updated
            alert_keys.add(intent["dedupe_key"])
        if cancel_event is not None and cancel_event.is_set():
            return updated
        if heartbeat.lost.is_set():
            return get_job_by_id(str(updated["_id"])) or updated
        summary = {
            "stage": "analysis",
            "detection": "signature_rules",
            "source_format": metadata.get("source_format"),
            "packet_count": features["packet_count"],
            "flow_count": features["flow_count"],
            "protocol_counts": features["protocol_counts"],
            "alert_count": len(alert_keys),
            "findings": findings,
            "enrichment": enrichment,
            "ml_scoring": {"status": "skipped", "reason": "no approved model artifact is configured"},
        }
        if cancel_event is not None and cancel_event.is_set():
            return updated
        completed = mark_job_completed(updated["_id"], claim_token, summary)
        terminal_update_succeeded = completed is not None
        if completed is None:
            return updated
        completed_job = completed
        if cancel_event is None or not cancel_event.is_set():
            relay_pending_alert_intents_for_job(updated["_id"])
        return completed
    except FileNotFoundError:
        if cancel_event is not None and cancel_event.is_set():
            return updated
        failed = mark_job_failed(
            updated["_id"],
            claim_token,
            "missing_capture",
            MissingStagedCaptureError.message,
        )
        terminal_update_succeeded = failed is not None
        return failed or updated
    except CaptureError as exc:
        if cancel_event is not None and cancel_event.is_set():
            return updated
        failed = mark_job_failed(updated["_id"], claim_token, exc.error_code, exc.message)
        terminal_update_succeeded = failed is not None
        return failed or updated
    except PyMongoError as exc:
        # Do not write a terminal state while the database outcome is uncertain.
        if completed_job is None:
            logger.warning(
                "Analysis job %s hit a transient database error (%s); leaving it recoverable.",
                updated["_id"],
                type(exc).__name__,
            )
        else:
            logger.warning(
                "Analysis job %s completed but alert relay hit a transient database error (%s); relay will retry.",
                updated["_id"],
                type(exc).__name__,
            )
        return completed_job or updated
    except Exception:
        if cancel_event is not None and cancel_event.is_set():
            return updated
        failed = mark_job_failed(
            updated["_id"],
            claim_token,
            "processing_failed",
            "Analysis could not be completed.",
        )
        terminal_update_succeeded = failed is not None
        return failed or updated
    finally:
        heartbeat.stop_and_wait()
        if terminal_update_succeeded:
            delete_staged_file(locals().get("storage_path"))
