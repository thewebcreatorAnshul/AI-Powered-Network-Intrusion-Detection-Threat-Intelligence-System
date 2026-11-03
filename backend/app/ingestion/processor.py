"""In-process analysis-job processor for this milestone.

Limitation: there is no separate worker or message queue. After a capture is
validated and a job is persisted as queued, this processor runs in the API
process, transitions the job to running, then to completed or failed. HTTP
clients receive the post-ingestion state; a completed job means parse/ingest
finished, not signature or ML detection.
"""

from pathlib import Path

from app.config import get_settings
from app.alerts import create_alert
from app.detection.engine import analyze_records
from app.intelligence import enrich_findings
from app.ingestion.base import CaptureError
from app.ingestion.pcap import get_source_adapter
from app.ingestion.storage import delete_staged_file
from app.jobs import mark_job_completed, mark_job_failed, mark_job_running


def staged_path_for_job(job: dict) -> Path:
    return get_settings().upload_dir / job["storage_name"]


def process_analysis_job(job: dict) -> dict:
    updated = mark_job_running(job["_id"]) or job
    storage_path = staged_path_for_job(updated)
    try:
        adapter = get_source_adapter(updated.get("source_type", "pcap"))
        records = list(adapter.iter_records(storage_path))
        metadata = adapter.metadata(storage_path)
        features, findings = analyze_records(records)
        settings = get_settings()
        findings, enrichment = enrich_findings(findings, settings.threat_intel_mode, settings.threat_intel_file)
        alerts = [create_alert(updated, finding) for finding in findings]
        summary = {
            "stage": "analysis",
            "detection": "signature_rules",
            "source_format": metadata.get("source_format"),
            "packet_count": features["packet_count"],
            "flow_count": features["flow_count"],
            "protocol_counts": features["protocol_counts"],
            "alert_count": len(alerts),
            "findings": findings,
            "enrichment": enrichment,
            "ml_scoring": {"status": "skipped", "reason": "no approved model artifact is configured"},
        }
        completed = mark_job_completed(updated["_id"], summary)
        return completed or updated
    except CaptureError as exc:
        failed = mark_job_failed(updated["_id"], exc.error_code, exc.message)
        return failed or updated
    except Exception:
        failed = mark_job_failed(
            updated["_id"],
            "processing_failed",
            "Analysis could not be completed.",
        )
        return failed or updated
    finally:
        delete_staged_file(storage_path)
