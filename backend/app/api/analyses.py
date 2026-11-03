"""Authenticated PCAP upload and analysis-job endpoints."""

from pathlib import Path
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, File, Query, UploadFile, status
from fastapi.responses import Response

from app.audit import record_audit_event
from app.config import get_settings
from app.deps import get_current_user, require_self_or_admin
from app.errors import raise_api_error
from app.ingestion.base import CaptureError
from app.ingestion.pcap import PcapSourceAdapter
from app.ingestion.processor import process_analysis_job
from app.ingestion.storage import (
    UploadTooLargeError,
    delete_staged_file,
    generated_storage_path,
    save_upload_stream,
    safe_original_filename,
)
from app.jobs import (
    create_analysis_job,
    get_job_by_id,
    list_jobs_page,
    serialize_job,
)
from app.roles import ADMINISTRATOR
from app.schemas import AnalysisJobResponse

router = APIRouter(prefix="/analyses", tags=["analyses"])


def _raise_capture_error(exc: CaptureError) -> None:
    raise_api_error(status.HTTP_400_BAD_REQUEST, exc.error_code, exc.message)


@router.post("", response_model=AnalysisJobResponse, status_code=status.HTTP_202_ACCEPTED)
def submit_pcap_analysis(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user),
) -> dict:
    settings = get_settings()
    original_name = safe_original_filename(file.filename)
    if Path(original_name).suffix.lower() not in {".pcap", ".pcapng"}:
        raise_api_error(status.HTTP_400_BAD_REQUEST, "unsupported_capture", "Upload a PCAP or PCAPNG file.")
    destination = generated_storage_path(settings)
    try:
        file_size = save_upload_stream(file, destination, settings.max_upload_bytes)
    except UploadTooLargeError:
        record_audit_event(
            str(current_user["_id"]),
            "upload",
            "analysis_job",
            None,
            "failure",
            {"error_code": "upload_too_large", "filename": original_name},
        )
        raise_api_error(
            status.HTTP_413_CONTENT_TOO_LARGE,
            "upload_too_large",
            f"Upload exceeds the maximum allowed size of {settings.max_upload_mb} MB.",
        )
    if file_size <= 0:
        record_audit_event(
            str(current_user["_id"]),
            "upload",
            "analysis_job",
            None,
            "failure",
            {"error_code": "empty_capture", "filename": original_name},
        )
        raise_api_error(status.HTTP_400_BAD_REQUEST, "empty_capture", "The capture is empty.")

    adapter = PcapSourceAdapter()
    try:
        adapter.validate(destination)
    except CaptureError as exc:
        delete_staged_file(destination)
        record_audit_event(
            str(current_user["_id"]),
            "upload",
            "analysis_job",
            None,
            "failure",
            {"error_code": exc.error_code, "filename": original_name},
        )
        _raise_capture_error(exc)

    job = create_analysis_job(
        submitted_by=str(current_user["_id"]),
        filename=original_name,
        file_size=file_size,
        storage_path=destination,
    )
    record_audit_event(
        str(current_user["_id"]),
        "upload",
        "analysis_job",
        str(job["_id"]),
        "success",
        {"filename": original_name, "file_size": file_size},
    )
    background_tasks.add_task(process_analysis_job, job)
    record_audit_event(
        str(current_user["_id"]),
        "analysis_launch",
        "analysis_job",
        str(job["_id"]),
        "queued",
        {"status": job.get("status")},
    )
    return serialize_job(job)


@router.get("", response_model=list[AnalysisJobResponse])
def list_analysis_jobs(
    current_user: dict = Depends(get_current_user),
    status_filter: str | None = Query(default=None, alias="status", pattern="^(queued|running|completed|failed)$"),
    q: str | None = Query(default=None, max_length=120),
    since: datetime | None = None,
    until: datetime | None = None,
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
) -> list[dict]:
    if (since and since.tzinfo is None) or (until and until.tzinfo is None) or (since and until and since > until):
        raise_api_error(status.HTTP_422_UNPROCESSABLE_CONTENT, "validation_error", "The start time must be before the end time.")
    owner_id = None if current_user.get("role") == ADMINISTRATOR else str(current_user["_id"])
    return [serialize_job(job) for job in list_jobs_page(owner_id, skip=skip, limit=limit, status=status_filter, q=q, since=since, until=until)]


@router.get("/{job_id}", response_model=AnalysisJobResponse)
def get_analysis_job(job_id: str, current_user: dict = Depends(get_current_user)) -> dict:
    job = get_job_by_id(job_id)
    if job is None:
        raise_api_error(status.HTTP_404_NOT_FOUND, "not_found", "Analysis job not found.")
    require_self_or_admin(current_user, job["submitted_by"])
    return serialize_job(job)


@router.get("/{job_id}/export")
def export_analysis_summary(job_id: str, current_user: dict = Depends(get_current_user)) -> Response:
    import csv
    import io

    job = get_job_by_id(job_id)
    if job is None:
        raise_api_error(status.HTTP_404_NOT_FOUND, "not_found", "Analysis job not found.")
    require_self_or_admin(current_user, job["submitted_by"])
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["analysis_id", "filename", "status", "created_at", "packet_count", "flow_count", "alert_count", "findings"])
    summary = job.get("summary") or {}
    writer.writerow([
        str(job["_id"]), job.get("filename", ""), job.get("status", ""),
        job.get("created_at", "").isoformat() if job.get("created_at") else "",
        summary.get("packet_count", 0), summary.get("flow_count", 0), summary.get("alert_count", 0),
        "; ".join(f"{f.get('rule_id')}: {f.get('title')}" for f in summary.get("findings", [])),
    ])
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="analysis-{job_id}.csv"'},
    )
