"""Ownership-scoped dashboard summaries."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, status

from app.alerts import alerts_collection
from app.deps import get_current_user
from app.errors import raise_api_error
from app.jobs import jobs_collection
from app.roles import ADMINISTRATOR

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("")
def dashboard_summary(
    current_user: dict = Depends(get_current_user),
    since: datetime | None = None,
    until: datetime | None = None,
    severity: str | None = Query(default=None, pattern="^(critical|high|medium|low)$"),
    method: str | None = Query(default=None, pattern="^(signature|model)$"),
) -> dict:
    if (since and since.tzinfo is None) or (until and until.tzinfo is None) or (since and until and since > until):
        raise_api_error(status.HTTP_422_UNPROCESSABLE_CONTENT, "validation_error", "The start time must be before the end time.")
    is_admin = current_user.get("role") == ADMINISTRATOR
    job_query = {} if is_admin else {"submitted_by": str(current_user["_id"])}
    alert_query = {} if is_admin else {"submitted_by": str(current_user["_id"])}
    if since or until:
        time_filter = {}
        if since:
            time_filter["$gte"] = since
        if until:
            time_filter["$lte"] = until
        job_query["created_at"] = time_filter
        alert_query["occurred_at"] = time_filter
    if severity:
        alert_query["severity"] = severity.lower()
    if method:
        alert_query["method"] = method.lower()
    jobs = list(jobs_collection().find(job_query))
    alerts = list(alerts_collection().find(alert_query))
    severities: dict[str, int] = {}
    methods: dict[str, int] = {}
    statuses: dict[str, int] = {}
    for alert in alerts:
        severities[alert["severity"]] = severities.get(alert["severity"], 0) + 1
        methods[alert["method"]] = methods.get(alert["method"], 0) + 1
        statuses[alert["status"]] = statuses.get(alert["status"], 0) + 1
    return {
        "analysis_count": len(jobs),
        "jobs_by_status": {state: sum(1 for job in jobs if job.get("status") == state) for state in ("queued", "running", "completed", "failed")},
        "alert_count": len(alerts),
        "alerts_by_severity": severities,
        "alerts_by_method": methods,
        "alerts_by_status": statuses,
        "generated_at": datetime.now(timezone.utc),
    }
