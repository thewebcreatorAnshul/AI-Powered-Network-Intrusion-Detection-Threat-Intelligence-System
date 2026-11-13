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
    job_facets = list(jobs_collection().aggregate([
        {"$match": job_query},
        {"$facet": {
            "total": [{"$count": "count"}],
            "by_status": [{"$group": {"_id": "$status", "count": {"$sum": 1}}}],
        }},
    ]))
    job_summary = job_facets[0] if job_facets else {}
    job_count_rows = job_summary.get("total", [])
    job_counts = {
        row["_id"]: row["count"]
        for row in job_summary.get("by_status", [])
        if row.get("_id") is not None
    }
    alert_facets = list(alerts_collection().aggregate([
        {"$match": alert_query},
        {"$facet": {
            "total": [{"$count": "count"}],
            "by_severity": [{"$group": {"_id": "$severity", "count": {"$sum": 1}}}],
            "by_method": [{"$group": {"_id": "$method", "count": {"$sum": 1}}}],
            "by_status": [{"$group": {"_id": "$status", "count": {"$sum": 1}}}],
        }},
    ]))
    facets = alert_facets[0] if alert_facets else {}
    alert_count_rows = facets.get("total", [])
    severities = {
        row["_id"]: row["count"]
        for row in facets.get("by_severity", [])
        if row.get("_id") is not None
    }
    methods = {
        row["_id"]: row["count"]
        for row in facets.get("by_method", [])
        if row.get("_id") is not None
    }
    statuses = {
        row["_id"]: row["count"]
        for row in facets.get("by_status", [])
        if row.get("_id") is not None
    }
    return {
        "analysis_count": job_count_rows[0]["count"] if job_count_rows else 0,
        "jobs_by_status": {state: job_counts.get(state, 0) for state in ("queued", "running", "completed", "failed")},
        "alert_count": alert_count_rows[0]["count"] if alert_count_rows else 0,
        "alerts_by_severity": severities,
        "alerts_by_method": methods,
        "alerts_by_status": statuses,
        "generated_at": datetime.now(timezone.utc),
    }
