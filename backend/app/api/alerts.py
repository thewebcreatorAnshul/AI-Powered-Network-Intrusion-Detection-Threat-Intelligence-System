"""Role-scoped alert review and export endpoints."""

import csv
import io
import json
import re
from datetime import datetime

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import StreamingResponse

from app.alerts import alerts_collection, get_alert_by_id, serialize_alert, update_alert_status
from app.audit import record_audit_event
from app.deps import get_current_admin, get_current_user
from app.csv_utils import spreadsheet_safe
from app.errors import raise_api_error
from app.roles import ADMINISTRATOR
from app.schemas import AlertStatusUpdate

router = APIRouter(prefix="/alerts", tags=["alerts"])


def _owned_alert(alert: dict, user: dict) -> bool:
    return user.get("role") == ADMINISTRATOR or alert.get("submitted_by") == str(user["_id"])


def _alert_query(user: dict, severity, method, alert_status, since, until, q) -> dict:
    if (since and since.tzinfo is None) or (until and until.tzinfo is None) or (since and until and since > until):
        raise_api_error(status.HTTP_422_UNPROCESSABLE_CONTENT, "validation_error", "The start time must be before the end time.")
    query = {} if user.get("role") == ADMINISTRATOR else {"submitted_by": str(user["_id"])}
    if severity:
        query["severity"] = severity.lower()
    if method:
        query["method"] = method.lower()
    if alert_status:
        query["status"] = alert_status.lower()
    if since or until:
        query["occurred_at"] = {}
        if since:
            query["occurred_at"]["$gte"] = since
        if until:
            query["occurred_at"]["$lte"] = until
    if q:
        escaped = re.escape(q)
        query["$or"] = [
            {"title": {"$regex": escaped, "$options": "i"}},
            {"category": {"$regex": escaped, "$options": "i"}},
        ]
    return query


def _csv_alerts(query: dict):
    columns = (
        "id", "job_id", "occurred_at", "severity", "category", "method",
        "detection_type", "rule_id", "rule_version", "title", "description",
        "status", "evidence",
    )
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(columns)
    yield output.getvalue()
    for document in alerts_collection().find(query).sort([("occurred_at", -1), ("_id", -1)]):
        output.seek(0)
        output.truncate(0)
        alert = serialize_alert(document)
        row = [alert.get(column, "") for column in columns]
        row[2] = row[2].isoformat() if row[2] else ""
        row[-1] = json.dumps(row[-1] or {}, ensure_ascii=True, separators=(",", ":"))
        writer.writerow([spreadsheet_safe(value) for value in row])
        yield output.getvalue()


@router.get("")
def list_alerts(
    current_user: dict = Depends(get_current_user),
    severity: str | None = Query(default=None, pattern="^(critical|high|medium|low)$"),
    method: str | None = Query(default=None, pattern="^(signature|model)$"),
    alert_status: str | None = Query(default=None, alias="status", pattern="^(open|acknowledged|resolved)$"),
    since: datetime | None = None,
    until: datetime | None = None,
    q: str | None = Query(default=None, max_length=120),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
) -> list[dict]:
    query = _alert_query(current_user, severity, method, alert_status, since, until, q)
    documents = (
        alerts_collection()
        .find(query)
        .sort([("occurred_at", -1), ("_id", -1)])
        .skip(skip)
        .limit(limit)
    )
    return [serialize_alert(alert) for alert in documents]


@router.get("/export")
def export_alerts(
    current_user: dict = Depends(get_current_user),
    severity: str | None = Query(default=None, pattern="^(critical|high|medium|low)$"),
    method: str | None = Query(default=None, pattern="^(signature|model)$"),
    alert_status: str | None = Query(default=None, alias="status", pattern="^(open|acknowledged|resolved)$"),
    since: datetime | None = None,
    until: datetime | None = None,
    q: str | None = Query(default=None, max_length=120),
) -> StreamingResponse:
    query = _alert_query(current_user, severity, method, alert_status, since, until, q)
    return StreamingResponse(
        _csv_alerts(query),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="alerts.csv"'},
    )


@router.get("/{alert_id}")
def read_alert(alert_id: str, current_user: dict = Depends(get_current_user)) -> dict:
    alert = get_alert_by_id(alert_id)
    if alert is None:
        raise_api_error(status.HTTP_404_NOT_FOUND, "not_found", "Alert not found.")
    if not _owned_alert(alert, current_user):
        record_audit_event(str(current_user["_id"]), "forbidden_access", "alert", alert_id, "failure")
        raise_api_error(status.HTTP_403_FORBIDDEN, "forbidden", "You do not have permission to access this resource.")
    return serialize_alert(alert)


@router.patch("/{alert_id}")
def change_alert_status(
    alert_id: str,
    payload: AlertStatusUpdate,
    admin: dict = Depends(get_current_admin),
) -> dict:
    alert = update_alert_status(alert_id, payload.status)
    if alert is None:
        raise_api_error(status.HTTP_404_NOT_FOUND, "not_found", "Alert not found.")
    record_audit_event(str(admin["_id"]), "update_alert_status", "alert", alert_id, "success", {"status": payload.status})
    return serialize_alert(alert)
