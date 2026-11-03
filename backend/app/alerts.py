"""Alert persistence and serialization."""

from datetime import datetime, timezone

from bson import ObjectId
from bson.errors import InvalidId

from app.database import get_database


def alerts_collection():
    return get_database()["alerts"]


def ensure_alert_indexes() -> None:
    collection = alerts_collection()
    collection.create_index("job_id")
    collection.create_index("severity")
    collection.create_index("occurred_at")
    collection.create_index("status")


def create_alert(job: dict, finding: dict) -> dict:
    document = {
        "job_id": str(job["_id"]),
        "submitted_by": job["submitted_by"],
        "occurred_at": datetime.now(timezone.utc),
        "severity": finding["severity"],
        "category": finding["category"],
        "method": finding["method"],
        "detection_type": finding["detection_type"],
        "rule_id": finding.get("rule_id"),
        "rule_version": finding.get("rule_version"),
        "title": finding["title"],
        "description": finding["description"],
        "evidence": finding.get("evidence", {}),
        "indicator_context": finding.get("indicator_context", []),
        "status": "open",
        "schema_version": 1,
    }
    result = alerts_collection().insert_one(document)
    document["_id"] = result.inserted_id
    return document


def get_alert_by_id(alert_id: str) -> dict | None:
    try:
        return alerts_collection().find_one({"_id": ObjectId(alert_id)})
    except (InvalidId, TypeError):
        return None


def serialize_alert(document: dict) -> dict:
    fields = (
        "job_id", "submitted_by", "occurred_at", "severity", "category", "method",
        "detection_type", "rule_id", "rule_version", "title", "description", "evidence", "indicator_context", "status",
    )
    return {"id": str(document["_id"]), **{key: document.get(key) for key in fields}}


def update_alert_status(alert_id: str, status: str) -> dict | None:
    alert = get_alert_by_id(alert_id)
    if alert is None:
        return None
    alerts_collection().update_one(
        {"_id": alert["_id"]},
        {"$set": {"status": status, "updated_at": datetime.now(timezone.utc)}},
    )
    return get_alert_by_id(alert_id)
