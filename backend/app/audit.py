"""Security-relevant audit events without secrets or payloads."""

from datetime import datetime, timezone

from app.database import get_database


def record_audit_event(
    actor_id: str | None,
    action: str,
    target_type: str,
    target_id: str | None,
    outcome: str,
    safe_metadata: dict | None = None,
) -> None:
    get_database()["audit_events"].insert_one(
        {
            "actor_id": actor_id,
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
            "occurred_at": datetime.now(timezone.utc),
            "outcome": outcome,
            "safe_metadata": safe_metadata or {},
        }
    )
