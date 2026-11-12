"""Alert persistence and serialization."""

from datetime import datetime, timezone
import hashlib
import json
from threading import BoundedSemaphore

from bson import ObjectId
from bson.errors import InvalidId
from pymongo.errors import DuplicateKeyError

from app.database import get_database, required_indexes_ready
from app.jobs import jobs_collection, mark_alert_intent_delivered, now_utc

OUTBOX_RELAY_CONCURRENCY = 2
OUTBOX_RELAY_BATCH_SIZE = 100
OUTBOX_SCAN_BATCH_SIZE = 500
_outbox_relay_slots = BoundedSemaphore(OUTBOX_RELAY_CONCURRENCY)


def alerts_collection():
    return get_database()["alerts"]


def alert_outbox_collection():
    return get_database()["alert_outbox"]


def ensure_alert_indexes() -> None:
    collection = alerts_collection()
    collection.create_index("job_id")
    collection.create_index("severity")
    collection.create_index("occurred_at")
    collection.create_index("status")
    collection.create_index("dedupe_key", unique=True, sparse=True)
    outbox = alert_outbox_collection()
    outbox.create_index(
        [("job_id", 1), ("claim_token", 1), ("dedupe_key", 1)],
        unique=True,
        name="uniq_job_claim_alert_intent",
    )
    outbox.create_index([("status", 1), ("created_at", 1)], name="pending_alert_outbox")
    outbox.create_index([("job_id", 1), ("status", 1), ("claim_token", 1)])


def _alert_dedupe_key(job: dict, finding: dict) -> str:
    identity = {
        "job_id": str(job["_id"]),
        "rule_id": finding.get("rule_id"),
        "rule_version": finding.get("rule_version"),
        "category": finding.get("category"),
        "detection_type": finding.get("detection_type"),
        "title": finding.get("title"),
        "evidence": finding.get("evidence", {}),
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_alert_intent(job: dict, finding: dict) -> dict:
    dedupe_key = _alert_dedupe_key(job, finding)
    payload = {
        "submitted_by": job["submitted_by"],
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
        "schema_version": 1,
    }
    return {
        "dedupe_key": dedupe_key,
        "occurred_at": datetime.now(timezone.utc),
        "payload": payload,
        "delivered": False,
    }


def _intent_id(job_id, claim_token: str, dedupe_key: str) -> str:
    raw = f"{job_id}:{claim_token}:{dedupe_key}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def enqueue_alert_intent(job_id, claim_token: str, intent: dict) -> bool:
    """Stage an intent, then validate ownership atomically on the job document.

    Staged rows are not relayable. The job's fenced completion transition is
    the durable authorization point for every pending row from that claim.
    """
    if not required_indexes_ready():
        return False
    timestamp = now_utc()
    owner_query = {
        "_id": job_id,
        "status": "running",
        "claim_token": claim_token,
        "lease_expires_at": {"$gt": timestamp},
    }
    if jobs_collection().find_one(owner_query) is None:
        return False
    intent_id = _intent_id(job_id, claim_token, intent["dedupe_key"])
    document = {
        "_id": intent_id,
        "job_id": job_id,
        "claim_token": claim_token,
        "dedupe_key": intent["dedupe_key"],
        "occurred_at": intent["occurred_at"],
        "payload": intent["payload"],
        "status": "staged",
        "created_at": timestamp,
    }
    try:
        alert_outbox_collection().update_one(
            {
                "job_id": job_id,
                "claim_token": claim_token,
                "dedupe_key": intent["dedupe_key"],
            },
            {"$setOnInsert": document},
            upsert=True,
        )
    except DuplicateKeyError:
        # Another retry for this claim inserted the deterministic intent first.
        pass

    validated_at = now_utc()
    ownership = jobs_collection().update_one(
        {**owner_query, "lease_expires_at": {"$gt": validated_at}},
        {"$set": {"outbox_write_validated_at": validated_at}},
    )
    if ownership.matched_count != 1:
        return False

    alert_outbox_collection().update_one(
        {"_id": intent_id, "status": "staged"},
        {"$set": {"status": "pending", "validated_at": validated_at}},
    )
    stored = alert_outbox_collection().find_one({"_id": intent_id})
    return stored is not None and stored.get("status") == "pending"


def materialize_alert_intent(job_id, intent: dict) -> dict:
    """Idempotently create the alert represented by a durable job outbox item."""
    if not required_indexes_ready():
        raise RuntimeError("Required database indexes are not ready for alert persistence.")
    document = {
        "job_id": str(job_id),
        **intent["payload"],
        "occurred_at": intent["occurred_at"],
        "status": "open",
        "dedupe_key": intent["dedupe_key"],
    }
    try:
        alerts_collection().update_one(
            {"dedupe_key": intent["dedupe_key"]},
            {"$setOnInsert": document},
            upsert=True,
        )
    except DuplicateKeyError:
        # A concurrent retry may win the unique-index upsert race.
        pass
    alert = alerts_collection().find_one({"dedupe_key": intent["dedupe_key"]})
    if alert is None:
        raise RuntimeError("Alert upsert completed without a retrievable alert.")
    return alert


def _job_authorizes_intent(job: dict | None, intent: dict) -> bool:
    return bool(
        job
        and job.get("status") == "completed"
        and job.get("completed_claim_token") == intent.get("claim_token")
    )


def _discard_if_stale(intent: dict, job: dict | None) -> bool:
    """Delete rows that can no longer be authorized by a fenced completion."""
    if job is None:
        alert_outbox_collection().delete_one({"_id": intent["_id"], "status": intent.get("status")})
        return True
    if job.get("status") == "running" and job.get("claim_token") == intent.get("claim_token"):
        lease = job.get("lease_expires_at")
        if lease is not None and lease > now_utc():
            return False
    if _job_authorizes_intent(job, intent):
        return False
    alert_outbox_collection().delete_one({"_id": intent["_id"], "status": intent.get("status")})
    return True


def _pending_authorized_intent(job_id=None) -> tuple[dict, dict, bool] | None:
    query = {"status": "pending"}
    if job_id is not None:
        query["job_id"] = job_id
    candidates = list(
        alert_outbox_collection().find(query).sort("created_at", 1)
    )[:OUTBOX_SCAN_BATCH_SIZE]
    for intent in candidates:
        job = jobs_collection().find_one({"_id": intent["job_id"]})
        if _job_authorizes_intent(job, intent):
            return job, intent, False
        _discard_if_stale(intent, job)

    # Remove provisional rows left by a crash before the owner check/promotion.
    staged_query = {"status": "staged"}
    if job_id is not None:
        staged_query["job_id"] = job_id
    staged = list(alert_outbox_collection().find(staged_query).sort("created_at", 1))[:OUTBOX_SCAN_BATCH_SIZE]
    for intent in staged:
        job = jobs_collection().find_one({"_id": intent["job_id"]})
        lease = job.get("lease_expires_at") if job else None
        if not (
            job
            and job.get("status") == "running"
            and job.get("claim_token") == intent.get("claim_token")
            and lease is not None
            and lease > now_utc()
        ):
            alert_outbox_collection().delete_one({"_id": intent["_id"], "status": "staged"})

    # Drain intents created by the previous embedded-outbox implementation.
    legacy_query = {
        "alert_outbox": {"$elemMatch": {"delivered": {"$ne": True}}},
    }
    if job_id is not None:
        legacy_query["_id"] = job_id
    for job in list(jobs_collection().find(legacy_query).sort("created_at", 1))[:OUTBOX_SCAN_BATCH_SIZE]:
        legacy = next(
            (item for item in job.get("alert_outbox", []) if not item.get("delivered", False)),
            None,
        )
        if legacy is not None:
            return job, legacy, True
    return None


def _relay_intent(job: dict, intent: dict, *, legacy: bool) -> None:
    alert = materialize_alert_intent(job["_id"], intent)
    if legacy:
        mark_alert_intent_delivered(job["_id"], intent["dedupe_key"], str(alert["_id"]))
    else:
        alert_outbox_collection().delete_one({"_id": intent["_id"], "status": "pending"})


def relay_pending_alert_intents_for_job(job_id) -> int:
    """Relay a job's authorized alert intents with bounded active concurrency."""
    if not required_indexes_ready():
        return 0
    with _outbox_relay_slots:
        delivered = 0
        while delivered < OUTBOX_RELAY_BATCH_SIZE:
            pending = _pending_authorized_intent(job_id)
            if pending is None:
                break
            job, intent, legacy = pending
            _relay_intent(job, intent, legacy=legacy)
            delivered += 1
        return delivered


def relay_next_pending_alert_intent() -> bool:
    if not required_indexes_ready():
        return False
    pending = _pending_authorized_intent()
    if pending is None:
        return False
    with _outbox_relay_slots:
        job, intent, legacy = pending
        _relay_intent(job, intent, legacy=legacy)
    return True


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
