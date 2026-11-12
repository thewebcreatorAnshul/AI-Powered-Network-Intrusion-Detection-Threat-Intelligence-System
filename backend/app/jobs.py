"""Analysis job persistence and serialization."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from bson import ObjectId
from bson.errors import InvalidId
from pymongo import ReturnDocument
from pymongo.collection import Collection

from app.database import get_database

JOB_QUEUED = "queued"
JOB_RUNNING = "running"
JOB_COMPLETED = "completed"
JOB_FAILED = "failed"
JOB_STATUSES = (JOB_QUEUED, JOB_RUNNING, JOB_COMPLETED, JOB_FAILED)
SOURCE_PCAP = "pcap"
JOB_LEASE_SECONDS = 300


def jobs_collection() -> Collection:
    return get_database()["analysis_jobs"]


def ensure_job_indexes() -> None:
    collection = jobs_collection()
    collection.create_index("status")
    collection.create_index("created_at")
    collection.create_index("submitted_by")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def serialize_job(document: dict) -> dict:
    return {
        "id": str(document["_id"]),
        "submitted_by": document["submitted_by"],
        "source_type": document["source_type"],
        "filename": document["filename"],
        "file_size": document["file_size"],
        "status": document["status"],
        "created_at": document["created_at"],
        "started_at": document.get("started_at"),
        "finished_at": document.get("finished_at"),
        "summary": document.get("summary"),
        "error_code": document.get("error_code"),
        "error_message": document.get("error_message"),
    }


def create_analysis_job(
    submitted_by: str,
    filename: str,
    file_size: int,
    storage_path: Path,
    source_type: str = SOURCE_PCAP,
) -> dict:
    timestamp = now_utc()
    document = {
        "submitted_by": submitted_by,
        "source_type": source_type,
        "filename": filename,
        "file_size": file_size,
        "storage_name": storage_path.name,
        "status": JOB_QUEUED,
        "created_at": timestamp,
        "started_at": None,
        "finished_at": None,
        "summary": None,
        "error_code": None,
        "error_message": None,
        "schema_version": 1,
        "claim_token": None,
        "lease_expires_at": None,
        "completed_claim_token": None,
        "outbox_write_validated_at": None,
    }
    result = jobs_collection().insert_one(document)
    document["_id"] = result.inserted_id
    return document


def get_job_by_id(job_id: str) -> dict | None:
    try:
        object_id = ObjectId(job_id)
    except (InvalidId, TypeError):
        return None
    return jobs_collection().find_one({"_id": object_id})


def list_jobs_for_user(user_id: str | None) -> list[dict]:
    query = {} if user_id is None else {"submitted_by": user_id}
    return list(jobs_collection().find(query).sort("created_at", -1))


def list_jobs_page(
    user_id: str | None, *, skip: int, limit: int, status: str | None = None,
    q: str | None = None, since=None, until=None,
) -> list[dict]:
    query = {} if user_id is None else {"submitted_by": user_id}
    if status:
        query["status"] = status
    if since or until:
        query["created_at"] = {}
        if since:
            query["created_at"]["$gte"] = since
        if until:
            query["created_at"]["$lte"] = until
    documents = list(jobs_collection().find(query).sort("created_at", -1))
    if q:
        needle = q.casefold()
        documents = [job for job in documents if needle in job.get("filename", "").casefold()]
    return documents[skip : skip + limit]


def list_recoverable_jobs() -> list[dict]:
    """Return queued jobs and running jobs whose worker lease expired."""
    timestamp = now_utc()
    return list(jobs_collection().find({"$or": [
        {"status": JOB_QUEUED},
        {"status": JOB_RUNNING, "$or": [
            {"lease_expires_at": {"$lte": timestamp}},
            {"lease_expires_at": None},
        ]},
    ]}))


def claim_job(job_id) -> dict | None:
    """Atomically claim a queued job or reclaim one with an expired lease."""
    timestamp = now_utc()
    return _claim_one(_claim_query(timestamp, job_id), timestamp)


def claim_next_recoverable_job() -> dict | None:
    """Atomically claim one recoverable job for a bounded startup worker."""
    timestamp = now_utc()
    return _claim_one(_claim_query(timestamp), timestamp)


def _claim_query(timestamp: datetime, job_id=None) -> dict:
    query = {"$or": [
        {"status": JOB_QUEUED},
        {"status": JOB_RUNNING, "$or": [
            {"lease_expires_at": {"$lte": timestamp}},
            {"lease_expires_at": None},
        ]},
    ]}
    if job_id is not None:
        query["_id"] = job_id
    return query


def _claim_one(query: dict, timestamp: datetime) -> dict | None:
    token = uuid4().hex
    return jobs_collection().find_one_and_update(
        query,
        {"$set": {
            "status": JOB_RUNNING,
            "claim_token": token,
            "lease_expires_at": timestamp + timedelta(seconds=JOB_LEASE_SECONDS),
            "lease_renewed_at": timestamp,
            "started_at": timestamp,
            "finished_at": None,
            "error_code": None,
            "error_message": None,
            "completed_claim_token": None,
        }},
        return_document=ReturnDocument.AFTER,
    )


def renew_job_lease(job_id, claim_token: str) -> bool:
    """Extend only a still-live lease owned by the supplied claim token."""
    timestamp = now_utc()
    result = jobs_collection().update_one(
        {
            "_id": job_id,
            "status": JOB_RUNNING,
            "claim_token": claim_token,
            "lease_expires_at": {"$gt": timestamp},
        },
        {"$set": {
            "lease_expires_at": timestamp + timedelta(seconds=JOB_LEASE_SECONDS),
            "lease_renewed_at": timestamp,
        }},
    )
    return result.matched_count == 1


def enqueue_alert_intent(job_id, claim_token: str, intent: dict) -> bool:
    """Compatibility wrapper for the separate, lease-fenced outbox store."""
    from app.alerts import enqueue_alert_intent as enqueue_to_outbox

    return enqueue_to_outbox(job_id, claim_token, intent)


def get_next_pending_alert_intent() -> tuple[dict, dict] | None:
    job = jobs_collection().find_one({
        "alert_outbox": {"$elemMatch": {"delivered": {"$ne": True}}},
    })
    if job is None:
        return None
    for intent in job.get("alert_outbox", []):
        if not intent.get("delivered", False):
            return job, intent
    return None


def mark_alert_intent_delivered(job_id, dedupe_key: str, alert_id: str) -> bool:
    result = jobs_collection().update_one(
        {"_id": job_id, "alert_outbox.dedupe_key": dedupe_key},
        {"$set": {
            "alert_outbox.$.delivered": True,
            "alert_outbox.$.delivered_at": now_utc(),
            "alert_outbox.$.alert_id": alert_id,
            "alert_outbox.$.payload": None,
        }},
    )
    return result.matched_count == 1


def mark_job_completed(job_id, claim_token: str, summary: dict) -> dict | None:
    timestamp = now_utc()
    result = jobs_collection().update_one(
        {
            "_id": job_id,
            "status": JOB_RUNNING,
            "claim_token": claim_token,
            "lease_expires_at": {"$gt": timestamp},
        },
        {
            "$set": {
                "status": JOB_COMPLETED,
                "finished_at": timestamp,
                "summary": summary,
                "error_code": None,
                "error_message": None,
                "completed_claim_token": claim_token,
                "claim_token": None,
                "lease_expires_at": None,
                "lease_renewed_at": None,
            }
        },
    )
    return jobs_collection().find_one({"_id": job_id}) if result.matched_count else None


def mark_job_failed(job_id, claim_token: str, error_code: str, error_message: str) -> dict | None:
    timestamp = now_utc()
    result = jobs_collection().update_one(
        {
            "_id": job_id,
            "status": JOB_RUNNING,
            "claim_token": claim_token,
            "lease_expires_at": {"$gt": timestamp},
        },
        {
            "$set": {
                "status": JOB_FAILED,
                "finished_at": timestamp,
                "error_code": error_code,
                "error_message": error_message,
                "completed_claim_token": None,
                "claim_token": None,
                "lease_expires_at": None,
                "lease_renewed_at": None,
            }
        },
    )
    return jobs_collection().find_one({"_id": job_id}) if result.matched_count else None
