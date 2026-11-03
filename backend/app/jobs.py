"""Analysis job persistence and serialization."""

from datetime import datetime, timezone
from pathlib import Path

from bson import ObjectId
from bson.errors import InvalidId
from pymongo.collection import Collection

from app.database import get_database

JOB_QUEUED = "queued"
JOB_RUNNING = "running"
JOB_COMPLETED = "completed"
JOB_FAILED = "failed"
JOB_STATUSES = (JOB_QUEUED, JOB_RUNNING, JOB_COMPLETED, JOB_FAILED)
SOURCE_PCAP = "pcap"


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


def mark_job_running(job_id) -> dict | None:
    jobs_collection().update_one(
        {"_id": job_id, "status": JOB_QUEUED},
        {"$set": {"status": JOB_RUNNING, "started_at": now_utc()}},
    )
    return jobs_collection().find_one({"_id": job_id})


def mark_job_completed(job_id, summary: dict) -> dict | None:
    jobs_collection().update_one(
        {"_id": job_id},
        {
            "$set": {
                "status": JOB_COMPLETED,
                "finished_at": now_utc(),
                "summary": summary,
                "error_code": None,
                "error_message": None,
            }
        },
    )
    return jobs_collection().find_one({"_id": job_id})


def mark_job_failed(job_id, error_code: str, error_message: str) -> dict | None:
    jobs_collection().update_one(
        {"_id": job_id},
        {
            "$set": {
                "status": JOB_FAILED,
                "finished_at": now_utc(),
                "error_code": error_code,
                "error_message": error_message,
            }
        },
    )
    return jobs_collection().find_one({"_id": job_id})
