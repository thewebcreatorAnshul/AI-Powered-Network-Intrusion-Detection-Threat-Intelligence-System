"""Bounded, claim-scoped persistence for detailed analysis findings."""

from hashlib import sha256
import json
from datetime import timezone

from bson import BSON

from app.database import get_database, required_indexes_ready
from app.jobs import (
    JOB_COMPLETED,
    JOB_RUNNING,
    jobs_collection,
    job_claim_is_active,
    now_utc,
)

MAX_FINDING_DOCUMENT_BYTES = 8 * 1024 * 1024
FINDING_PAGE_DEFAULT = 50
FINDING_PAGE_MAX = 100
FINDING_EXPORT_BATCH_SIZE = 500
FINDING_WRITE_CHECKPOINT_SIZE = 100
FINDING_ORPHAN_CLEANUP_BATCH_SIZE = 200


class StaleAnalysisClaimError(RuntimeError):
    """Raised when findings are submitted by a claim without a live lease."""


def _utc_aware(value):
    """Normalize PyMongo's default naive UTC BSON datetimes for comparison."""
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def analysis_findings_collection():
    return get_database()["analysis_findings"]


def ensure_analysis_result_indexes() -> None:
    analysis_findings_collection().create_index(
        [("job_id", 1), ("claim_token", 1), ("finding_index", 1)],
        unique=True,
        name="uniq_job_claim_finding_index",
    )


def _finding_hash(finding: dict) -> str:
    encoded = json.dumps(finding, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(encoded.encode("utf-8")).hexdigest()


def persist_analysis_findings(job_id, claim_token: str, findings: list[dict]) -> int:
    """Upsert one bounded finding per document, scoped to this job claim.

    Results from a claim become visible only when the fenced job completion
    stores the same completed_claim_token. Partial or stale attempt records
    therefore remain invisible. Ownership is rechecked at bounded checkpoints;
    standalone MongoDB cannot atomically fence writes across the jobs and
    findings collections, so a lease-loss race can still leave invisible rows
    for the bounded orphan sweeper to remove.
    """
    if not required_indexes_ready():
        raise RuntimeError("Required database indexes are not ready for analysis result persistence.")
    collection = analysis_findings_collection()
    timestamp = now_utc()
    for index, finding in enumerate(findings):
        if index % FINDING_WRITE_CHECKPOINT_SIZE == 0 and not job_claim_is_active(job_id, claim_token):
            raise StaleAnalysisClaimError("The analysis job claim is no longer active.")
        document = {
            "job_id": job_id,
            "claim_token": claim_token,
            "finding_index": index,
            "finding_key": _finding_hash(finding),
            "finding": finding,
            "created_at": timestamp,
        }
        if len(BSON.encode(document)) > MAX_FINDING_DOCUMENT_BYTES:
            raise ValueError("An analysis finding exceeds the per-document storage limit.")
        collection.update_one(
            {
                "job_id": job_id,
                "claim_token": claim_token,
                "finding_index": index,
            },
            {"$setOnInsert": document},
            upsert=True,
        )
    return len(findings)


def cleanup_orphaned_analysis_findings(
    *, after_id=None, batch_size: int = FINDING_ORPHAN_CLEANUP_BATCH_SIZE,
) -> tuple[int, int, object | None]:
    """Delete one bounded page of findings whose job/claim is no longer valid.

    The returned cursor is the last scanned finding id, allowing callers to
    sweep large collections over multiple worker iterations without loading
    the full collection. Completed claims are always retained.
    """
    if not required_indexes_ready():
        return 0, 0, after_id
    if batch_size < 1:
        raise ValueError("batch_size must be positive")
    query = {} if after_id is None else {"_id": {"$gt": after_id}}
    rows = list(
        analysis_findings_collection().find(query).sort("_id", 1).limit(batch_size)
    )
    if not rows:
        return 0, 0, None

    timestamp = now_utc()
    deleted = 0
    findings = analysis_findings_collection()
    for row in rows:
        job = jobs_collection().find_one({"_id": row["job_id"]})
        token = row.get("claim_token")
        valid_completed_claim = (
            job is not None
            and job.get("status") == JOB_COMPLETED
            and job.get("completed_claim_token") == token
        )
        lease_expires_at = _utc_aware(job.get("lease_expires_at")) if job else None
        valid_running_claim = (
            job is not None
            and job.get("status") == JOB_RUNNING
            and job.get("claim_token") == token
            and lease_expires_at is not None
            and lease_expires_at > timestamp
        )
        if valid_completed_claim or valid_running_claim:
            continue
        result = findings.delete_one({
            "_id": row["_id"],
            "job_id": row["job_id"],
            "claim_token": token,
        })
        deleted += result.deleted_count
    return len(rows), deleted, rows[-1]["_id"]


def cleanup_other_analysis_attempts(job_id, keep_claim_token: str) -> int:
    """Remove abandoned rows from older claims for this analysis."""
    if not required_indexes_ready():
        return 0
    result = analysis_findings_collection().delete_many(
        {"job_id": job_id, "claim_token": {"$ne": keep_claim_token}}
    )
    return result.deleted_count


def delete_analysis_findings_for_attempt(job_id, claim_token: str) -> int:
    if not required_indexes_ready():
        return 0
    result = analysis_findings_collection().delete_many(
        {"job_id": job_id, "claim_token": claim_token}
    )
    return result.deleted_count


def _legacy_findings(job: dict) -> list[dict] | None:
    findings = (job.get("summary") or {}).get("findings")
    return findings if isinstance(findings, list) else None


def get_analysis_findings_page(job: dict, *, skip: int = 0, limit: int = FINDING_PAGE_DEFAULT) -> tuple[list[dict], int]:
    """Read a bounded page for the job's successfully completed claim."""
    summary = job.get("summary") or {}
    claim_token = job.get("completed_claim_token")
    if claim_token:
        collection = analysis_findings_collection()
        query = {"job_id": job["_id"], "claim_token": claim_token}
        total = collection.count_documents(query)
        if total:
            rows = list(
                collection.find({**query, "finding_index": {"$gte": skip}})
                .sort("finding_index", 1)
                .limit(limit)
            )
            return [row["finding"] for row in rows], total
    legacy = _legacy_findings(job)
    if legacy is not None:
        return legacy[skip : skip + limit], len(legacy)
    return [], int(summary.get("finding_count", 0))


def iter_analysis_findings(job: dict):
    """Yield stored findings in bounded indexed batches for exports."""
    claim_token = job.get("completed_claim_token")
    if claim_token:
        collection = analysis_findings_collection()
        query = {"job_id": job["_id"], "claim_token": claim_token}
        if collection.count_documents(query):
            last_index = -1
            while True:
                batch = list(
                    collection.find({**query, "finding_index": {"$gt": last_index}})
                    .sort("finding_index", 1)
                    .limit(FINDING_EXPORT_BATCH_SIZE)
                )
                if not batch:
                    return
                for row in batch:
                    last_index = row["finding_index"]
                    yield row["finding"]
                if len(batch) < FINDING_EXPORT_BATCH_SIZE:
                    return
    legacy = _legacy_findings(job) or []
    yield from legacy
