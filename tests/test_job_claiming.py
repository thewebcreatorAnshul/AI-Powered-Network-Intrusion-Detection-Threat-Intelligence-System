from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest

from app.database import get_database
from app.jobs import (
    claim_job,
    create_analysis_job,
    list_recoverable_jobs,
    mark_job_completed,
    mark_job_failed,
    now_utc,
    renew_job_lease,
)
import app.database as database_module
from tests.fake_mongo import Client as FakeMongoClient


@pytest.fixture
def job_store(monkeypatch):
    """Provide isolated Mongo semantics without starting the HTTP app lifespan."""
    monkeypatch.setattr(database_module, "_client", FakeMongoClient())
    yield
    database_module.close_client()


def make_job(tmp_path):
    return create_analysis_job("user-1", "capture.pcap", 100, tmp_path / "staged.pcap")


def test_queued_job_claim_succeeds_and_sets_lease(job_store, tmp_path):
    job = make_job(tmp_path)
    claimed = claim_job(job["_id"])
    assert claimed["status"] == "running"
    assert claimed["claim_token"]
    assert claimed["lease_expires_at"] > claimed["started_at"]
    assert claim_job(job["_id"]) is None


def test_active_lease_prevents_reclaim_and_expired_lease_allows_it(job_store, tmp_path):
    job = claim_job(make_job(tmp_path)["_id"])
    assert claim_job(job["_id"]) is None

    get_database()["analysis_jobs"].update_one(
        {"_id": job["_id"]},
        {"$set": {"lease_expires_at": now_utc() - timedelta(seconds=1)}},
    )
    reclaimed = claim_job(job["_id"])
    assert reclaimed["claim_token"] != job["claim_token"]
    assert reclaimed["status"] == "running"


def test_recovery_query_includes_queued_and_expired_but_not_active_jobs(job_store, tmp_path):
    queued = make_job(tmp_path)
    active = claim_job(make_job(tmp_path)["_id"])
    expired = claim_job(make_job(tmp_path)["_id"])
    get_database()["analysis_jobs"].update_one(
        {"_id": expired["_id"]},
        {"$set": {"lease_expires_at": now_utc() - timedelta(seconds=1)}},
    )

    recoverable_ids = {job["_id"] for job in list_recoverable_jobs()}
    assert queued["_id"] in recoverable_ids
    assert expired["_id"] in recoverable_ids
    assert active["_id"] not in recoverable_ids


def test_only_one_simultaneous_claim_succeeds(job_store, tmp_path):
    job = make_job(tmp_path)
    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(pool.map(lambda _index: claim_job(job["_id"]), range(2)))
    successful = [claim for claim in claims if claim is not None]
    assert len(successful) == 1


def test_old_claim_token_cannot_complete_or_fail_reclaimed_job(job_store, tmp_path):
    job = claim_job(make_job(tmp_path)["_id"])
    get_database()["analysis_jobs"].update_one(
        {"_id": job["_id"]},
        {"$set": {"lease_expires_at": now_utc() - timedelta(seconds=1)}},
    )
    newer_claim = claim_job(job["_id"])

    assert mark_job_completed(job["_id"], job["claim_token"], {"packet_count": 1}) is None
    assert mark_job_failed(job["_id"], job["claim_token"], "failed", "failure") is None
    current = get_database()["analysis_jobs"].find_one({"_id": job["_id"]})
    assert current["status"] == "running"
    assert current["claim_token"] == newer_claim["claim_token"]


def test_current_claim_can_complete_and_clears_lease(job_store, tmp_path):
    job = claim_job(make_job(tmp_path)["_id"])
    completed = mark_job_completed(job["_id"], job["claim_token"], {"packet_count": 2})
    assert completed["status"] == "completed"
    assert completed["claim_token"] is None
    assert completed["lease_expires_at"] is None


def test_lease_renews_only_for_current_unexpired_claim(job_store, monkeypatch, tmp_path):
    import app.jobs as jobs_module

    claimed = claim_job(make_job(tmp_path)["_id"])
    renewal_time = claimed["started_at"] + timedelta(seconds=1)
    monkeypatch.setattr(jobs_module, "now_utc", lambda: renewal_time)
    assert renew_job_lease(claimed["_id"], claimed["claim_token"])
    renewed = get_database()["analysis_jobs"].find_one({"_id": claimed["_id"]})
    assert renewed["lease_renewed_at"] == renewal_time
    assert renewed["lease_expires_at"] == renewal_time + timedelta(seconds=jobs_module.JOB_LEASE_SECONDS)

    monkeypatch.setattr(jobs_module, "now_utc", lambda: renewal_time + timedelta(seconds=jobs_module.JOB_LEASE_SECONDS + 1))
    get_database()["analysis_jobs"].update_one(
        {"_id": claimed["_id"]},
        {"$set": {"lease_expires_at": renewal_time + timedelta(seconds=jobs_module.JOB_LEASE_SECONDS)}},
    )
    assert not renew_job_lease(claimed["_id"], claimed["claim_token"])


def test_expired_lease_cannot_complete_or_fail_before_reclaim(job_store, tmp_path):
    claimed = claim_job(make_job(tmp_path)["_id"])
    get_database()["analysis_jobs"].update_one(
        {"_id": claimed["_id"]},
        {"$set": {"lease_expires_at": now_utc() - timedelta(seconds=1)}},
    )
    assert mark_job_completed(claimed["_id"], claimed["claim_token"], {}) is None
    assert mark_job_failed(claimed["_id"], claimed["claim_token"], "failure", "failed") is None


def test_claim_next_recoverable_job_is_atomic_and_skips_active_lease(job_store, tmp_path):
    active = claim_job(make_job(tmp_path)["_id"])
    queued = make_job(tmp_path)
    from app.jobs import claim_next_recoverable_job

    recovered = claim_next_recoverable_job()
    assert recovered["_id"] == queued["_id"]
    assert recovered["claim_token"]
    assert claim_next_recoverable_job() is None
    current_active = get_database()["analysis_jobs"].find_one({"_id": active["_id"]})
    assert current_active["claim_token"] == active["claim_token"]
