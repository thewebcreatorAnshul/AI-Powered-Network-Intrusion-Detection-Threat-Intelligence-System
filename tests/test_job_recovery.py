from datetime import timedelta
import os
import threading
import time
from types import SimpleNamespace

import pytest
from bson import BSON, ObjectId
from pymongo.errors import PyMongoError
from scapy.all import Ether, wrpcap
from starlette.testclient import TestClient

from app.alerts import (
    alert_outbox_collection,
    alerts_collection,
    build_alert_intent,
    ensure_alert_indexes,
    materialize_alert_intent,
    relay_next_pending_alert_intent,
    relay_pending_alert_intents_for_job,
)
from app.analysis_results import (
    StaleAnalysisClaimError,
    analysis_findings_collection,
    cleanup_orphaned_analysis_findings,
    cleanup_other_analysis_attempts,
    ensure_analysis_result_indexes,
    get_analysis_findings_page,
    persist_analysis_findings,
)
from app.config import get_settings
from app.database import get_database, set_required_indexes_ready
from app.jobs import (
    claim_job,
    create_analysis_job,
    enqueue_alert_intent,
    mark_job_completed,
    now_utc,
)
from app.users import ensure_user_indexes
from tests.fake_mongo import Client as FakeMongoClient
import app.database as database_module
import app.ingestion.processor as processor_module
import app.ingestion.storage as storage_module
import app.main as main_module
import app.alerts as alerts_module
import app.jobs as jobs_module


@pytest.fixture
def recovery_store(monkeypatch):
    monkeypatch.setenv("MONGODB_DATABASE", "intrusion_detection_test")
    monkeypatch.setenv("JWT_SECRET", "test-only-jwt-secret-long-enough-for-tests-123456")
    monkeypatch.setenv("THREAT_INTEL_MODE", "offline")
    get_settings.cache_clear()
    monkeypatch.setattr(database_module, "_client", FakeMongoClient())
    ensure_user_indexes()
    jobs_module.ensure_job_indexes()
    ensure_alert_indexes()
    ensure_analysis_result_indexes()
    set_required_indexes_ready(True)
    yield
    database_module.close_client()
    get_settings.cache_clear()


def finding():
    return {
        "severity": "high",
        "category": "reconnaissance",
        "method": "signature",
        "detection_type": "signature",
        "rule_id": "SIG-TEST-001",
        "rule_version": "1",
        "title": "Controlled finding",
        "description": "Test evidence",
        "evidence": {"source_ip": "192.0.2.10", "ports": [22, 23]},
    }


def test_alert_is_idempotent_for_retried_finding(recovery_store, tmp_path):
    ensure_alert_indexes()
    job = create_analysis_job("user-1", "capture.pcap", 10, tmp_path / "capture.pcap")
    claimed = claim_job(job["_id"])
    intent = build_alert_intent(claimed, finding())

    assert enqueue_alert_intent(claimed["_id"], claimed["claim_token"], intent)
    assert enqueue_alert_intent(claimed["_id"], claimed["claim_token"], intent)
    assert mark_job_completed(claimed["_id"], claimed["claim_token"], {"alert_count": 1})["status"] == "completed"
    relay_pending_alert_intents_for_job(claimed["_id"])
    first = alerts_collection().find_one({"job_id": str(job["_id"])})
    second = materialize_alert_intent(job["_id"], intent)

    assert first["_id"] == second["_id"]
    assert len(alerts_collection().find({"job_id": str(job["_id"])})) == 1
    assert any(
        index[0] == ("dedupe_key",) and index[1] and index[2]
        for index in alerts_collection().unique_indexes
    )
    assert any(
        index[0] == ("job_id", "claim_token", "dedupe_key") and index[1]
        for index in alert_outbox_collection().unique_indexes
    )
    stored = get_database()["analysis_jobs"].find_one({"_id": job["_id"]})
    assert "alert_outbox" not in stored
    assert alert_outbox_collection().find_one({"job_id": job["_id"]}) is None


def test_outbox_rejects_invalid_tokens_and_expired_leases(recovery_store, tmp_path):
    job = claim_job(create_analysis_job("user", "capture.pcap", 10, tmp_path / "capture.pcap")["_id"])
    intent = build_alert_intent(job, finding())

    assert not enqueue_alert_intent(job["_id"], "wrong-token", intent)
    get_database()["analysis_jobs"].update_one(
        {"_id": job["_id"]},
        {"$set": {"lease_expires_at": now_utc() - timedelta(seconds=1)}},
    )
    assert not enqueue_alert_intent(job["_id"], job["claim_token"], intent)
    assert alert_outbox_collection().find_one({"job_id": job["_id"], "status": "pending"}) is None


def test_lease_reclaim_and_alert_enqueue_race_is_fenced(recovery_store, monkeypatch, tmp_path):
    job = claim_job(create_analysis_job("user", "capture.pcap", 10, tmp_path / "capture.pcap")["_id"])
    intent = build_alert_intent(job, finding())
    base = now_utc()
    expires_at = base + timedelta(seconds=1)
    get_database()["analysis_jobs"].update_one(
        {"_id": job["_id"]},
        {"$set": {"lease_expires_at": expires_at}},
    )
    barrier = threading.Barrier(2)

    def controlled_clock():
        return base + timedelta(seconds=2) if threading.current_thread().name == "reclaimer" else base + timedelta(milliseconds=500)

    monkeypatch.setattr(jobs_module, "now_utc", controlled_clock)
    monkeypatch.setattr(alerts_module, "now_utc", controlled_clock)

    def enqueue():
        threading.current_thread().name = "enqueuer"
        barrier.wait()
        return enqueue_alert_intent(job["_id"], job["claim_token"], intent)

    def reclaim():
        threading.current_thread().name = "reclaimer"
        barrier.wait()
        return claim_job(job["_id"])

    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=2) as executor:
        enqueue_future = executor.submit(enqueue)
        reclaim_future = executor.submit(reclaim)
        enqueued = enqueue_future.result(timeout=3)
        replacement = reclaim_future.result(timeout=3)

    stored = get_database()["analysis_jobs"].find_one({"_id": job["_id"]})
    assert replacement["claim_token"] != job["claim_token"]
    assert stored["claim_token"] == replacement["claim_token"]
    old_intents = list(
        alert_outbox_collection().find({"job_id": job["_id"], "claim_token": job["claim_token"]})
    )
    assert len(old_intents) <= int(enqueued)
    assert not enqueue_alert_intent(job["_id"], job["claim_token"], build_alert_intent(job, {**finding(), "title": "stale extra"}))

    current_intent = build_alert_intent(replacement, finding())
    assert enqueue_alert_intent(job["_id"], replacement["claim_token"], current_intent)
    assert mark_job_completed(job["_id"], replacement["claim_token"], {"alert_count": 1})["status"] == "completed"
    relay_pending_alert_intents_for_job(job["_id"])
    assert len(list(alerts_collection().find({"job_id": str(job["_id"])}))) == 1


def test_crash_after_enqueue_is_recovered_from_outbox(recovery_store, tmp_path):
    ensure_alert_indexes()
    job = claim_job(create_analysis_job("user", "capture.pcap", 10, tmp_path / "capture.pcap")["_id"])
    intent = build_alert_intent(job, finding())
    assert enqueue_alert_intent(job["_id"], job["claim_token"], intent)

    get_database()["analysis_jobs"].update_one(
        {"_id": job["_id"]},
        {"$set": {"lease_expires_at": now_utc() - timedelta(seconds=1)}},
    )
    reclaimed = claim_job(job["_id"])
    assert reclaimed["claim_token"] != job["claim_token"]
    assert enqueue_alert_intent(job["_id"], reclaimed["claim_token"], build_alert_intent(reclaimed, finding()))
    mark_job_completed(job["_id"], reclaimed["claim_token"], {"alert_count": 1})

    assert relay_next_pending_alert_intent()
    stored = get_database()["analysis_jobs"].find_one({"_id": job["_id"]})
    assert "alert_outbox" not in stored
    assert alert_outbox_collection().find_one({"job_id": job["_id"], "claim_token": job["claim_token"]}) is None
    assert alerts_collection().find_one({"dedupe_key": intent["dedupe_key"]}) is not None


def test_crash_after_staging_intent_before_lease_validation_is_not_relayed(recovery_store, monkeypatch, tmp_path):
    job = claim_job(create_analysis_job("user", "capture.pcap", 10, tmp_path / "capture.pcap")["_id"])
    intent = build_alert_intent(job, finding())
    original_jobs_collection = alerts_module.jobs_collection

    class FailingJobCollection:
        def find_one(self, query):
            return original_jobs_collection().find_one(query)

        def update_one(self, *_args, **_kwargs):
            raise PyMongoError("simulated crash after outbox insert")

    monkeypatch.setattr(alerts_module, "jobs_collection", lambda: FailingJobCollection())
    with pytest.raises(PyMongoError, match="simulated crash"):
        enqueue_alert_intent(job["_id"], job["claim_token"], intent)
    staged = alert_outbox_collection().find_one({"job_id": job["_id"]})
    assert staged["status"] == "staged"
    monkeypatch.setattr(alerts_module, "jobs_collection", original_jobs_collection)

    get_database()["analysis_jobs"].update_one(
        {"_id": job["_id"]},
        {"$set": {"lease_expires_at": now_utc() - timedelta(seconds=1)}},
    )
    reclaimed = claim_job(job["_id"])
    current_intent = build_alert_intent(reclaimed, finding())
    assert enqueue_alert_intent(job["_id"], reclaimed["claim_token"], current_intent)
    mark_job_completed(job["_id"], reclaimed["claim_token"], {"alert_count": 1})

    relay_pending_alert_intents_for_job(job["_id"])

    assert len(list(alerts_collection().find({"job_id": str(job["_id"])}))) == 1
    assert alert_outbox_collection().find_one({"job_id": job["_id"]}) is None


def test_crash_after_alert_upsert_before_delivery_mark_is_retry_safe(recovery_store, monkeypatch, tmp_path):
    ensure_alert_indexes()
    job = claim_job(create_analysis_job("user", "capture.pcap", 10, tmp_path / "capture.pcap")["_id"])
    intent = build_alert_intent(job, finding())
    enqueue_alert_intent(job["_id"], job["claim_token"], intent)
    mark_job_completed(job["_id"], job["claim_token"], {"alert_count": 1})
    original_ack = alert_outbox_collection().delete_one
    fail_once = True

    def fail_first_ack(*_args, **_kwargs):
        nonlocal fail_once
        if fail_once:
            fail_once = False
            raise RuntimeError("simulated crash before delivery acknowledgement")
        return original_ack(*_args, **_kwargs)

    monkeypatch.setattr(alert_outbox_collection(), "delete_one", fail_first_ack)
    with pytest.raises(RuntimeError, match="simulated crash"):
        relay_pending_alert_intents_for_job(job["_id"])
    assert len(alerts_collection().find({"job_id": str(job["_id"])})) == 1

    relay_pending_alert_intents_for_job(job["_id"])
    assert len(alerts_collection().find({"job_id": str(job["_id"])})) == 1
    assert alert_outbox_collection().find_one({"job_id": job["_id"]}) is None


def test_completed_job_with_pending_outbox_is_drained(recovery_store, tmp_path):
    ensure_alert_indexes()
    job = claim_job(create_analysis_job("user", "capture.pcap", 10, tmp_path / "capture.pcap")["_id"])
    intent = build_alert_intent(job, finding())
    assert enqueue_alert_intent(job["_id"], job["claim_token"], intent)
    assert mark_job_completed(job["_id"], job["claim_token"], {"alert_count": 1})["status"] == "completed"

    assert relay_next_pending_alert_intent()
    stored = get_database()["analysis_jobs"].find_one({"_id": job["_id"]})
    assert stored["status"] == "completed"
    assert alert_outbox_collection().find_one({"job_id": job["_id"]}) is None


def test_legacy_embedded_outbox_entries_are_still_drained(recovery_store, tmp_path):
    job = claim_job(create_analysis_job("user", "legacy.pcap", 10, tmp_path / "legacy.pcap")["_id"])
    intent = build_alert_intent(job, finding())
    get_database()["analysis_jobs"].update_one(
        {"_id": job["_id"]},
        {"$push": {"alert_outbox": intent}},
    )
    mark_job_completed(job["_id"], job["claim_token"], {"alert_count": 1})

    assert relay_next_pending_alert_intent()

    stored = get_database()["analysis_jobs"].find_one({"_id": job["_id"]})
    assert stored["alert_outbox"][0]["delivered"] is True
    assert stored["alert_outbox"][0]["payload"] is None
    assert alerts_collection().find_one({"dedupe_key": intent["dedupe_key"]}) is not None


def test_outbox_relay_concurrency_is_bounded(recovery_store, monkeypatch, tmp_path):
    ensure_alert_indexes()
    jobs = []
    for index in range(5):
        claimed = claim_job(create_analysis_job("user", f"{index}.pcap", 10, tmp_path / f"{index}.pcap")["_id"])
        enqueue_alert_intent(claimed["_id"], claimed["claim_token"], build_alert_intent(claimed, {**finding(), "title": f"finding-{index}"}))
        mark_job_completed(claimed["_id"], claimed["claim_token"], {"alert_count": 1})
        jobs.append(claimed)

    lock = threading.Lock()
    active = 0
    maximum_active = 0
    both_entered = threading.Event()
    release = threading.Event()
    original_materialize = alerts_module.materialize_alert_intent

    def observed_materialize(job_id, intent):
        nonlocal active, maximum_active
        with lock:
            active += 1
            maximum_active = max(maximum_active, active)
            if active == alerts_module.OUTBOX_RELAY_CONCURRENCY:
                both_entered.set()
        assert release.wait(3)
        try:
            return original_materialize(job_id, intent)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(alerts_module, "materialize_alert_intent", observed_materialize)
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(relay_pending_alert_intents_for_job, job["_id"]) for job in jobs]
        assert both_entered.wait(3)
        assert maximum_active == alerts_module.OUTBOX_RELAY_CONCURRENCY
        release.set()
        for future in futures:
            future.result(timeout=5)

    assert maximum_active <= alerts_module.OUTBOX_RELAY_CONCURRENCY
    assert len(alerts_collection().find({})) == len(jobs)


def test_many_findings_are_stored_outside_the_analysis_job_document(recovery_store, tmp_path):
    from bson import BSON

    job = claim_job(create_analysis_job("user", "large.pcap", 10, tmp_path / "large.pcap")["_id"])
    finding_count = 350
    for index in range(finding_count):
        item = {**finding(), "title": f"finding-{index}", "evidence": {"index": index}}
        assert enqueue_alert_intent(job["_id"], job["claim_token"], build_alert_intent(job, item))

    stored = get_database()["analysis_jobs"].find_one({"_id": job["_id"]})
    assert "alert_outbox" not in stored
    assert len(list(alert_outbox_collection().find({"job_id": job["_id"], "status": "pending"}))) == finding_count
    assert len(BSON.encode(stored)) < 1024 * 1024
    assert relay_pending_alert_intents_for_job(job["_id"]) == 0
    assert alerts_collection().find_one({"job_id": str(job["_id"])}) is None

    mark_job_completed(job["_id"], job["claim_token"], {"alert_count": finding_count})
    delivered = 0
    while delivered < finding_count:
        count = relay_pending_alert_intents_for_job(job["_id"])
        if count == 0:
            break
        delivered += count
    assert delivered == finding_count
    assert len(list(alerts_collection().find({"job_id": str(job["_id"])}))) == finding_count
    assert alert_outbox_collection().find_one({"job_id": job["_id"]}) is None


def test_large_analysis_results_do_not_enlarge_the_job_document(recovery_store, tmp_path):
    job = create_analysis_job("user", "very-large.pcap", 10, tmp_path / "large.pcap")
    claimed = claim_job(job["_id"])
    findings = [
        {
            "rule_id": "SIG-LARGE",
            "rule_version": "1",
            "title": f"Finding {index}",
            "description": "x" * 6000,
            "severity": "medium",
            "evidence": {"record": index},
        }
        for index in range(3000)
    ]

    assert persist_analysis_findings(job["_id"], claimed["claim_token"], findings) == len(findings)
    completed = mark_job_completed(
        job["_id"],
        claimed["claim_token"],
        {"finding_count": len(findings), "findings_storage": "analysis_findings"},
    )
    stored = get_database()["analysis_jobs"].find_one({"_id": job["_id"]})
    assert completed["status"] == "completed"
    assert len(BSON.encode(stored)) < 1024 * 1024
    assert "findings" not in stored["summary"]
    assert analysis_findings_collection().count_documents(
        {"job_id": job["_id"], "claim_token": claimed["claim_token"]}
    ) == len(findings)
    assert any(
        index[0] == ("job_id", "claim_token", "finding_index") and index[1]
        for index in analysis_findings_collection().unique_indexes
    )
    page, total = get_analysis_findings_page(stored, skip=2990, limit=20)
    assert total == len(findings)
    assert [item["title"] for item in page] == [f"Finding {index}" for index in range(2990, 3000)]


def test_partial_result_writes_recover_without_duplicate_findings(recovery_store, tmp_path):
    job = create_analysis_job("user", "retry-results.pcap", 10, tmp_path / "retry.pcap")
    first_claim = claim_job(job["_id"])
    findings = [{**finding(), "title": f"finding-{index}"} for index in range(5)]
    assert persist_analysis_findings(job["_id"], first_claim["claim_token"], findings[:2]) == 2

    get_database()["analysis_jobs"].update_one(
        {"_id": job["_id"]},
        {"$set": {"lease_expires_at": now_utc() - timedelta(seconds=1)}},
    )
    retry_claim = claim_job(job["_id"])
    assert retry_claim["claim_token"] != first_claim["claim_token"]
    cleanup_other_analysis_attempts(job["_id"], retry_claim["claim_token"])
    assert persist_analysis_findings(job["_id"], retry_claim["claim_token"], findings) == 5
    assert persist_analysis_findings(job["_id"], retry_claim["claim_token"], findings) == 5
    assert mark_job_completed(job["_id"], retry_claim["claim_token"], {"finding_count": 5})["status"] == "completed"

    stored = get_database()["analysis_jobs"].find_one({"_id": job["_id"]})
    page, total = get_analysis_findings_page(stored, skip=0, limit=10)
    assert total == 5
    assert [item["title"] for item in page] == [item["title"] for item in findings]
    assert analysis_findings_collection().count_documents({"job_id": job["_id"]}) == 5


def test_stale_or_expired_claim_cannot_persist_analysis_findings(recovery_store, tmp_path):
    job = create_analysis_job("user", "stale-write.pcap", 10, tmp_path / "stale.pcap")
    first = claim_job(job["_id"])
    get_database()["analysis_jobs"].update_one(
        {"_id": job["_id"]},
        {"$set": {"lease_expires_at": now_utc() - timedelta(seconds=1)}},
    )
    replacement = claim_job(job["_id"])
    assert replacement["claim_token"] != first["claim_token"]

    with pytest.raises(StaleAnalysisClaimError):
        persist_analysis_findings(job["_id"], first["claim_token"], [finding()])
    assert analysis_findings_collection().count_documents({"job_id": job["_id"]}) == 0


def test_claim_replacement_race_leaves_invisible_row_for_cleanup(recovery_store, tmp_path, monkeypatch):
    import app.analysis_results as results_module

    job = create_analysis_job("user", "claim-race.pcap", 10, tmp_path / "race.pcap")
    first = claim_job(job["_id"])
    original_check = results_module.job_claim_is_active
    replacement = {}

    def replace_immediately_after_check(job_id, token, **kwargs):
        nonlocal replacement
        active = original_check(job_id, token, **kwargs)
        get_database()["analysis_jobs"].update_one(
            {"_id": job_id},
            {"$set": {"lease_expires_at": now_utc() - timedelta(seconds=1)}},
        )
        replacement = claim_job(job_id)
        return active

    monkeypatch.setattr(results_module, "job_claim_is_active", replace_immediately_after_check)
    assert persist_analysis_findings(job["_id"], first["claim_token"], [finding()]) == 1
    monkeypatch.setattr(results_module, "job_claim_is_active", original_check)

    scanned, deleted, _cursor = cleanup_orphaned_analysis_findings(batch_size=10)
    assert scanned >= 1 and deleted == 1
    assert replacement["claim_token"] != first["claim_token"]
    assert analysis_findings_collection().count_documents({"job_id": job["_id"]}) == 0


def test_orphan_cleanup_preserves_completed_results(recovery_store, tmp_path):
    job = create_analysis_job("user", "completed-protection.pcap", 10, tmp_path / "done.pcap")
    claimed = claim_job(job["_id"])
    persist_analysis_findings(job["_id"], claimed["claim_token"], [finding()])
    assert mark_job_completed(job["_id"], claimed["claim_token"], {"finding_count": 1})
    # Add a row from an invalid token to prove cleanup is claim-scoped.
    analysis_findings_collection().insert_one({
        "job_id": job["_id"], "claim_token": "invalid-token", "finding_index": 0,
        "finding": finding(),
    })

    scanned, deleted, _cursor = cleanup_orphaned_analysis_findings(batch_size=10)
    stored = get_database()["analysis_jobs"].find_one({"_id": job["_id"]})
    page, total = get_analysis_findings_page(stored, skip=0, limit=10)
    assert scanned >= 2 and deleted == 1
    assert total == 1 and page == [finding()]
    assert analysis_findings_collection().count_documents(
        {"job_id": job["_id"], "claim_token": claimed["claim_token"]}
    ) == 1


def test_orphan_cleanup_preserves_current_live_claim(recovery_store, tmp_path):
    job = create_analysis_job("user", "active-claim.pcap", 10, tmp_path / "active.pcap")
    claimed = claim_job(job["_id"])
    assert persist_analysis_findings(job["_id"], claimed["claim_token"], [finding()]) == 1

    scanned, deleted, _cursor = cleanup_orphaned_analysis_findings(batch_size=10)

    assert scanned >= 1 and deleted == 0
    assert analysis_findings_collection().count_documents(
        {"job_id": job["_id"], "claim_token": claimed["claim_token"]}
    ) == 1


def test_orphan_cleanup_handles_pymongo_naive_utc_lease(recovery_store, tmp_path):
    job = create_analysis_job("user", "naive-lease.pcap", 10, tmp_path / "naive.pcap")
    claimed = claim_job(job["_id"])
    persist_analysis_findings(job["_id"], claimed["claim_token"], [finding()])
    get_database()["analysis_jobs"].update_one(
        {"_id": job["_id"]},
        {"$set": {"lease_expires_at": (now_utc() + timedelta(minutes=1)).replace(tzinfo=None)}},
    )

    scanned, deleted, _cursor = cleanup_orphaned_analysis_findings(batch_size=10)

    assert scanned >= 1 and deleted == 0
    assert analysis_findings_collection().count_documents({"job_id": job["_id"]}) == 1


def test_orphan_cleanup_is_bounded_and_eventually_removes_large_backlog(recovery_store):
    collection = analysis_findings_collection()
    orphan_count = 450
    for index in range(orphan_count):
        collection.insert_one({
            "job_id": ObjectId(),
            "claim_token": "orphan-token",
            "finding_index": index,
            "finding": finding(),
        })
    cursor = None
    scanned_total = deleted_total = 0
    while True:
        scanned, deleted, cursor = cleanup_orphaned_analysis_findings(
            after_id=cursor,
            batch_size=37,
        )
        assert scanned <= 37
        scanned_total += scanned
        deleted_total += deleted
        if scanned == 0:
            break
    assert scanned_total == orphan_count
    assert deleted_total == orphan_count
    assert collection.count_documents({"claim_token": "orphan-token"}) == 0


def test_orphan_cleanup_failure_is_idempotent_and_preserves_completed_findings(
    recovery_store, tmp_path, monkeypatch
):
    from pymongo.errors import PyMongoError

    job = create_analysis_job("user", "cleanup-failure.pcap", 10, tmp_path / "clean.pcap")
    claimed = claim_job(job["_id"])
    persist_analysis_findings(job["_id"], claimed["claim_token"], [finding()])
    assert mark_job_completed(job["_id"], claimed["claim_token"], {"finding_count": 1})
    collection = analysis_findings_collection()
    collection.insert_one({
        "job_id": job["_id"], "claim_token": "invalid-token", "finding_index": 0,
        "finding": finding(),
    })
    original_delete_one = collection.delete_one

    def fail_delete(_query):
        raise PyMongoError("controlled cleanup failure")

    monkeypatch.setattr(collection, "delete_one", fail_delete)
    with pytest.raises(PyMongoError):
        cleanup_orphaned_analysis_findings(batch_size=10)
    stored = get_database()["analysis_jobs"].find_one({"_id": job["_id"]})
    assert get_analysis_findings_page(stored, skip=0, limit=10) == ([finding()], 1)

    monkeypatch.setattr(collection, "delete_one", original_delete_one)
    _scanned, deleted, _cursor = cleanup_orphaned_analysis_findings(batch_size=10)
    assert deleted == 1
    assert get_analysis_findings_page(stored, skip=0, limit=10) == ([finding()], 1)


def test_stale_cleanup_preserves_files_referenced_by_nonterminal_jobs(recovery_store, tmp_path):
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    settings = SimpleNamespace(upload_dir=upload_dir, retention_hours=1)
    keep_queued = upload_dir / "queued.pcap"
    keep_running = upload_dir / "running.pcap"
    remove_completed = upload_dir / "completed.pcap"
    remove_orphan = upload_dir / "orphan.pcap"
    for path in (keep_queued, keep_running, remove_completed, remove_orphan):
        path.write_bytes(b"old")
        os.utime(path, (time.time() - 7200, time.time() - 7200))

    queued = create_analysis_job("user", "queued.pcap", 3, keep_queued)
    running = create_analysis_job("user", "running.pcap", 3, keep_running)
    completed = create_analysis_job("user", "completed.pcap", 3, remove_completed)
    jobs = get_database()["analysis_jobs"]
    jobs.update_one({"_id": running["_id"]}, {"$set": {"status": "running"}})
    jobs.update_one({"_id": completed["_id"]}, {"$set": {"status": "completed"}})

    assert "jobs_storage_name_cleanup" in jobs.index_information()

    storage_module.cleanup_stale_uploads(settings)

    assert keep_queued.exists()
    assert keep_running.exists()
    assert not remove_completed.exists()
    assert not remove_orphan.exists()


def test_missing_staged_capture_fails_claimed_job_safely(recovery_store, monkeypatch, tmp_path):
    monkeypatch.setenv("UPLOAD_DIR", str(tmp_path / "uploads"))
    get_settings.cache_clear()
    job = create_analysis_job("user", "missing.pcap", 10, tmp_path / "uploads" / "missing.pcap")

    result = processor_module.process_analysis_job(job)
    stored = get_database()["analysis_jobs"].find_one({"_id": job["_id"]})

    assert result["status"] == "failed"
    assert result["error_code"] == "missing_capture"
    assert stored["finished_at"] is not None
    assert stored["claim_token"] is None


def _make_processable_job(monkeypatch, tmp_path, *, findings=None):
    monkeypatch.setenv("UPLOAD_DIR", str(tmp_path / "uploads"))
    get_settings.cache_clear()
    staged = tmp_path / "uploads" / "capture.pcap"
    staged.parent.mkdir(parents=True, exist_ok=True)
    staged.write_bytes(b"validated by the test adapter")
    job = create_analysis_job("user", "capture.pcap", staged.stat().st_size, staged)

    class Adapter:
        def validate(self, _path):
            return None

        def iter_records(self, _path):
            yield {"protocol": "tcp"}

        def metadata(self, _path):
            return {"source_format": "pcap"}

    monkeypatch.setattr(processor_module, "get_source_adapter", lambda _source: Adapter())
    monkeypatch.setattr(
        processor_module,
        "analyze_records",
        lambda _records: ({"packet_count": 1, "flow_count": 1, "protocol_counts": {"tcp": 1}}, findings or []),
    )
    monkeypatch.setattr(processor_module, "enrich_findings", lambda items, *_args: (items, {"status": "skipped"}))
    return job


def _assert_running_job_is_recoverable(job, result):
    assert result["status"] == "running"
    stored = get_database()["analysis_jobs"].find_one({"_id": job["_id"]})
    assert stored["status"] == "running"
    assert stored["claim_token"] == result["claim_token"]
    assert stored["lease_expires_at"] > now_utc()
    assert claim_job(job["_id"]) is None

    get_database()["analysis_jobs"].update_one(
        {"_id": job["_id"]},
        {"$set": {"lease_expires_at": now_utc() - timedelta(seconds=1)}},
    )
    reclaimed = claim_job(job["_id"])
    assert reclaimed is not None
    assert reclaimed["claim_token"] != result["claim_token"]
    assert reclaimed["status"] == "running"
    return reclaimed


def test_analysis_time_budget_fails_safely(recovery_store, monkeypatch, tmp_path):
    job = _make_processable_job(monkeypatch, tmp_path)
    monkeypatch.setenv("ANALYSIS_TIMEOUT_SECONDS", "1")
    get_settings.cache_clear()

    class SlowAdapter:
        def validate(self, _path):
            return None

        def iter_records(self, _path):
            time.sleep(1.05)
            yield {"protocol": "tcp"}

        def metadata(self, _path):
            return {"source_format": "pcap"}

    monkeypatch.setattr(processor_module, "get_source_adapter", lambda _source: SlowAdapter())
    result = processor_module.process_analysis_job(job)

    assert result["status"] == "failed"
    assert result["error_code"] == "capture_processing_limit"


def test_transient_mongo_error_during_alert_enqueue_remains_recoverable(recovery_store, monkeypatch, tmp_path):
    job = _make_processable_job(monkeypatch, tmp_path, findings=[finding()])
    original_enqueue = processor_module.enqueue_alert_intent

    def enqueue_then_raise(*args):
        original_enqueue(*args)
        raise PyMongoError("temporary enqueue response failure")

    monkeypatch.setattr(processor_module, "enqueue_alert_intent", enqueue_then_raise)

    result = processor_module.process_analysis_job(job)

    reclaimed = _assert_running_job_is_recoverable(job, result)
    assert len(list(alert_outbox_collection().find({"job_id": job["_id"]}))) == 1

    monkeypatch.setattr(processor_module, "enqueue_alert_intent", original_enqueue)
    retried = processor_module.process_claimed_analysis_job(reclaimed)
    stored = get_database()["analysis_jobs"].find_one({"_id": job["_id"]})
    assert retried["status"] == "completed"
    assert "alert_outbox" not in stored
    assert alert_outbox_collection().find_one({"job_id": job["_id"]}) is None
    assert len(list(alerts_collection().find({"job_id": str(job["_id"])}))) == 1


def test_transient_mongo_error_during_outbox_relay_remains_recoverable(recovery_store, monkeypatch, tmp_path):
    job = _make_processable_job(monkeypatch, tmp_path, findings=[finding()])
    original_relay = processor_module.relay_pending_alert_intents_for_job
    monkeypatch.setattr(
        processor_module,
        "relay_pending_alert_intents_for_job",
        lambda *_args: (_ for _ in ()).throw(PyMongoError("temporary relay failure")),
    )

    result = processor_module.process_analysis_job(job)

    assert result["status"] == "completed"
    stored = get_database()["analysis_jobs"].find_one({"_id": job["_id"]})
    assert stored["status"] == "completed"
    assert len(list(alert_outbox_collection().find({"job_id": job["_id"], "status": "pending"}))) == 1
    assert alerts_collection().find_one({"job_id": str(job["_id"])}) is None
    monkeypatch.setattr(processor_module, "relay_pending_alert_intents_for_job", original_relay)
    relay_pending_alert_intents_for_job(job["_id"])
    assert len(list(alerts_collection().find({"job_id": str(job["_id"])}))) == 1


def test_transient_mongo_error_during_completion_remains_recoverable(recovery_store, monkeypatch, tmp_path):
    job = _make_processable_job(monkeypatch, tmp_path)
    monkeypatch.setattr(
        processor_module,
        "mark_job_completed",
        lambda *_args: (_ for _ in ()).throw(PyMongoError("temporary completion failure")),
    )

    result = processor_module.process_analysis_job(job)

    _assert_running_job_is_recoverable(job, result)


def test_malformed_capture_still_fails_permanently(recovery_store, monkeypatch, tmp_path):
    monkeypatch.setenv("UPLOAD_DIR", str(tmp_path / "uploads"))
    get_settings.cache_clear()
    staged = tmp_path / "uploads" / "malformed.pcap"
    staged.parent.mkdir(parents=True, exist_ok=True)
    staged.write_bytes(b"not a pcap")
    job = create_analysis_job("user", "malformed.pcap", staged.stat().st_size, staged)

    result = processor_module.process_analysis_job(job)
    stored = get_database()["analysis_jobs"].find_one({"_id": job["_id"]})

    assert result["status"] == "failed"
    assert result["error_code"] == "unsupported_capture"
    assert stored["status"] == "failed"
    assert stored["claim_token"] is None


def test_lost_lease_stops_processor_before_alert_persistence(recovery_store, monkeypatch, tmp_path):
    monkeypatch.setenv("UPLOAD_DIR", str(tmp_path))
    get_settings.cache_clear()
    staged = tmp_path / "capture.pcap"
    staged.write_bytes(b"placeholder")
    job = create_analysis_job("user", "capture.pcap", 11, staged)
    parsing_started = threading.Event()
    lease_lost = threading.Event()
    heartbeat_stopped = threading.Event()
    persisted_alerts = []

    class SlowAdapter:
        def validate(self, _path):
            return None

        def iter_records(self, _path):
            parsing_started.set()
            assert lease_lost.wait(2)
            yield {"protocol": "tcp"}

        def metadata(self, _path):
            return {"source_format": "pcap"}

    monkeypatch.setattr(processor_module, "get_source_adapter", lambda _source: SlowAdapter())
    monkeypatch.setattr(processor_module, "analyze_records", lambda _records: ({"packet_count": 1, "flow_count": 1, "protocol_counts": {}}, [finding()]))
    monkeypatch.setattr(processor_module, "enrich_findings", lambda findings, *_args: (findings, {"status": "skipped"}))
    monkeypatch.setattr(processor_module, "enqueue_alert_intent", lambda *_args: persisted_alerts.append("unexpected"))
    monkeypatch.setattr(processor_module, "LEASE_HEARTBEAT_INTERVAL_SECONDS", 0.02)

    original_stop = processor_module.LeaseHeartbeat.stop_and_wait

    def stop_and_observe(heartbeat):
        original_stop(heartbeat)
        assert not heartbeat._thread.is_alive()
        heartbeat_stopped.set()

    monkeypatch.setattr(processor_module.LeaseHeartbeat, "stop_and_wait", stop_and_observe)

    def lose_lease(_job_id, _claim_token):
        get_database()["analysis_jobs"].update_one(
            {"_id": job["_id"]},
            {"$set": {"claim_token": "new-owner", "lease_expires_at": now_utc() + timedelta(minutes=5)}},
        )
        lease_lost.set()
        return False

    monkeypatch.setattr(processor_module, "renew_job_lease", lose_lease)

    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(processor_module.process_analysis_job, job)
        assert parsing_started.wait(2)
        result = future.result(timeout=3)

    assert result["status"] == "running"
    assert persisted_alerts == []
    assert heartbeat_stopped.is_set()
    assert staged.exists()


def test_startup_recovers_persisted_queued_job(recovery_store, monkeypatch, tmp_path):
    from app.main import app

    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    monkeypatch.setenv("UPLOAD_DIR", str(upload_dir))
    get_settings.cache_clear()
    capture = upload_dir / "startup.pcap"
    wrpcap(str(capture), [Ether()])
    job = create_analysis_job("user", "startup.pcap", capture.stat().st_size, capture)

    with TestClient(app):
        deadline = time.monotonic() + 5
        stored = None
        while time.monotonic() < deadline:
            stored = get_database()["analysis_jobs"].find_one({"_id": job["_id"]})
            if stored and stored["status"] in {"completed", "failed"}:
                break
            time.sleep(0.01)

    assert stored["status"] == "completed"
    assert stored["summary"]["packet_count"] == 1


def test_startup_reclaims_expired_running_job(recovery_store, monkeypatch, tmp_path):
    from app.main import app

    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    monkeypatch.setenv("UPLOAD_DIR", str(upload_dir))
    get_settings.cache_clear()
    capture = upload_dir / "expired.pcap"
    wrpcap(str(capture), [Ether()])
    job = create_analysis_job("user", "expired.pcap", capture.stat().st_size, capture)
    get_database()["analysis_jobs"].update_one(
        {"_id": job["_id"]},
        {"$set": {
            "status": "running",
            "claim_token": "previous-process",
            "lease_expires_at": now_utc() - timedelta(seconds=1),
        }},
    )

    with TestClient(app):
        deadline = time.monotonic() + 5
        stored = None
        while time.monotonic() < deadline:
            stored = get_database()["analysis_jobs"].find_one({"_id": job["_id"]})
            if stored and stored["status"] in {"completed", "failed"}:
                break
            time.sleep(0.01)

    assert stored["status"] == "completed"
    assert stored["claim_token"] is None
    assert stored["summary"]["packet_count"] == 1


def test_startup_recovery_dispatch_uses_fixed_worker_count(recovery_store, monkeypatch, tmp_path):
    from app.main import app

    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    monkeypatch.setenv("UPLOAD_DIR", str(upload_dir))
    get_settings.cache_clear()
    jobs = [
        create_analysis_job("user", f"{index}.pcap", 1, upload_dir / f"{index}.pcap")
        for index in range(5)
    ]
    lock = threading.Lock()
    active = 0
    maximum_active = 0
    processed = 0
    entered = threading.Event()
    release = threading.Event()

    def process_claimed(job, *, cancel_event=None):
        nonlocal active, maximum_active, processed
        with lock:
            active += 1
            maximum_active = max(maximum_active, active)
            if active >= main_module.RECOVERY_WORKER_COUNT:
                entered.set()
        assert release.wait(3)
        mark_job_completed(job["_id"], job["claim_token"], {"packet_count": 0})
        with lock:
            active -= 1
            processed += 1

    monkeypatch.setattr(main_module, "process_claimed_analysis_job", process_claimed)
    with TestClient(app):
        assert entered.wait(3)
        assert maximum_active == main_module.RECOVERY_WORKER_COUNT
        release.set()
        deadline = time.monotonic() + 5
        while processed < len(jobs) and time.monotonic() < deadline:
            time.sleep(0.01)

    assert processed == len(jobs)
    assert maximum_active <= main_module.RECOVERY_WORKER_COUNT


def test_shutdown_cancels_active_recovery_processing_and_leaves_job_recoverable(
    recovery_store, monkeypatch, tmp_path
):
    from concurrent.futures import ThreadPoolExecutor
    from app.ingestion.processor import wait_for_active_heartbeats

    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    monkeypatch.setenv("UPLOAD_DIR", str(upload_dir))
    get_settings.cache_clear()
    staged = upload_dir / "shutdown.pcap"
    staged.write_bytes(b"test capture")
    job = create_analysis_job("user", "shutdown.pcap", staged.stat().st_size, staged)
    parsing_started = threading.Event()
    observed_shutdown = threading.Event()
    database_close_requested = threading.Event()

    class InterruptibleAdapter:
        def validate(self, _path):
            return None

        def iter_records(self, _path):
            parsing_started.set()
            yield {"protocol": "tcp"}
            assert observed_shutdown.wait(2)
            yield {"protocol": "tcp"}

        def metadata(self, _path):
            return {"source_format": "pcap"}

    monkeypatch.setattr(processor_module, "get_source_adapter", lambda _source: InterruptibleAdapter())
    monkeypatch.setattr(processor_module, "LEASE_HEARTBEAT_INTERVAL_SECONDS", 0.02)
    monkeypatch.setattr(main_module, "close_client", database_close_requested.set)
    original_run = main_module._run_recovery_worker

    def observe_shutdown(stop_event):
        # The same event is passed to active processing; the adapter observes it
        # while paused between records, then processor cancellation exits cleanly.
        observer = threading.Thread(target=lambda: (stop_event.wait(), observed_shutdown.set()), daemon=True)
        observer.start()
        original_run(stop_event)

    monkeypatch.setattr(main_module, "_run_recovery_worker", observe_shutdown)
    stop_event = threading.Event()
    executor = ThreadPoolExecutor(max_workers=1)
    worker = executor.submit(main_module._run_recovery_worker, stop_event)
    assert parsing_started.wait(2)

    stopped_in_grace = main_module._shutdown_recovery_workers(stop_event, [worker], executor, 2)

    assert stopped_in_grace is True
    assert database_close_requested.is_set()
    assert wait_for_active_heartbeats(0.5)
    stored = get_database()["analysis_jobs"].find_one({"_id": job["_id"]})
    assert stored["status"] == "running"
    assert stored["summary"] is None
    assert stored["claim_token"]

    get_database()["analysis_jobs"].update_one(
        {"_id": job["_id"]},
        {"$set": {"lease_expires_at": now_utc() - timedelta(seconds=1)}},
    )
    reclaimed = claim_job(job["_id"])
    assert reclaimed is not None
    assert reclaimed["claim_token"] != stored["claim_token"]


def test_shutdown_grace_timeout_defers_database_close_until_workers_exit(recovery_store, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from app.ingestion.processor import LeaseHeartbeat

    worker_entered = threading.Event()
    release_worker = threading.Event()
    heartbeat_entered = threading.Event()
    release_heartbeat = threading.Event()
    database_closed = threading.Event()
    stop_event = threading.Event()
    executor = ThreadPoolExecutor(max_workers=1)

    def uncooperative_worker():
        worker_entered.set()
        assert release_worker.wait(3)

    monkeypatch.setattr(main_module, "close_client", database_closed.set)
    worker = executor.submit(uncooperative_worker)
    assert worker_entered.wait(2)

    heartbeat = LeaseHeartbeat("shutdown-job", "shutdown-token", stop_event)
    heartbeat.interval = 0.01

    def blocked_renewal():
        heartbeat_entered.set()
        assert release_heartbeat.wait(3)
        return True

    monkeypatch.setattr(heartbeat, "renew", blocked_renewal)
    heartbeat.start()
    assert heartbeat_entered.wait(2)

    started = time.monotonic()
    stopped_in_grace = main_module._shutdown_recovery_workers(stop_event, [worker], executor, 0.05)
    elapsed = time.monotonic() - started

    assert stopped_in_grace is False
    assert elapsed < 1
    assert stop_event.is_set()
    assert not database_closed.is_set()

    release_worker.set()
    assert worker.result(timeout=2) is None
    assert not database_closed.wait(0.05)
    release_heartbeat.set()
    assert heartbeat.stop_and_wait(timeout=2)
    assert database_closed.wait(2)


def test_foreground_shutdown_cancels_processing_and_waits_for_heartbeat(
    recovery_store, monkeypatch, tmp_path
):
    from concurrent.futures import ThreadPoolExecutor
    from app.ingestion.processor import run_foreground_analysis_job, wait_for_active_heartbeats
    from app.task_coordinator import AnalysisTaskCoordinator

    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    monkeypatch.setenv("UPLOAD_DIR", str(upload_dir))
    get_settings.cache_clear()
    staged = upload_dir / "foreground.pcap"
    staged.write_bytes(b"interruptible test capture")
    job = create_analysis_job("user", "foreground.pcap", staged.stat().st_size, staged)
    coordinator = AnalysisTaskCoordinator()
    registration = coordinator.register()
    assert registration is not None
    parsing_started = threading.Event()
    close_called = threading.Event()

    class InterruptibleAdapter:
        def validate(self, _path):
            return None

        def iter_records(self, _path):
            parsing_started.set()
            yield {"protocol": "tcp"}
            assert registration.cancel_event.wait(2)
            yield {"protocol": "tcp"}

        def metadata(self, _path):
            return {"source_format": "pcap"}

    monkeypatch.setattr(processor_module, "get_source_adapter", lambda _source: InterruptibleAdapter())
    monkeypatch.setattr(processor_module, "LEASE_HEARTBEAT_INTERVAL_SECONDS", 0.02)

    def assert_shutdown_idle(current_coordinator):
        assert current_coordinator.wait_until_idle(0)

    def assert_heartbeats_stopped():
        assert wait_for_active_heartbeats(0)

    def close_database_after_workers():
        assert_shutdown_idle(coordinator)
        assert_heartbeats_stopped()
        close_called.set()

    monkeypatch.setattr(main_module, "close_client", close_database_after_workers)

    foreground_executor = ThreadPoolExecutor(max_workers=2)
    recovery_executor = ThreadPoolExecutor(max_workers=1)
    try:
        task_future = foreground_executor.submit(
            run_foreground_analysis_job, job, coordinator, registration
        )
        assert parsing_started.wait(2)
        stopped_in_grace = main_module._shutdown_application_work(
            coordinator, threading.Event(), [], recovery_executor, 2
        )
        assert stopped_in_grace is True
        assert task_future.result(timeout=1)["status"] == "running"
        assert close_called.is_set()
        assert wait_for_active_heartbeats(0.5)
        stored = get_database()["analysis_jobs"].find_one({"_id": job["_id"]})
        assert stored["status"] == "running"
        assert stored["summary"] is None
        assert stored["claim_token"]

        get_database()["analysis_jobs"].update_one(
            {"_id": job["_id"]},
            {"$set": {"lease_expires_at": now_utc() - timedelta(seconds=1)}},
        )
        reclaimed = claim_job(job["_id"])
        assert reclaimed is not None
        assert reclaimed["claim_token"] != stored["claim_token"]
    finally:
        foreground_executor.shutdown(wait=True, cancel_futures=True)


def test_foreground_completion_start_is_serialized_with_shutdown(
    recovery_store, monkeypatch, tmp_path
):
    from concurrent.futures import ThreadPoolExecutor
    from app.ingestion.processor import run_foreground_analysis_job
    from app.task_coordinator import AnalysisTaskCoordinator

    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    monkeypatch.setenv("UPLOAD_DIR", str(upload_dir))
    get_settings.cache_clear()
    staged = upload_dir / "completing.pcap"
    staged.write_bytes(b"completion race test capture")
    job = create_analysis_job("user", "completing.pcap", staged.stat().st_size, staged)
    coordinator = AnalysisTaskCoordinator()
    registration = coordinator.register()
    assert registration is not None
    completion_entered = threading.Event()
    permit_completion = threading.Event()
    shutdown_closed_database = threading.Event()
    original_complete = processor_module.mark_job_completed

    class Adapter:
        def validate(self, _path):
            return None

        def iter_records(self, _path):
            yield {"protocol": "tcp"}

        def metadata(self, _path):
            return {"source_format": "pcap"}

    monkeypatch.setattr(processor_module, "get_source_adapter", lambda _source: Adapter())
    monkeypatch.setattr(processor_module, "analyze_records", lambda _records: (
        {"packet_count": 1, "flow_count": 0, "protocol_counts": {"tcp": 1}}, []
    ))
    monkeypatch.setattr(processor_module, "enrich_findings", lambda items, *_args: (items, {"status": "skipped"}))

    def delayed_completion(*args):
        completion_entered.set()
        assert permit_completion.wait(2)
        return original_complete(*args)

    monkeypatch.setattr(processor_module, "mark_job_completed", delayed_completion)
    monkeypatch.setattr(main_module, "close_client", shutdown_closed_database.set)
    foreground_executor = ThreadPoolExecutor(max_workers=2)
    recovery_executor = ThreadPoolExecutor(max_workers=1)
    try:
        task_future = foreground_executor.submit(
            run_foreground_analysis_job, job, coordinator, registration
        )
        assert completion_entered.wait(2)
        shutdown_future = foreground_executor.submit(
            main_module._shutdown_application_work,
            coordinator,
            threading.Event(),
            [],
            recovery_executor,
            2,
        )
        assert registration.cancel_event.wait(1)
        assert not shutdown_closed_database.is_set()
        permit_completion.set()
        assert task_future.result(timeout=2)["status"] == "completed"
        assert shutdown_future.result(timeout=2) is True
        assert shutdown_closed_database.is_set()
        stored = get_database()["analysis_jobs"].find_one({"_id": job["_id"]})
        assert stored["status"] == "completed"
    finally:
        permit_completion.set()
        foreground_executor.shutdown(wait=True, cancel_futures=True)


def test_foreground_registration_is_rejected_after_shutdown():
    from app.task_coordinator import AnalysisTaskCoordinator

    coordinator = AnalysisTaskCoordinator()
    task = coordinator.register()
    assert task is not None
    coordinator.request_shutdown()
    assert task.cancel_event.is_set()
    assert coordinator.register() is None
    coordinator.finish(task)
    assert coordinator.wait_until_idle(0)


def test_upload_route_registers_analysis_with_application_coordinator(
    recovery_store, monkeypatch, tmp_path
):
    from io import BytesIO
    from types import SimpleNamespace
    from fastapi import BackgroundTasks, UploadFile
    from scapy.all import IP
    from app.api.analyses import submit_pcap_analysis
    from app.task_coordinator import AnalysisTaskCoordinator

    monkeypatch.setenv("UPLOAD_DIR", str(tmp_path / "uploads"))
    get_settings.cache_clear()
    capture = tmp_path / "route-capture.pcap"
    wrpcap(
        str(capture),
        [Ether() / IP(src="192.0.2.2", dst="192.0.2.3")],
    )
    coordinator = AnalysisTaskCoordinator()
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(analysis_task_coordinator=coordinator)
        )
    )
    background = BackgroundTasks()
    job = submit_pcap_analysis(
        background,
        UploadFile(file=BytesIO(capture.read_bytes()), filename="route.pcap"),
        {"_id": "foreground-user", "role": "normal_user"},
        request,
    )

    assert job["status"] == "queued"
    assert len(background.tasks) == 1
    assert not coordinator.wait_until_idle(0)
    task = background.tasks[0].args[2]
    coordinator.request_shutdown()
    assert task.cancel_event.is_set()
    background.tasks[0].func(*background.tasks[0].args, **background.tasks[0].kwargs)
    assert coordinator.wait_until_idle(0)
    stored = get_database()["analysis_jobs"].find_one({"filename": "route.pcap"})
    assert stored["status"] == "queued"


def test_lease_heartbeat_stops_renewing_after_cancellation(recovery_store, monkeypatch, tmp_path):
    from app.ingestion.processor import LeaseHeartbeat, wait_for_active_heartbeats

    job = create_analysis_job("user", "heartbeat.pcap", 1, tmp_path / "heartbeat.pcap")
    claimed = claim_job(job["_id"])
    cancel_event = threading.Event()
    renewals = []
    renewed = threading.Event()

    def renew(_job_id, _claim_token):
        renewals.append(True)
        renewed.set()
        return True

    monkeypatch.setattr(processor_module, "renew_job_lease", renew)
    heartbeat = LeaseHeartbeat(claimed["_id"], claimed["claim_token"], cancel_event)
    heartbeat.interval = 0.02
    heartbeat.start()
    assert renewed.wait(1)
    cancel_event.set()
    assert heartbeat.stop_and_wait(timeout=1)
    assert wait_for_active_heartbeats(1)
    count_after_stop = len(renewals)
    time.sleep(0.05)
    assert len(renewals) == count_after_stop


def test_mongo_client_uses_configured_socket_timeout(recovery_store, monkeypatch):
    monkeypatch.setenv("MONGODB_URI", "mongodb://mongo.example.invalid")
    monkeypatch.setenv("MONGODB_SOCKET_TIMEOUT_MS", "4321")
    monkeypatch.setenv("SHUTDOWN_GRACE_SECONDS", "7")
    get_settings.cache_clear()
    monkeypatch.setattr(database_module, "_client", None)
    captured = {}

    class MongoClientStub:
        def __init__(self, uri, **kwargs):
            captured["uri"] = uri
            captured.update(kwargs)

        def close(self):
            pass

    monkeypatch.setattr(database_module, "MongoClient", MongoClientStub)
    database_module.get_client()

    assert captured["socketTimeoutMS"] == 4321
    assert captured["serverSelectionTimeoutMS"] == 3000
    assert get_settings().shutdown_grace_seconds == 7
