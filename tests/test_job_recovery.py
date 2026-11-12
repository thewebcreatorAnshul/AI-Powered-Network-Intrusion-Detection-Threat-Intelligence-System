from datetime import timedelta
import os
import threading
import time
from types import SimpleNamespace

import pytest
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
