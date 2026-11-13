from pathlib import Path
from tempfile import TemporaryDirectory
from datetime import datetime, timedelta, timezone
import csv
import io

from scapy.all import Ether, IP, TCP, wrpcap
from scapy.utils import PcapNgWriter

from app.alerts import alerts_collection
from app.analysis_results import persist_analysis_findings
from app.database import get_database
from app.jobs import claim_job, create_analysis_job, get_job_by_id, mark_job_completed
from app.detection.engine import analyze_records
from app.roles import ADMINISTRATOR, NORMAL_USER
from app.users import create_user, get_user_by_username


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def token_for(client, username: str, password: str) -> str:
    response = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()["access_token"]


def syn_scan_capture() -> bytes:
    packets = [
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="198.51.100.10", dst="203.0.113.20") / TCP(sport=41000 + port, dport=port, flags="S")
        for port in range(20, 30)
    ]
    with TemporaryDirectory() as directory:
        capture = Path(directory) / "controlled.pcap"
        wrpcap(str(capture), packets)
        return capture.read_bytes()


def test_syn_scan_signature_is_explainable_and_thresholded():
    records = [
        {"timestamp": float(index), "length": 60, "src_ip": "198.51.100.10", "dst_ip": "203.0.113.20", "src_port": 41000 + index, "dst_port": 20 + index, "protocol": "tcp", "tcp_flags": "S"}
        for index in range(10)
    ]
    features, findings = analyze_records(records)
    assert features["packet_count"] == 10
    assert features["flow_count"] == 10
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SIG-NET-001"
    assert findings[0]["evidence"]["distinct_destination_ports"] == list(range(20, 30))
    _, below_threshold = analyze_records(records[:9])
    assert below_threshold == []
    flood_records = [
        {"timestamp": index / 120, "length": 60, "src_ip": "198.51.100.11", "dst_ip": "203.0.113.21", "src_port": 42000, "dst_port": 443, "protocol": "tcp", "tcp_flags": "S"}
        for index in range(100)
    ]
    _, flood_findings = analyze_records(flood_records)
    flood = next(item for item in flood_findings if item["rule_id"] == "SIG-NET-002")
    assert flood["severity"] == "high"
    assert flood["evidence"]["probe_count"] == 100


def test_syn_scan_rule_handles_many_repeated_ports_without_quadratic_work():
    from app.detection.rules import detect_syn_port_scan

    records = [
        {"timestamp": index / 1000, "src_ip": "192.0.2.10", "dst_ip": "192.0.2.20",
         "dst_port": 443, "protocol": "tcp", "tcp_flags": "S"}
        for index in range(10000)
    ]
    assert detect_syn_port_scan(records) == []


def test_local_indicator_context_is_attached_only_from_configured_data(tmp_path):
    import json
    from app.intelligence import enrich_findings

    findings = [{"evidence": {"source_ip": "198.51.100.10"}}]
    dataset = tmp_path / "indicators.json"
    dataset.write_text(json.dumps([{"indicator": "198.51.100.10", "type": "ip", "source": "authorized test list"}]), encoding="utf-8")
    enriched, summary = enrich_findings(findings, "local", str(dataset))
    assert summary == {"status": "completed", "indicator_matches": 1}
    assert enriched[0]["indicator_context"][0]["source"] == "authorized test list"


def test_runtime_configuration_rejects_weak_jwt_keys_and_unknown_intelligence_modes(monkeypatch):
    import pytest
    from app.config import Settings

    monkeypatch.setenv("JWT_SECRET", "too-short")
    with pytest.raises(RuntimeError, match="at least 32 characters"):
        Settings()
    monkeypatch.setenv("JWT_SECRET", "test-only-key-longer-than-thirty-two-characters")
    monkeypatch.setenv("THREAT_INTEL_MODE", "remote-without-authorization")
    with pytest.raises(RuntimeError, match="THREAT_INTEL_MODE"):
        Settings()
    monkeypatch.setenv("THREAT_INTEL_MODE", "offline")
    monkeypatch.setenv("ALLOWED_ORIGINS", "*")
    with pytest.raises(RuntimeError, match="explicit browser origins"):
        Settings()


def test_upload_accepts_pcapng(client):
    create_user("alice", "Password123")
    token = token_for(client, "alice", "Password123")
    with TemporaryDirectory() as directory:
        path = Path(directory) / "capture.pcapng"
        writer = PcapNgWriter(str(path))
        writer.write(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="192.0.2.10", dst="192.0.2.20") / TCP(sport=12345, dport=443, flags="S"))
        writer.close()
        body = path.read_bytes()
    response = client.post("/api/v1/analyses", headers=auth(token), files={"file": ("capture.pcapng", body, "application/x-pcapng")})
    assert response.status_code == 202
    job = client.get(f"/api/v1/analyses/{response.json()['id']}", headers=auth(token)).json()
    assert job["status"] == "completed"
    assert job["summary"]["source_format"] == "pcapng"


def test_analysis_packet_limit_fails_safely_and_cleans_up(client, monkeypatch):
    from app.config import get_settings

    monkeypatch.setenv("MAX_ANALYSIS_PACKETS", "5")
    get_settings.cache_clear()
    create_user("packet-limit-user", "Password123")
    token = token_for(client, "packet-limit-user", "Password123")
    response = client.post(
        "/api/v1/analyses",
        headers=auth(token),
        files={"file": ("controlled-sample.pcap", syn_scan_capture(), "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 202
    result = client.get(f"/api/v1/analyses/{response.json()['id']}", headers=auth(token)).json()
    assert result["status"] == "failed"
    assert result["error_code"] == "capture_processing_limit"
    from app.config import get_settings as current_settings
    assert list(Path(current_settings().upload_dir).glob("*.pcap")) == []


def test_upload_persists_completed_analysis_and_alert(client):
    create_user("alice", "Password123", role=NORMAL_USER)
    token = token_for(client, "alice", "Password123")
    response = client.post(
        "/api/v1/analyses",
        headers=auth(token),
        files={"file": ("controlled-sample.pcap", syn_scan_capture(), "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 202
    submitted = response.json()
    assert submitted["status"] == "queued"
    job = client.get(f"/api/v1/analyses/{submitted['id']}", headers=auth(token)).json()
    assert job["status"] == "completed"
    assert "claim_token" not in job
    assert "alert_outbox" not in job
    assert job["summary"]["packet_count"] == 10
    assert job["summary"]["flow_count"] == 10
    assert job["summary"]["alert_count"] == 1
    assert job["summary"]["findings"][0]["rule_id"] == "SIG-NET-001"
    alert = alerts_collection().find_one({"job_id": job["id"]})
    assert alert["severity"] == "high"
    assert alert["method"] == "signature"
    assert alert["status"] == "open"
    api_alert = client.get("/api/v1/alerts", headers=auth(token)).json()[0]
    assert "dedupe_key" not in api_alert
    assert "payload" not in api_alert
    from app.config import get_settings
    assert list(Path(get_settings().upload_dir).glob("*.pcap")) == []


def test_analysis_findings_pagination_and_large_csv_export(client, tmp_path):
    create_user("alice", "Password123", role=NORMAL_USER)
    create_user("bob", "Password123", role=NORMAL_USER)
    alice_token = token_for(client, "alice", "Password123")
    bob_token = token_for(client, "bob", "Password123")
    owner = get_database()["users"].find_one({"username": "alice"})
    unsafe_filename = '=HYPERLINK("x","click").pcap'
    job = create_analysis_job(str(owner["_id"]), unsafe_filename, 1, tmp_path / "capture.pcap")
    claimed = claim_job(job["_id"])
    findings = [
        {
            "rule_id": "SIG-PAGE-001",
            "rule_version": "1.0",
            "title": f'Finding "{index:03d}"',
            "description": "Paginated finding",
            "severity": "medium",
            "category": "test",
            "method": "signature",
            "detection_type": "signature",
            "evidence": {"sequence": index},
            "indicator_context": [],
        }
        for index in range(1225)
    ]
    persist_analysis_findings(job["_id"], claimed["claim_token"], findings)
    mark_job_completed(
        job["_id"], claimed["claim_token"],
        {"finding_count": len(findings), "findings_storage": "analysis_findings", "packet_count": len(findings)},
    )
    detail = client.get(f"/api/v1/analyses/{job['_id']}", headers=auth(alice_token))
    assert detail.status_code == 200
    first_page = detail.json()["summary"]
    assert len(first_page["findings"]) == 50
    assert first_page["findings_pagination"] == {"skip": 0, "limit": 50, "total": 1225, "has_more": True}
    second = client.get(
        f"/api/v1/analyses/{job['_id']}/findings?skip=50&limit=50",
        headers=auth(alice_token),
    )
    third = client.get(
        f"/api/v1/analyses/{job['_id']}/findings?skip=1200&limit=50",
        headers=auth(alice_token),
    )
    assert second.status_code == third.status_code == 200
    assert len(second.json()["items"]) == 50
    assert len(third.json()["items"]) == 25
    assert third.json()["has_more"] is False
    assert client.get(
        f"/api/v1/analyses/{job['_id']}/findings",
        headers=auth(bob_token),
    ).status_code == 403

    exported = client.get(f"/api/v1/analyses/{job['_id']}/export", headers=auth(alice_token))
    assert exported.status_code == 200
    rows = list(csv.reader(io.StringIO(exported.text)))
    assert rows[0][-1] == "findings"
    assert len(rows) == 2
    assert rows[1][1] == "'" + unsafe_filename
    assert rows[1][-1].count("SIG-PAGE-001:") == len(findings)
    assert 'Finding "000"' in rows[1][-1]
    assert 'Finding "1224"' in rows[1][-1]


def test_upload_rejects_invalid_types_empty_and_malformed_capture(client):
    assert client.get("/api/v1/analyses").status_code == 401
    create_user("alice", "Password123")
    token = token_for(client, "alice", "Password123")
    headers = auth(token)
    unsupported = client.post("/api/v1/analyses", headers=headers, files={"file": ("notes.txt", b"not a capture", "text/plain")})
    empty = client.post("/api/v1/analyses", headers=headers, files={"file": ("empty.pcap", b"", "application/octet-stream")})
    malformed = client.post("/api/v1/analyses", headers=headers, files={"file": ("broken.pcap", b"\xd4\xc3\xb2\xa1broken", "application/octet-stream")})
    assert unsupported.status_code == 400
    assert unsupported.json()["error"]["code"] == "unsupported_capture"
    assert empty.status_code == 400
    assert malformed.status_code == 400


def test_oversized_upload_is_rejected(client, monkeypatch):
    monkeypatch.setenv("MAX_UPLOAD_MB", "1")
    from app.config import get_settings
    get_settings.cache_clear()
    create_user("alice", "Password123")
    token = token_for(client, "alice", "Password123")
    response = client.post(
        "/api/v1/analyses",
        headers=auth(token),
        files={"file": ("large.pcap", b"x" * (1024 * 1024 + 1), "application/octet-stream")},
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "upload_too_large"


def test_analysis_and_alert_ownership_admin_visibility_and_dashboard(client):
    create_user("alice", "Password123")
    create_user("bob", "Password123")
    create_user("admin", "AdminPass123", role=ADMINISTRATOR)
    alice = token_for(client, "alice", "Password123")
    bob = token_for(client, "bob", "Password123")
    admin = token_for(client, "admin", "AdminPass123")
    uploaded = client.post(
        "/api/v1/analyses",
        headers=auth(alice),
        files={"file": ("scan.pcap", syn_scan_capture(), "application/vnd.tcpdump.pcap")},
    ).json()
    alert = alerts_collection().find_one({"job_id": uploaded["id"]})
    assert client.get(f"/api/v1/analyses/{uploaded['id']}", headers=auth(bob)).status_code == 403
    assert client.get(f"/api/v1/alerts/{alert['_id']}", headers=auth(bob)).status_code == 403
    assert len(client.get("/api/v1/analyses", headers=auth(bob)).json()) == 0
    assert len(client.get("/api/v1/analyses", headers=auth(admin)).json()) == 1
    assert len(client.get("/api/v1/alerts", headers=auth(admin)).json()) == 1
    alice_dashboard = client.get("/api/v1/dashboard", headers=auth(alice)).json()
    assert alice_dashboard["analysis_count"] == 1
    assert alice_dashboard["alert_count"] == 1
    assert alice_dashboard["alerts_by_status"]["open"] == 1
    assert client.get("/api/v1/dashboard", headers=auth(bob)).json()["analysis_count"] == 0
    assert client.get("/api/v1/dashboard?severity=low", headers=auth(alice)).json()["alert_count"] == 0
    assert client.get("/api/v1/dashboard?since=2030-01-01T00:00:00Z", headers=auth(alice)).json()["analysis_count"] == 0
    assert client.get("/api/v1/alerts?severity=high&method=signature", headers=auth(alice)).json()
    assert client.get("/api/v1/alerts?severity=not-a-severity", headers=auth(alice)).status_code == 422
    assert client.get("/api/v1/analyses?skip=-1", headers=auth(alice)).status_code == 422
    assert client.get(f"/api/v1/analyses/{uploaded['id']}/export", headers=auth(bob)).status_code == 403
    assert client.get(f"/api/v1/analyses/{uploaded['id']}/export", headers=auth(alice)).headers["content-type"].startswith("text/csv")
    updated = client.patch(f"/api/v1/alerts/{alert['_id']}", headers=auth(admin), json={"status": "acknowledged"})
    assert updated.status_code == 200
    assert updated.json()["status"] == "acknowledged"
    event = next(event for event in get_database()["audit_events"].find({}) if event["action"] == "update_alert_status")
    assert event["actor_id"] == str(get_user_by_username("admin")["_id"])
    assert event["target_id"] == str(alert["_id"])
    assert event["safe_metadata"]["previous_status"] == "open"
    assert event["safe_metadata"]["new_status"] == "acknowledged"
    assert event["occurred_at"] is not None


def test_alert_status_transitions_are_owner_scoped_audited_and_metadata_safe(client):
    create_user("status-owner", "Password123")
    create_user("status-other", "Password123")
    create_user("status-admin", "AdminPass123", role=ADMINISTRATOR)
    owner_token = token_for(client, "status-owner", "Password123")
    other_token = token_for(client, "status-other", "Password123")
    admin_token = token_for(client, "status-admin", "AdminPass123")
    owner_id = str(get_user_by_username("status-owner")["_id"])

    uploaded = client.post(
        "/api/v1/analyses",
        headers=auth(owner_token),
        files={"file": ("status-scan.pcap", syn_scan_capture(), "application/vnd.tcpdump.pcap")},
    ).json()
    alert = alerts_collection().find_one({"job_id": uploaded["id"]})
    alert_id = str(alert["_id"])
    original = {key: alert[key] for key in ("submitted_by", "severity", "evidence", "rule_id", "detection_type")}

    acknowledged = client.patch(f"/api/v1/alerts/{alert_id}", headers=auth(owner_token), json={"status": "acknowledged"})
    assert acknowledged.status_code == 200
    assert acknowledged.json()["status"] == "acknowledged"
    assert "status_updated_by" not in acknowledged.json()
    stored = alerts_collection().find_one({"_id": alert["_id"]})
    assert stored["status_updated_by"] == owner_id
    assert stored["status_updated_at"] is not None
    assert stored["updated_at"] == stored["status_updated_at"]
    assert {key: stored[key] for key in original} == original

    assert client.patch(f"/api/v1/alerts/{alert_id}", headers=auth(owner_token), json={"status": "open"}).status_code == 409
    assert client.patch(f"/api/v1/alerts/{alert_id}", headers=auth(owner_token), json={"status": "dismissed"}).status_code == 422
    assert client.patch(
        f"/api/v1/alerts/{alert_id}",
        headers=auth(owner_token),
        json={"status": "resolved", "severity": "low", "submitted_by": "someone-else"},
    ).status_code == 422
    assert client.patch(f"/api/v1/alerts/{alert_id}", headers=auth(other_token), json={"status": "resolved"}).status_code == 403

    resolved = client.patch(f"/api/v1/alerts/{alert_id}", headers=auth(owner_token), json={"status": "resolved"})
    assert resolved.status_code == 200
    reopened = client.patch(f"/api/v1/alerts/{alert_id}", headers=auth(admin_token), json={"status": "open"})
    assert reopened.status_code == 200
    assert reopened.json()["status"] == "open"

    events = [event for event in get_database()["audit_events"].find({"target_id": alert_id}) if event["action"] == "update_alert_status"]
    assert len(events) == 3
    assert [(event["safe_metadata"]["previous_status"], event["safe_metadata"]["new_status"]) for event in events] == [
        ("open", "acknowledged"), ("acknowledged", "resolved"), ("resolved", "open"),
    ]
    assert [event["actor_id"] for event in events] == [owner_id, owner_id, str(get_user_by_username("status-admin")["_id"])]


def test_concurrent_alert_status_updates_cannot_apply_the_same_transition_twice(client):
    from concurrent.futures import ThreadPoolExecutor
    from bson import ObjectId
    from app.alerts import update_alert_status

    alert_id = alerts_collection().insert_one({
        "submitted_by": "transition-owner",
        "status": "open",
        "severity": "high",
        "evidence": {"source_ip": "192.0.2.10"},
    }).inserted_id

    def acknowledge(actor):
        return update_alert_status(
            str(alert_id), "acknowledged", actor_id=actor, owner_id="transition-owner",
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(acknowledge, ("actor-a", "actor-b")))
    assert sum(result is not None for result in results) == 1
    stored = alerts_collection().find_one({"_id": ObjectId(str(alert_id))})
    assert stored["status"] == "acknowledged"


def test_database_pagination_filtering_sorting_and_dashboard_aggregations(client, tmp_path):
    from app.jobs import jobs_collection
    from app.token_revocation import token_revocations_collection

    alice = create_user("page-alice", "Password123")
    bob = create_user("page-bob", "Password123")
    admin = create_user("page-admin", "AdminPass123", role=ADMINISTRATOR)
    alice_token = token_for(client, "page-alice", "Password123")
    admin_token = token_for(client, "page-admin", "AdminPass123")
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)

    jobs = []
    for owner, name, state, offset in [
        (alice, "Alpha-scan-old.pcap", "failed", 1),
        (alice, "Alpha-scan-new.pcap", "failed", 2),
        (alice, "Alpha-complete.pcap", "completed", 3),
        (bob, "Alpha-other-user.pcap", "failed", 4),
    ]:
        job = create_analysis_job(str(owner["_id"]), name, 10, tmp_path / name)
        jobs_collection().update_one(
            {"_id": job["_id"]},
            {"$set": {"status": state, "created_at": base + timedelta(minutes=offset)}},
        )
        jobs.append(job)

    job_page_one = client.get(
        "/api/v1/analyses?status=failed&q=ALPHA-scan&skip=0&limit=1",
        headers=auth(alice_token),
    )
    job_page_two = client.get(
        "/api/v1/analyses?status=failed&q=ALPHA-scan&skip=1&limit=1",
        headers=auth(alice_token),
    )
    job_empty = client.get(
        "/api/v1/analyses?status=failed&q=ALPHA-scan&skip=2&limit=1",
        headers=auth(alice_token),
    )
    assert [item["filename"] for item in job_page_one.json()] == ["Alpha-scan-new.pcap"]
    assert [item["filename"] for item in job_page_two.json()] == ["Alpha-scan-old.pcap"]
    assert job_empty.json() == []

    alerts = get_database()["alerts"]
    for owner, title, category, severity, method, state, offset in [
        (alice, "scan-old", "recon", "high", "signature", "open", 1),
        (alice, "scan-new", "recon", "high", "signature", "resolved", 2),
        (alice, "other", "benign", "low", "model", "open", 3),
        (bob, "scan-private", "recon", "high", "signature", "open", 4),
    ]:
        alerts.insert_one({
            "submitted_by": str(owner["_id"]),
            "title": title,
            "category": category,
            "severity": severity,
            "method": method,
            "detection_type": method,
            "status": state,
            "occurred_at": base + timedelta(minutes=offset),
            "job_id": "controlled",
            "description": "controlled test alert",
            "evidence": {},
            "indicator_context": [],
        })
    alert_page_one = client.get(
        "/api/v1/alerts?severity=high&method=signature&q=SCAN&skip=0&limit=1",
        headers=auth(alice_token),
    )
    alert_page_two = client.get(
        "/api/v1/alerts?severity=high&method=signature&q=SCAN&skip=1&limit=1",
        headers=auth(alice_token),
    )
    alert_empty = client.get(
        "/api/v1/alerts?severity=high&method=signature&q=SCAN&skip=2&limit=1",
        headers=auth(alice_token),
    )
    assert [item["title"] for item in alert_page_one.json()] == ["scan-new"]
    assert [item["title"] for item in alert_page_two.json()] == ["scan-old"]
    assert alert_empty.json() == []

    alice_dashboard = client.get("/api/v1/dashboard", headers=auth(alice_token)).json()
    assert alice_dashboard["analysis_count"] == 3
    assert alice_dashboard["jobs_by_status"] == {
        "queued": 0, "running": 0, "completed": 1, "failed": 2,
    }
    assert alice_dashboard["alert_count"] == 3
    assert alice_dashboard["alerts_by_severity"] == {"high": 2, "low": 1}
    assert alice_dashboard["alerts_by_method"] == {"signature": 2, "model": 1}
    assert alice_dashboard["alerts_by_status"] == {"open": 2, "resolved": 1}
    admin_dashboard = client.get("/api/v1/dashboard", headers=auth(admin_token)).json()
    assert admin_dashboard["analysis_count"] == 4
    assert admin_dashboard["alert_count"] == 4
    assert admin_dashboard["jobs_by_status"]["failed"] == 3
    assert admin_dashboard["alerts_by_status"]["open"] == 3
    empty_dashboard = client.get(
        "/api/v1/dashboard?since=2030-01-01T00:00:00Z", headers=auth(alice_token)
    ).json()
    assert empty_dashboard["analysis_count"] == 0
    assert empty_dashboard["alert_count"] == 0
    assert empty_dashboard["jobs_by_status"] == {
        "queued": 0, "running": 0, "completed": 0, "failed": 0,
    }
    job_indexes = jobs_collection().index_information()
    alert_indexes = alerts.index_information()
    assert "jobs_owner_status_created_page" in job_indexes
    assert "jobs_status_created_page" in job_indexes
    assert "alerts_owner_occurred_page" in alert_indexes
    assert "alerts_severity_occurred_page" in alert_indexes
    assert token_revocations_collection().index_information()["expired_token_revocations"]["expireAfterSeconds"] == 0
def test_processing_failure_marks_job_failed_and_health_remains_available(client, tmp_path):
    from app.ingestion.processor import process_analysis_job

    job = create_analysis_job("test-user", "missing.pcap", 20, tmp_path / "missing.pcap")
    result = process_analysis_job(job)
    stored = get_job_by_id(str(job["_id"]))
    assert result["status"] == "failed"
    assert result["error_code"] == "missing_capture"
    assert stored["status"] == "failed"
    assert client.get("/api/v1/health").status_code == 200
    assert client.get("/api/v1/health/database").status_code == 200


def test_failed_database_index_initialization_blocks_analysis_until_recovered(monkeypatch, tmp_path):
    from io import BytesIO

    from fastapi import BackgroundTasks, UploadFile
    from pymongo.errors import PyMongoError
    import pytest

    import app.alerts as alerts_module
    import app.analysis_results as results_module
    import app.database as database_module
    import app.main as main_module
    from app.database import required_indexes_ready
    from app.config import get_settings
    from app.api.analyses import submit_pcap_analysis
    from app.api.health import get_database_health
    from app.errors import APIError
    from app.jobs import get_job_by_id
    from app.ingestion.processor import process_analysis_job
    from tests.fake_mongo import Client as FakeMongoClient
    from scapy.all import Ether, IP, TCP, wrpcap

    monkeypatch.setenv("UPLOAD_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("THREAT_INTEL_MODE", "offline")
    get_settings.cache_clear()
    monkeypatch.setattr(database_module, "_client", FakeMongoClient())
    capture_path = tmp_path / "readiness-capture.pcap"
    wrpcap(
        str(capture_path),
        [Ether() / IP(src="192.0.2.10", dst="192.0.2.20") / TCP(sport=12345, dport=443, flags="S")],
    )
    capture_bytes = capture_path.read_bytes()

    def fail_alert_indexes():
        raise PyMongoError("simulated index initialization failure")

    monkeypatch.setattr(main_module, "ensure_alert_indexes", fail_alert_indexes)
    try:
        settings = get_settings()
        assert main_module.initialize_database(settings) is False
        assert not required_indexes_ready()
        health = get_database_health()
        assert health.status_code == 503
        assert health.body and b"indexes_unavailable" in health.body

        with pytest.raises(APIError) as blocked:
            submit_pcap_analysis(
                BackgroundTasks(),
                UploadFile(file=BytesIO(capture_bytes), filename="capture.pcap"),
                {"_id": "readiness-user", "role": NORMAL_USER},
            )
        assert blocked.value.status_code == 503
        assert blocked.value.detail["code"] == "database_not_ready"
        assert get_database()["analysis_jobs"].find_one({"filename": "capture.pcap"}) is None

        queued = create_analysis_job("readiness-user", "queued.pcap", 10, tmp_path / "queued.pcap")
        assert process_analysis_job(queued)["status"] == "queued"
        assert get_job_by_id(str(queued["_id"]))["status"] == "queued"
        assert alerts_module.relay_next_pending_alert_intent() is False

        # Once index initialization succeeds, the same app can safely accept work.
        monkeypatch.setattr(main_module, "ensure_alert_indexes", alerts_module.ensure_alert_indexes)
        def fail_result_indexes():
            raise PyMongoError("simulated analysis result index initialization failure")

        monkeypatch.setattr(main_module, "ensure_analysis_result_indexes", fail_result_indexes)
        assert main_module.initialize_database(settings) is False
        assert not required_indexes_ready()
        monkeypatch.setattr(
            main_module,
            "ensure_analysis_result_indexes",
            results_module.ensure_analysis_result_indexes,
        )
        assert main_module.initialize_database(settings) is True
        assert required_indexes_ready()
        assert any(
            index[0] == ("job_id", "claim_token", "finding_index") and index[1]
            for index in results_module.analysis_findings_collection().unique_indexes
        )
        background = BackgroundTasks()
        accepted = submit_pcap_analysis(
            background,
            UploadFile(file=BytesIO(capture_bytes), filename="capture.pcap"),
            {"_id": "readiness-user", "role": NORMAL_USER},
        )
        assert accepted["status"] == "queued"
        assert len(background.tasks) == 1
        assert process_analysis_job(get_job_by_id(accepted["id"]))["status"] == "completed"
        assert get_database_health()["status"] == "ok"
    finally:
        get_settings.cache_clear()


def test_missing_mongodb_configuration_keeps_liveness_and_reports_not_ready(client, monkeypatch):
    from app.config import get_settings
    from app.database import required_indexes_ready
    from app.main import initialize_database

    monkeypatch.setenv("MONGODB_URI", "")
    monkeypatch.setenv("MONGODB_DATABASE", "")
    get_settings.cache_clear()
    assert initialize_database(get_settings()) is False
    assert not required_indexes_ready()
    assert client.get("/api/v1/health").status_code == 200
    database_health = client.get("/api/v1/health/database")
    assert database_health.status_code == 503
    assert database_health.json()["database"] == "not_configured"


def test_cors_preflight_allows_only_configured_origins_and_api_methods(client):
    from fastapi.middleware.cors import CORSMiddleware

    cors = next(item for item in client.app.user_middleware if item.cls is CORSMiddleware)
    allowed_origin = cors.kwargs["allow_origins"][0]
    allowed = client.options(
        "/api/v1/auth/login",
        headers={
            "Origin": allowed_origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization,content-type",
        },
    )
    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == allowed_origin
    denied = client.options(
        "/api/v1/auth/login",
        headers={"Origin": "https://not-configured.invalid", "Access-Control-Request-Method": "POST"},
    )
    assert denied.status_code == 400
    assert "access-control-allow-origin" not in denied.headers


def test_upload_body_limiter_rejects_declared_and_chunked_oversize_bodies():
    import asyncio
    from app.middleware import UploadBodyLimitMiddleware

    async def consume(scope, receive, send):
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                raise RuntimeError("request body exceeded test limit")
            if not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    async def exercise(headers, messages):
        middleware = UploadBodyLimitMiddleware(consume, path="/api/v1/analyses", max_body_bytes=3)
        response = []
        async def receive():
            return messages.pop(0)
        async def send(message):
            response.append(message)
        await middleware(
            {"type": "http", "method": "POST", "path": "/api/v1/analyses", "headers": headers},
            receive,
            send,
        )
        return response

    declared = asyncio.run(exercise(
        [(b"content-length", b"4")],
        [{"type": "http.request", "body": b"four", "more_body": False}],
    ))
    chunked = asyncio.run(exercise(
        [],
        [
            {"type": "http.request", "body": b"ab", "more_body": True},
            {"type": "http.request", "body": b"cd", "more_body": True},
        ],
    ))
    for response in (declared, chunked):
        assert response[0]["status"] == 413
        assert b'"code": "upload_too_large"' in response[1]["body"]


def test_alert_csv_export_is_filtered_and_owner_scoped(client):
    from bson import ObjectId

    create_user("alice", "Password123", role=NORMAL_USER)
    create_user("bob", "Password123", role=NORMAL_USER)
    create_user("admin", "Password123", role=ADMINISTRATOR)
    alice_token = token_for(client, "alice", "Password123")
    admin_token = token_for(client, "admin", "Password123")
    alice_id = str(get_user_by_username("alice")["_id"])
    bob_id = str(get_user_by_username("bob")["_id"])
    stamp = datetime.now(timezone.utc)
    alerts = alerts_collection()
    alerts.insert_one({"_id": ObjectId(), "job_id": "job-a", "submitted_by": alice_id, "occurred_at": stamp, "severity": "high", "category": "scan", "method": "signature", "detection_type": "signature", "rule_id": "SIG-1", "rule_version": "1", "title": " =HYPERLINK(\"x\",\"click\")", "description": "evidence A", "evidence": {"ports": [22]}, "status": "open"})
    alerts.insert_one({"_id": ObjectId(), "job_id": "job-b", "submitted_by": bob_id, "occurred_at": stamp, "severity": "high", "category": "scan", "method": "signature", "detection_type": "signature", "rule_id": "SIG-1", "rule_version": "1", "title": "Port scan other owner", "description": "evidence B", "evidence": {"ports": [23]}, "status": "open"})
    alerts.insert_one({"_id": ObjectId(), "job_id": "job-c", "submitted_by": alice_id, "occurred_at": stamp, "severity": "low", "category": "dns", "method": "signature", "detection_type": "signature", "rule_id": "SIG-2", "rule_version": "1", "title": "DNS event", "description": "evidence C", "evidence": {}, "status": "open"})

    own_export = client.get("/api/v1/alerts/export?severity=high", headers=auth(alice_token))
    admin_export = client.get("/api/v1/alerts/export?severity=high", headers=auth(admin_token))
    assert own_export.status_code == 200
    assert own_export.headers["content-type"].startswith("text/csv")
    own_rows = list(csv.DictReader(io.StringIO(own_export.text)))
    admin_rows = list(csv.DictReader(io.StringIO(admin_export.text)))
    assert [row["job_id"] for row in own_rows] == ["job-a"]
    assert own_rows[0]["title"].startswith("' =HYPERLINK(")
    assert {row["job_id"] for row in admin_rows} == {"job-a", "job-b"}
    assert '"ports":[22]' in own_rows[0]["evidence"]
