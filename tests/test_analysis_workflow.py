from pathlib import Path
from tempfile import TemporaryDirectory

from scapy.all import Ether, IP, TCP, wrpcap
from scapy.utils import PcapNgWriter

from app.alerts import alerts_collection
from app.database import get_database
from app.jobs import create_analysis_job, get_job_by_id
from app.detection.engine import analyze_records
from app.roles import ADMINISTRATOR, NORMAL_USER
from app.users import create_user


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
    assert job["summary"]["packet_count"] == 10
    assert job["summary"]["flow_count"] == 10
    assert job["summary"]["alert_count"] == 1
    assert job["summary"]["findings"][0]["rule_id"] == "SIG-NET-001"
    alert = alerts_collection().find_one({"job_id": job["id"]})
    assert alert["severity"] == "high"
    assert alert["method"] == "signature"
    assert alert["status"] == "open"
    from app.config import get_settings
    assert list(Path(get_settings().upload_dir).glob("*.pcap")) == []


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
    assert any(event["action"] == "update_alert_status" for event in get_database()["audit_events"].find({}))


def test_processing_failure_marks_job_failed_and_health_remains_available(client, tmp_path):
    from app.ingestion.processor import process_analysis_job

    job = create_analysis_job("test-user", "missing.pcap", 20, tmp_path / "missing.pcap")
    result = process_analysis_job(job)
    stored = get_job_by_id(str(job["_id"]))
    assert result["status"] == "failed"
    assert result["error_code"] == "processing_failed"
    assert stored["status"] == "failed"
    assert client.get("/api/v1/health").status_code == 200
    assert client.get("/api/v1/health/database").status_code == 200
