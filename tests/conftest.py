import os

os.environ["JWT_SECRET"] = "test-only-jwt-secret-long-enough-for-tests-123456"
os.environ["MONGODB_DATABASE"] = "intrusion_detection_test"
os.environ["JWT_EXPIRE_MINUTES"] = "60"
os.environ["ADMIN_USERNAME"] = "bootstrap_admin"
os.environ["ADMIN_PASSWORD"] = "BootstrapPass123"
os.environ["ADMIN_PASSWORD_RESET"] = "false"

import pytest
from starlette.testclient import TestClient

from app.config import get_settings
from app.database import close_client, get_database
from app.main import app
import app.database as database_module
from tests.fake_mongo import Client as FakeMongoClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("UPLOAD_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("THREAT_INTEL_MODE", "offline")
    monkeypatch.delenv("THREAT_INTEL_FILE", raising=False)
    get_settings.cache_clear()
    close_client()
    database_module._client = FakeMongoClient()
    with TestClient(app) as test_client:
        database = get_database()
        database["users"].delete_many({})
        database["analysis_jobs"].delete_many({})
        database["alerts"].delete_many({})
        database["audit_events"].delete_many({})
        upload_dir = get_settings().upload_dir
        if upload_dir.exists():
            for staged_file in upload_dir.iterdir():
                if staged_file.is_file():
                    staged_file.unlink(missing_ok=True)
        yield test_client
        database["users"].delete_many({})
        database["analysis_jobs"].delete_many({})
        database["alerts"].delete_many({})
        database["audit_events"].delete_many({})
    close_client()
    get_settings.cache_clear()
