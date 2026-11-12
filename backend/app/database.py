"""MongoDB client lifecycle and connectivity checks."""

from pymongo import MongoClient
from pymongo.errors import PyMongoError

from app.config import Settings, get_settings

_client: MongoClient | None = None
_required_indexes_ready = False


def set_required_indexes_ready(ready: bool) -> None:
    """Track whether startup verified every index required for processing."""
    global _required_indexes_ready
    _required_indexes_ready = ready


def required_indexes_ready() -> bool:
    return _required_indexes_ready


def get_client() -> MongoClient:
    global _client
    if _client is None:
        settings = get_settings()
        if not settings.mongodb_uri:
            raise RuntimeError("MongoDB is not configured.")
        _client = MongoClient(
            settings.mongodb_uri,
            serverSelectionTimeoutMS=3000,
            connectTimeoutMS=3000,
            socketTimeoutMS=settings.mongodb_socket_timeout_ms,
        )
    return _client


def get_database():
    settings = get_settings()
    if not settings.mongodb_database:
        raise RuntimeError("MongoDB is not configured.")
    return get_client()[settings.mongodb_database]


def check_database_connection(settings: Settings | None = None) -> dict:
    """Ping MongoDB and return a non-sensitive health summary."""
    settings = settings or get_settings()
    if not settings.mongodb_uri or not settings.mongodb_database:
        return {
            "status": "unavailable",
            "database": "not_configured",
        }

    try:
        client = get_client()
        client.admin.command("ping")
        database = client[settings.mongodb_database]
        database.command("ping")
    except PyMongoError:
        return {
            "status": "unavailable",
            "database": "disconnected",
        }

    if not required_indexes_ready():
        return {
            "status": "unavailable",
            "database": "indexes_unavailable",
        }
    return {
        "status": "ok",
        "database": "connected",
    }


def close_client() -> None:
    global _client
    if _client is not None:
        _client.close()
        _client = None
    set_required_indexes_ready(False)
