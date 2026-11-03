"""MongoDB client lifecycle and connectivity checks."""

from pymongo import MongoClient
from pymongo.errors import PyMongoError

from app.config import Settings, get_settings

_client: MongoClient | None = None


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
        return {
            "status": "ok",
            "database": "connected",
        }
    except PyMongoError:
        return {
            "status": "unavailable",
            "database": "disconnected",
        }


def close_client() -> None:
    global _client
    if _client is not None:
        _client.close()
        _client = None
