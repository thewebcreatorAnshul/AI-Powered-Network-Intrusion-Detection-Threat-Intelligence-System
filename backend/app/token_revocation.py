"""Hashed bearer-token revocation with expiry-based retention."""

from datetime import datetime, timezone
from hashlib import sha256

from app.database import get_database, required_indexes_ready
from app.security import decode_access_token_payload

TOKEN_REVOCATION_CLEANUP_BATCH_SIZE = 500


def token_revocations_collection():
    return get_database()["token_revocations"]


def ensure_token_revocation_indexes() -> None:
    token_revocations_collection().create_index(
        "expires_at",
        expireAfterSeconds=0,
        name="expired_token_revocations",
    )


def _fingerprint(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()


def is_access_token_revoked(token: str) -> bool:
    if not required_indexes_ready():
        # Fail closed if revocation readiness cannot be established.
        return True
    payload = decode_access_token_payload(token)
    if payload is None:
        return False
    expiration = datetime.fromtimestamp(payload["exp"], timezone.utc)
    if expiration <= datetime.now(timezone.utc):
        return False
    return token_revocations_collection().find_one({
        "_id": _fingerprint(token),
        "expires_at": {"$gt": datetime.now(timezone.utc)},
    }) is not None


def revoke_access_token(token: str) -> bool:
    if not required_indexes_ready():
        return False
    payload = decode_access_token_payload(token)
    if payload is None:
        return False
    expiration = datetime.fromtimestamp(payload["exp"], timezone.utc)
    if expiration <= datetime.now(timezone.utc):
        return False
    token_revocations_collection().update_one(
        {"_id": _fingerprint(token)},
        {"$setOnInsert": {
            "expires_at": expiration,
            "revoked_at": datetime.now(timezone.utc),
        }},
        upsert=True,
    )
    return True


def cleanup_expired_token_revocations(*, batch_size: int = TOKEN_REVOCATION_CLEANUP_BATCH_SIZE) -> int:
    """Remove at most batch_size expired entries; MongoDB TTL remains a backstop."""
    if not required_indexes_ready():
        return 0
    if batch_size < 1:
        raise ValueError("batch_size must be positive")
    expired = list(
        token_revocations_collection()
        .find({"expires_at": {"$lte": datetime.now(timezone.utc)}})
        .sort("expires_at", 1)
        .limit(batch_size)
    )
    removed = 0
    for record in expired:
        removed += token_revocations_collection().delete_one({"_id": record["_id"]}).deleted_count
    return removed
