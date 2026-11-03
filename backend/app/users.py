"""User persistence helpers."""

from datetime import datetime, timezone

from bson import ObjectId
from bson.errors import InvalidId
from pymongo.collection import Collection
from pymongo.errors import DuplicateKeyError

from app.database import get_database
from app.roles import ADMINISTRATOR, ALLOWED_ROLES, NORMAL_USER
from app.security import hash_password


def users_collection() -> Collection:
    return get_database()["users"]


def ensure_user_indexes() -> None:
    users_collection().create_index("username", unique=True)


def serialize_user(document: dict) -> dict:
    return {
        "id": str(document["_id"]),
        "username": document["username"],
        "role": document["role"],
        "active": document["active"],
        "created_at": document["created_at"],
        "updated_at": document["updated_at"],
    }


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def create_user(username: str, password: str, role: str = NORMAL_USER, active: bool = True) -> dict:
    if role not in ALLOWED_ROLES:
        raise ValueError("invalid_role")
    if get_user_by_username(username) is not None:
        raise ValueError("username_taken")
    timestamp = now_utc()
    document = {
        "username": username,
        "password_hash": hash_password(password),
        "role": role,
        "active": active,
        "created_at": timestamp,
        "updated_at": timestamp,
    }
    try:
        result = users_collection().insert_one(document)
    except DuplicateKeyError as exc:
        raise ValueError("username_taken") from exc
    document["_id"] = result.inserted_id
    return document


def get_user_by_username(username: str) -> dict | None:
    return users_collection().find_one({"username": username})


def get_user_by_id(user_id: str) -> dict | None:
    try:
        object_id = ObjectId(user_id)
    except (InvalidId, TypeError):
        return None
    return users_collection().find_one({"_id": object_id})


def list_users() -> list[dict]:
    return list(users_collection().find().sort("username", 1))


def update_user(user_id: str, updates: dict) -> dict | None:
    user = get_user_by_id(user_id)
    if user is None:
        return None
    changes = {key: value for key, value in updates.items() if value is not None}
    if not changes:
        return user
    changes["updated_at"] = now_utc()
    users_collection().update_one({"_id": user["_id"]}, {"$set": changes})
    return get_user_by_id(user_id)


def bootstrap_administrator(username: str, password: str) -> None:
    if not username or not password or len(password) < 8:
        return
    existing_admin = users_collection().find_one({"role": ADMINISTRATOR})
    if existing_admin is not None:
        return
    if get_user_by_username(username) is not None:
        return
    create_user(username, password, role=ADMINISTRATOR, active=True)


def reset_administrator_password(username: str, password: str) -> bool:
    if not username or not password or len(password) < 8:
        return False
    user = get_user_by_username(username.strip().lower())
    if (
        user is None
        or user.get("role") != ADMINISTRATOR
        or not user.get("active", False)
    ):
        return False
    result = users_collection().update_one(
        {
            "_id": user["_id"],
            "role": ADMINISTRATOR,
            "active": True,
        },
        {
            "$set": {
                "password_hash": hash_password(password),
                "updated_at": now_utc(),
            }
        },
    )
    return result.matched_count == 1


def apply_administrator_startup(username: str, password: str, *, reset_password: bool) -> None:
    bootstrap_administrator(username, password)
    if reset_password:
        reset_administrator_password(username, password)
