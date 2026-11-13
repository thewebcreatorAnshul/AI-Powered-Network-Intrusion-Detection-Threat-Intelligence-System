"""FastAPI dependencies for authentication and authorization."""

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette import status

from app.audit import record_audit_event
from app.errors import raise_api_error
from app.roles import ADMINISTRATOR
from app.security import decode_access_token
from app.token_revocation import is_access_token_revoked
from app.users import get_user_by_id

bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> dict:
    if credentials is None or credentials.scheme.lower() != "bearer" or not credentials.credentials:
        raise_api_error(
            status.HTTP_401_UNAUTHORIZED,
            "unauthenticated",
            "Authentication is required.",
        )
    user_id = decode_access_token(credentials.credentials)
    if user_id is None or is_access_token_revoked(credentials.credentials):
        raise_api_error(
            status.HTTP_401_UNAUTHORIZED,
            "unauthenticated",
            "Authentication is required.",
        )
    user = get_user_by_id(user_id)
    if user is None or not user.get("active", False):
        raise_api_error(
            status.HTTP_401_UNAUTHORIZED,
            "unauthenticated",
            "Authentication is required.",
        )
    return user


def get_current_admin(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user.get("role") != ADMINISTRATOR:
        record_audit_event(
            str(current_user["_id"]),
            "forbidden_access",
            "user",
            str(current_user["_id"]),
            "failure",
        )
        raise_api_error(
            status.HTTP_403_FORBIDDEN,
            "forbidden",
            "You do not have permission to access this resource.",
        )
    return current_user


def require_self_or_admin(current_user: dict, target_user_id: str) -> None:
    if current_user.get("role") == ADMINISTRATOR:
        return
    if str(current_user["_id"]) != str(target_user_id):
        record_audit_event(
            str(current_user["_id"]),
            "forbidden_access",
            "user",
            target_user_id,
            "failure",
        )
        raise_api_error(
            status.HTTP_403_FORBIDDEN,
            "forbidden",
            "You do not have permission to access this resource.",
        )
