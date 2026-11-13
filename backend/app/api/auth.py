"""Authentication routes: login, logout, and current user."""

from fastapi import APIRouter, Depends, Response, status
from fastapi.security import HTTPAuthorizationCredentials

from app.audit import record_audit_event
from app.deps import bearer_scheme, get_current_user
from app.errors import raise_api_error
from app.schemas import LoginRequest, TokenResponse, UserResponse
from app.security import create_access_token, verify_password
from app.token_revocation import revoke_access_token
from app.users import get_user_by_username, serialize_user

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest) -> dict:
    user = get_user_by_username(payload.username)
    if (
        user is None
        or not user.get("active", False)
        or not verify_password(payload.password, user.get("password_hash", ""))
    ):
        actor_id = str(user["_id"]) if user is not None else None
        record_audit_event(actor_id, "login", "user", actor_id, "failure")
        raise_api_error(
            status.HTTP_401_UNAUTHORIZED,
            "invalid_credentials",
            "Invalid username or password.",
        )
    token = create_access_token(str(user["_id"]))
    record_audit_event(str(user["_id"]), "login", "user", str(user["_id"]), "success")
    return {"access_token": token, "token_type": "bearer"}


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    current_user: dict = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> Response:
    revoke_access_token(credentials.credentials)
    record_audit_event(str(current_user["_id"]), "logout", "user", str(current_user["_id"]), "success")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=UserResponse)
def read_current_user(current_user: dict = Depends(get_current_user)) -> dict:
    return serialize_user(current_user)
