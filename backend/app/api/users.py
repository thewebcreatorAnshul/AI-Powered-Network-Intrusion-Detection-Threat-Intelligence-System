"""Administrator user-management routes and ownership-scoped user reads."""

from fastapi import APIRouter, Depends, status

from app.audit import record_audit_event
from app.deps import get_current_admin, get_current_user, require_self_or_admin
from app.errors import raise_api_error
from app.schemas import CreateUserRequest, UpdateUserRequest, UserResponse
from app.users import create_user, get_user_by_id, list_users, serialize_user, update_user

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=list[UserResponse])
def list_all_users(admin: dict = Depends(get_current_admin)) -> list[dict]:
    del admin
    return [serialize_user(user) for user in list_users()]


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def admin_create_user(payload: CreateUserRequest, admin: dict = Depends(get_current_admin)) -> dict:
    try:
        user = create_user(payload.username, payload.password, role=payload.role)
    except ValueError as exc:
        if str(exc) == "invalid_role":
            raise_api_error(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "validation_error",
                "Invalid request input.",
            )
        raise_api_error(
            status.HTTP_409_CONFLICT,
            "username_taken",
            "A user with this username already exists.",
        )
    record_audit_event(str(admin["_id"]), "create_user", "user", str(user["_id"]), "success")
    return serialize_user(user)


@router.get("/{user_id}", response_model=UserResponse)
def get_user(user_id: str, current_user: dict = Depends(get_current_user)) -> dict:
    require_self_or_admin(current_user, user_id)
    user = get_user_by_id(user_id)
    if user is None:
        raise_api_error(status.HTTP_404_NOT_FOUND, "not_found", "User not found.")
    return serialize_user(user)


@router.patch("/{user_id}", response_model=UserResponse)
def admin_update_user(
    user_id: str,
    payload: UpdateUserRequest,
    admin: dict = Depends(get_current_admin),
) -> dict:
    if payload.role is None and payload.active is None:
        raise_api_error(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "validation_error",
            "Invalid request input.",
        )
    user = update_user(user_id, {"role": payload.role, "active": payload.active})
    if user is None:
        raise_api_error(status.HTTP_404_NOT_FOUND, "not_found", "User not found.")
    action = "update_user"
    if payload.role is not None:
        action = "assign_role"
    elif payload.active is False:
        action = "disable_user"
    record_audit_event(str(admin["_id"]), action, "user", user_id, "success")
    return serialize_user(user)
