from app.config import get_settings
from app.roles import ADMINISTRATOR, NORMAL_USER
from app.security import verify_password
from app.users import (
    apply_administrator_startup,
    bootstrap_administrator,
    create_user,
    get_user_by_username,
    reset_administrator_password,
)


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def login_user(client, username: str, password: str = "Password123"):
    return client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password},
    )


def create_admin_token(client, username: str = "admin", password: str = "AdminPass123") -> str:
    create_user(username, password, role=ADMINISTRATOR)
    response = login_user(client, username, password)
    assert response.status_code == 200
    return response.json()["access_token"]


def create_normal_user(username: str, password: str = "Password123") -> dict:
    return create_user(username, password, role=NORMAL_USER)


def admin_create_user(client, admin_token: str, username: str, role: str = NORMAL_USER):
    return client.post(
        "/api/v1/users",
        headers=auth_header(admin_token),
        json={"username": username, "password": "Password123", "role": role},
    )


def test_public_registration_is_unavailable(client):
    response = client.post(
        "/api/v1/auth/register",
        json={"username": "alice", "password": "Password123"},
    )
    assert response.status_code == 404


def test_login_returns_access_token(client):
    create_normal_user("alice")
    response = login_user(client, "alice")
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]


def test_login_rejects_invalid_credentials(client):
    create_normal_user("alice")
    wrong_password = login_user(client, "alice", "WrongPass123")
    unknown_user = login_user(client, "missing", "Password123")
    assert wrong_password.status_code == 401
    assert unknown_user.status_code == 401
    assert wrong_password.json()["error"]["code"] == "invalid_credentials"
    assert unknown_user.json()["error"]["code"] == "invalid_credentials"
    assert wrong_password.json()["error"]["message"] == unknown_user.json()["error"]["message"]


def test_me_requires_authentication(client):
    unauthenticated = client.get("/api/v1/auth/me")
    assert unauthenticated.status_code == 401
    create_normal_user("alice")
    token = login_user(client, "alice").json()["access_token"]
    authenticated = client.get("/api/v1/auth/me", headers=auth_header(token))
    assert authenticated.status_code == 200
    assert authenticated.json()["username"] == "alice"
    assert "password" not in authenticated.json()
    assert "password_hash" not in authenticated.json()


def test_password_is_stored_as_salted_hash(client):
    del client
    create_normal_user("alice", "Password123")
    stored = get_user_by_username("alice")
    assert stored is not None
    assert stored["password_hash"] != "Password123"
    assert stored["password_hash"].startswith("pbkdf2_sha256$")


def test_unauthenticated_user_cannot_list_users(client):
    response = client.get("/api/v1/users")
    assert response.status_code == 401


def test_normal_user_cannot_access_admin_user_list(client):
    create_normal_user("alice")
    token = login_user(client, "alice").json()["access_token"]
    response = client.get("/api/v1/users", headers=auth_header(token))
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


def test_normal_user_cannot_create_users(client):
    create_normal_user("alice")
    token = login_user(client, "alice").json()["access_token"]
    response = client.post(
        "/api/v1/users",
        headers=auth_header(token),
        json={"username": "bob", "password": "Password123", "role": ADMINISTRATOR},
    )
    assert response.status_code == 403


def test_admin_can_list_and_create_users(client):
    admin_token = create_admin_token(client)
    created = admin_create_user(client, admin_token, "bob")
    assert created.status_code == 201
    body = created.json()
    assert body["username"] == "bob"
    assert body["role"] == NORMAL_USER
    assert "password" not in body
    assert "password_hash" not in body
    listed = client.get("/api/v1/users", headers=auth_header(admin_token))
    assert listed.status_code == 200
    usernames = {user["username"] for user in listed.json()}
    assert usernames == {"admin", "bob"}


def test_admin_create_rejects_duplicate_username(client):
    admin_token = create_admin_token(client)
    assert admin_create_user(client, admin_token, "bob").status_code == 201
    duplicate = admin_create_user(client, admin_token, "bob")
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "username_taken"


def test_normal_user_cannot_access_another_users_resource(client):
    first = create_normal_user("alice")
    second = create_normal_user("bob")
    alice_token = login_user(client, "alice").json()["access_token"]
    own = client.get(f"/api/v1/users/{first['_id']}", headers=auth_header(alice_token))
    other = client.get(f"/api/v1/users/{second['_id']}", headers=auth_header(alice_token))
    assert own.status_code == 200
    assert own.json()["username"] == "alice"
    assert other.status_code == 403
    assert other.json()["error"]["code"] == "forbidden"


def test_normal_user_cannot_change_roles_or_disable_users(client):
    alice = create_normal_user("alice")
    bob = create_normal_user("bob")
    alice_token = login_user(client, "alice").json()["access_token"]
    role_change = client.patch(
        f"/api/v1/users/{bob['_id']}",
        headers=auth_header(alice_token),
        json={"role": ADMINISTRATOR},
    )
    disable = client.patch(
        f"/api/v1/users/{alice['_id']}",
        headers=auth_header(alice_token),
        json={"active": False},
    )
    assert role_change.status_code == 403
    assert disable.status_code == 403


def test_admin_can_assign_role_and_disable_user(client):
    admin_token = create_admin_token(client)
    user = create_normal_user("alice")
    assigned = client.patch(
        f"/api/v1/users/{user['_id']}",
        headers=auth_header(admin_token),
        json={"role": ADMINISTRATOR},
    )
    assert assigned.status_code == 200
    assert assigned.json()["role"] == ADMINISTRATOR
    disabled = client.patch(
        f"/api/v1/users/{user['_id']}",
        headers=auth_header(admin_token),
        json={"active": False},
    )
    assert disabled.status_code == 200
    assert disabled.json()["active"] is False
    login_after_disable = login_user(client, "alice")
    assert login_after_disable.status_code == 401


def test_disabled_user_cannot_use_existing_token(client):
    admin_token = create_admin_token(client)
    user = create_normal_user("alice")
    token = login_user(client, "alice").json()["access_token"]
    disabled = client.patch(
        f"/api/v1/users/{user['_id']}",
        headers=auth_header(admin_token),
        json={"active": False},
    )
    assert disabled.status_code == 200
    me = client.get("/api/v1/auth/me", headers=auth_header(token))
    assert me.status_code == 401


def test_bootstrap_administrator_creates_only_the_first_admin(client):
    del client
    bootstrap_administrator("seedadmin", "SeedPass123")
    first = get_user_by_username("seedadmin")
    assert first is not None
    assert first["role"] == ADMINISTRATOR
    assert first["password_hash"] != "SeedPass123"
    bootstrap_administrator("anotheradmin", "SeedPass123")
    assert get_user_by_username("anotheradmin") is None


def test_admin_password_reset_updates_hash_and_preserves_other_users(client):
    old_password = "OldAdminPass123"
    new_password = "NewAdminPass123"
    admin = create_user("admin", old_password, role=ADMINISTRATOR)
    other = create_normal_user("alice", "AlicePass123")
    other_hash = other["password_hash"]

    assert login_user(client, "admin", old_password).status_code == 200
    assert login_user(client, "admin", new_password).status_code == 401

    stored_admin = get_user_by_username("admin")
    stored_other = get_user_by_username("alice")
    assert stored_admin is not None
    assert stored_other is not None
    admin_created_at = stored_admin["created_at"]
    admin_updated_at = stored_admin["updated_at"]
    other_created_at = stored_other["created_at"]
    other_updated_at = stored_other["updated_at"]

    reset = reset_administrator_password("admin", new_password)
    assert reset is True

    updated_admin = get_user_by_username("admin")
    unchanged_other = get_user_by_username("alice")
    assert updated_admin is not None
    assert unchanged_other is not None
    assert updated_admin["username"] == admin["username"]
    assert updated_admin["role"] == ADMINISTRATOR
    assert updated_admin["active"] is True
    assert updated_admin["created_at"] == admin_created_at
    assert updated_admin["updated_at"] != admin_updated_at
    assert updated_admin["password_hash"] != admin["password_hash"]
    assert updated_admin["password_hash"].startswith("pbkdf2_sha256$")
    assert verify_password(new_password, updated_admin["password_hash"])
    assert not verify_password(old_password, updated_admin["password_hash"])
    assert unchanged_other["_id"] == other["_id"]
    assert unchanged_other["username"] == "alice"
    assert unchanged_other["role"] == NORMAL_USER
    assert unchanged_other["password_hash"] == other_hash
    assert unchanged_other["created_at"] == other_created_at
    assert unchanged_other["updated_at"] == other_updated_at

    assert login_user(client, "admin", new_password).status_code == 200
    assert login_user(client, "admin", old_password).status_code == 401
    assert login_user(client, "alice", "AlicePass123").status_code == 200


def test_admin_password_reset_requires_opt_in_flag(client, monkeypatch):
    old_password = "OldAdminPass123"
    new_password = "NewAdminPass123"
    create_user("resetadmin", old_password, role=ADMINISTRATOR)
    create_normal_user("alice", "AlicePass123")

    monkeypatch.setenv("ADMIN_USERNAME", "resetadmin")
    monkeypatch.setenv("ADMIN_PASSWORD", new_password)
    monkeypatch.setenv("ADMIN_PASSWORD_RESET", "false")
    get_settings.cache_clear()
    settings = get_settings()
    apply_administrator_startup(
        settings.admin_username,
        settings.admin_password,
        reset_password=settings.admin_password_reset,
    )
    assert login_user(client, "resetadmin", old_password).status_code == 200
    assert login_user(client, "resetadmin", new_password).status_code == 401
    assert login_user(client, "alice", "AlicePass123").status_code == 200

    monkeypatch.setenv("ADMIN_PASSWORD_RESET", "true")
    get_settings.cache_clear()
    settings = get_settings()
    apply_administrator_startup(
        settings.admin_username,
        settings.admin_password,
        reset_password=settings.admin_password_reset,
    )
    updated_admin = get_user_by_username("resetadmin")
    unchanged_other = get_user_by_username("alice")
    assert updated_admin is not None
    assert verify_password(new_password, updated_admin["password_hash"])
    assert not verify_password(old_password, updated_admin["password_hash"])
    assert unchanged_other is not None
    assert login_user(client, "resetadmin", new_password).status_code == 200
    assert login_user(client, "resetadmin", old_password).status_code == 401
    assert login_user(client, "alice", "AlicePass123").status_code == 200


def test_admin_password_reset_skips_non_admin_and_inactive_users(client):
    del client
    alice = create_normal_user("alice")
    inactive = create_user("oldadmin", "OldAdminPass123", role=ADMINISTRATOR, active=False)
    assert reset_administrator_password("alice", "NewAdminPass123") is False
    assert reset_administrator_password("missing", "NewAdminPass123") is False
    assert reset_administrator_password("oldadmin", "NewAdminPass123") is False
    assert get_user_by_username("alice")["password_hash"] == alice["password_hash"]
    assert get_user_by_username("oldadmin")["password_hash"] == inactive["password_hash"]
