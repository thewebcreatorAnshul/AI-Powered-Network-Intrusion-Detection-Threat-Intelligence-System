"""Password hashing and JWT access tokens."""

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from jwt.exceptions import InvalidTokenError

from app.config import get_settings

PBKDF2_ALGORITHM = "pbkdf2_sha256"
PBKDF2_ITERATIONS = 210_000
HASH_NAME = "sha256"
SALT_BYTES = 16
DK_LEN = 32
JWT_ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    salt = secrets.token_hex(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        HASH_NAME,
        password.encode("utf-8"),
        bytes.fromhex(salt),
        PBKDF2_ITERATIONS,
        dklen=DK_LEN,
    )
    return f"{PBKDF2_ALGORITHM}${PBKDF2_ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, iteration_text, salt, digest_hex = password_hash.split("$", 3)
        if algorithm != PBKDF2_ALGORITHM:
            return False
        iterations = int(iteration_text)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac(
            HASH_NAME,
            password.encode("utf-8"),
            bytes.fromhex(salt),
            iterations,
            dklen=len(expected),
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def create_access_token(subject: str) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.jwt_expire_minutes)).timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> str | None:
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[JWT_ALGORITHM],
        )
    except InvalidTokenError:
        return None
    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject:
        return None
    return subject
