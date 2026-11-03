"""Request and response models for authentication, users, and analysis jobs."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.roles import NORMAL_USER


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned.replace("_", "").isalnum():
            raise ValueError("Username may contain only letters, numbers, and underscores.")
        return cleaned.lower()


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        return value.strip().lower()


class CreateUserRequest(RegisterRequest):
    role: Literal["administrator", "normal_user"] = NORMAL_USER


class UpdateUserRequest(BaseModel):
    role: Literal["administrator", "normal_user"] | None = None
    active: bool | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    id: str
    username: str
    role: str
    active: bool
    created_at: datetime
    updated_at: datetime


class AnalysisJobResponse(BaseModel):
    id: str
    submitted_by: str
    source_type: str
    filename: str
    file_size: int
    status: Literal["queued", "running", "completed", "failed"]
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    summary: dict | None = None
    error_code: str | None = None
    error_message: str | None = None


class AlertStatusUpdate(BaseModel):
    status: Literal["open", "acknowledged", "resolved"]
