"""Request/response schemas for authentication."""

import re

from pydantic import BaseModel, Field, field_validator

from app.core.config import get_settings
from app.core.security import MAX_PASSWORD_BYTES
from app.schemas.user import UserRead

_settings = get_settings()

# Deliberately permissive but safe: one @, no spaces, a dot in the domain.
EMAIL_PATTERN = re.compile(r"^[^@\s]{1,64}@[^@\s.]+(\.[^@\s.]+)+$")
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")

PASSWORD_HELP = (
    f"At least {_settings.PASSWORD_MIN_LENGTH} characters. "
    "Use a passphrase; length matters more than symbols."
)


class RegisterRequest(BaseModel):
    email: str = Field(max_length=255, examples=["dev@example.com"])
    username: str = Field(min_length=3, max_length=100, examples=["dev"])
    password: str = Field(
        min_length=_settings.PASSWORD_MIN_LENGTH,
        max_length=MAX_PASSWORD_BYTES,
        description=PASSWORD_HELP,
    )

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str) -> str:
        value = value.strip().lower()
        if not EMAIL_PATTERN.match(value):
            raise ValueError("Enter a valid email address")
        return value

    @field_validator("username")
    @classmethod
    def _validate_username(cls, value: str) -> str:
        value = value.strip()
        if not USERNAME_PATTERN.match(value):
            raise ValueError("Username may contain letters, digits, dot, underscore and hyphen")
        return value

    @field_validator("password")
    @classmethod
    def _reject_blank_password(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Password cannot be blank")
        return value


class LoginRequest(BaseModel):
    identifier: str = Field(min_length=1, max_length=255, description="Email address or username")
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_BYTES)


class TokenResponse(BaseModel):
    """The access token lives in browser memory only; the refresh token is a cookie."""

    access_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth2 scheme name, not a secret
    expires_in: int = Field(description="Access token lifetime in seconds")
    user: UserRead
