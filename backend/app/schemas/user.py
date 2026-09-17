"""User schemas returned by the API. Never expose password hashes."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models import UserRole


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    username: str
    role: UserRole
    is_active: bool
    created_at: datetime


class UserListResponse(BaseModel):
    items: list[UserRead]
    total: int
    limit: int
    offset: int
