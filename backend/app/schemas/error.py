"""Response schemas for the standard error envelope (used in OpenAPI docs)."""

from typing import Any

from pydantic import BaseModel, Field


class ErrorBody(BaseModel):
    code: str = Field(examples=["NOT_FOUND"])
    message: str = Field(examples=["Resource not found"])
    details: Any = None
    request_id: str | None = Field(default=None, examples=["9f1c2b7e4a6d4f0c8e2b1a3d5c7e9f10"])


class ErrorResponse(BaseModel):
    error: ErrorBody
