"""Repository request/response schemas.

``project_id`` comes from the URL and ``workspace_path`` is never returned:
the path on the server's disk is infrastructure, not something a client needs
(and telling an attacker where uploads land is free reconnaissance).
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.repository import RepositorySource, RepositoryStatus

URL_MAX = 500
BRANCH_MAX = 100


class RepositoryConnectRequest(BaseModel):
    """Connect a public Git URL. Deep validation (scheme, SSRF, argument
    injection) happens in ``app.ingestion.git_clone``; this is the shape check."""

    repository_url: str = Field(
        min_length=1, max_length=URL_MAX, examples=["https://github.com/pallets/flask"]
    )
    branch: str | None = Field(default=None, max_length=BRANCH_MAX, examples=["main"])

    @field_validator("repository_url", "branch")
    @classmethod
    def _trim(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip() or None


class RepositoryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    source: RepositorySource
    status: RepositoryStatus
    origin: str
    branch: str | None
    commit_hash: str | None
    file_count: int
    total_bytes: int
    primary_language: str | None
    language_breakdown: dict[str, int] | None
    error_message: str | None
    ingested_at: datetime | None
    created_at: datetime
    updated_at: datetime


class RepositoryListResponse(BaseModel):
    items: list[RepositoryRead]
    total: int
