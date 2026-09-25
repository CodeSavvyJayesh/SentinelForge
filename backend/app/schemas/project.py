"""Project request/response schemas.

``owner_id`` is never accepted from a client: ownership comes from the access
token. Accepting it would let anyone create or move projects for anyone.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.project import DEFAULT_BRANCH

NAME_MAX = 120
DESCRIPTION_MAX = 2000
BRANCH_MAX = 100
URL_MAX = 500


def _clean(value: str | None) -> str | None:
    """Trim, and turn an empty string into ``None`` so the column stays clean."""
    if value is None:
        return None
    trimmed = value.strip()
    return trimmed or None


class ProjectBase(BaseModel):
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)
    repository_url: str | None = Field(default=None, max_length=URL_MAX)
    default_branch: str = Field(default=DEFAULT_BRANCH, max_length=BRANCH_MAX)

    @field_validator("description", "repository_url", mode="before")
    @classmethod
    def _normalise_optional(cls, value: object) -> object:
        return _clean(value) if isinstance(value, str) else value

    @field_validator("repository_url")
    @classmethod
    def _validate_repository_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        # Phase 4 does the real ingestion; here we only refuse obvious nonsense
        # and schemes a browser or git client should never be handed.
        if not value.startswith(("http://", "https://", "git@")):
            raise ValueError("Repository URL must start with http://, https:// or git@")
        return value

    @field_validator("default_branch")
    @classmethod
    def _validate_branch(cls, value: str) -> str:
        branch = value.strip()
        if not branch:
            return DEFAULT_BRANCH
        if any(character in branch for character in " ~^:?*[\\") or branch.startswith("-"):
            raise ValueError("Branch name contains characters git does not allow")
        return branch


class ProjectCreate(ProjectBase):
    name: str = Field(min_length=1, max_length=NAME_MAX, examples=["SecureBank"])

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        name = value.strip()
        if not name:
            raise ValueError("Project name cannot be blank")
        return name


class ProjectUpdate(BaseModel):
    """Every field optional: a PATCH changes only what it mentions."""

    name: str | None = Field(default=None, min_length=1, max_length=NAME_MAX)
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)
    repository_url: str | None = Field(default=None, max_length=URL_MAX)
    default_branch: str | None = Field(default=None, max_length=BRANCH_MAX)

    _validate_url = field_validator("repository_url")(ProjectBase._validate_repository_url)

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        name = value.strip()
        if not name:
            raise ValueError("Project name cannot be blank")
        return name

    @field_validator("default_branch")
    @classmethod
    def _validate_branch(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return ProjectBase._validate_branch(value)


class ProjectRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    owner_id: int
    name: str
    description: str | None
    repository_url: str | None
    default_branch: str
    language: str | None
    created_at: datetime
    updated_at: datetime


class ProjectListResponse(BaseModel):
    items: list[ProjectRead]
    total: int
    limit: int
    offset: int
