"""Repository model: a codebase attached to a project.

A repository is either an uploaded archive or a cloned Git URL. The row records
what was ingested and where it landed, so a scan (Phase 6) can be reproduced:
the commit hash, the ingestion settings and the detected languages are all kept.
"""

from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import BigInteger, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.base import Base
from app.models.mixins import TimestampMixin


class RepositorySource(StrEnum):
    """How the code arrived."""

    UPLOAD = "UPLOAD"
    GIT = "GIT"


class RepositoryStatus(StrEnum):
    """Ingestion lifecycle. Phase 4 ingests synchronously, but the states are
    already explicit so Phase 6 can move this to a background job."""

    PENDING = "PENDING"
    INGESTING = "INGESTING"
    READY = "READY"
    FAILED = "FAILED"


class Repository(TimestampMixin, Base):
    __tablename__ = "repositories"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True, nullable=False
    )
    source: Mapped[RepositorySource] = mapped_column(
        Enum(RepositorySource, name="repository_source", validate_strings=True), nullable=False
    )
    status: Mapped[RepositoryStatus] = mapped_column(
        Enum(RepositoryStatus, name="repository_status", validate_strings=True),
        default=RepositoryStatus.PENDING,
        server_default=RepositoryStatus.PENDING.value,
        nullable=False,
    )

    # Where it came from: a Git URL, or the uploaded file's (sanitised) name.
    origin: Mapped[str] = mapped_column(String(500), nullable=False)
    branch: Mapped[str | None] = mapped_column(String(100), nullable=True)
    commit_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Workspace directory, relative to the configured workspace root. Never an
    # absolute path: the root is deployment configuration, not data.
    workspace_path: Mapped[str | None] = mapped_column(String(300), nullable=True)

    file_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    total_bytes: Mapped[int] = mapped_column(
        BigInteger, default=0, server_default="0", nullable=False
    )
    primary_language: Mapped[str | None] = mapped_column(String(50), nullable=True)
    # Bytes per language, biggest first: {"Python": 40213, "TypeScript": 9120}.
    # Bytes rather than file counts, because forty tiny JSON fixtures say less
    # about a codebase than one large Python module.
    language_breakdown: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    # Set only when status is FAILED; safe to show to the owner.
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    ingested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # When the static analysis (Phase 5) last ran. NULL means never analysed,
    # which is different from "analysed and clean" - the UI says which.
    analyzed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    project: Mapped["Project"] = relationship(back_populates="repositories")  # noqa: F821
    findings: Mapped[list["Finding"]] = relationship(  # noqa: F821
        back_populates="repository", cascade="all, delete-orphan", passive_deletes=True
    )
    scans: Mapped[list["Scan"]] = relationship(  # noqa: F821
        back_populates="repository", cascade="all, delete-orphan", passive_deletes=True
    )

    def __repr__(self) -> str:
        return f"Repository(id={self.id!r}, project_id={self.project_id!r}, source={self.source!r})"
