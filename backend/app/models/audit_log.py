"""Audit log: an append-only record of security-relevant actions.

Rows are never updated or deleted by the application, so there is no
``updated_at``. Secrets (passwords, tokens) must never be written here.
"""

from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.base import Base


class AuditAction(StrEnum):
    """Actions worth keeping a permanent record of. Extended by later phases."""

    USER_REGISTERED = "user.registered"
    LOGIN_SUCCEEDED = "auth.login_succeeded"
    LOGIN_FAILED = "auth.login_failed"
    TOKEN_REFRESHED = "auth.token_refreshed"  # noqa: S105 - an event name, not a secret
    REFRESH_REUSE_DETECTED = "auth.refresh_reuse_detected"
    LOGOUT = "auth.logout"
    PROJECT_CREATED = "project.created"
    PROJECT_UPDATED = "project.updated"
    PROJECT_DELETED = "project.deleted"
    REPOSITORY_CONNECTED = "repository.connected"
    REPOSITORY_INGEST_FAILED = "repository.ingest_failed"
    REPOSITORY_DELETED = "repository.deleted"
    REPOSITORY_ANALYZED = "repository.analyzed"
    SCAN_QUEUED = "scan.queued"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"

    # Phase 8. Recorded because a generated explanation is advice shown to a
    # person: who asked for it, which model answered, and whether it had to be
    # cleaned up are all things an audit should be able to reconstruct.
    EXPLANATION_REQUESTED = "explanation.requested"
    EXPLANATION_COMPLETED = "explanation.completed"
    EXPLANATION_FAILED = "explanation.failed"


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Kept even if the user is deleted: the record of what happened must survive.
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True, nullable=True
    )
    action: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    entity_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    entity_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True, nullable=False
    )

    def __repr__(self) -> str:
        return f"AuditLog(id={self.id!r}, action={self.action!r}, user_id={self.user_id!r})"
