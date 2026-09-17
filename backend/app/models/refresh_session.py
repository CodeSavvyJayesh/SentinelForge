"""Refresh sessions: one row per issued refresh token.

Only the SHA-256 hash of a token is stored, so the table cannot be used to
impersonate anyone if the database leaks.

Every refresh rotates the token: the old row is revoked and a new one is
created with the same ``family_id``. If a token that was already used (or
revoked) is presented again, it was probably stolen, so the whole family is
revoked — the legitimate user simply logs in again.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.base import Base
from app.models.mixins import TimestampMixin


class RefreshSession(TimestampMixin, Base):
    __tablename__ = "refresh_sessions"
    __table_args__ = (Index("ix_refresh_sessions_user_id_expires_at", "user_id", "expires_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    family_id: Mapped[uuid.UUID] = mapped_column(Uuid, index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)

    user: Mapped["User"] = relationship(back_populates="refresh_sessions")  # noqa: F821

    def is_usable(self, now: datetime | None = None) -> bool:
        moment = now or datetime.now(UTC)
        return self.revoked_at is None and self.expires_at > moment

    def __repr__(self) -> str:  # never include token_hash
        return f"RefreshSession(id={self.id!r}, user_id={self.user_id!r})"
