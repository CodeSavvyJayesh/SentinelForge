"""Reusable column sets for ORM models."""

from datetime import datetime

from sqlalchemy import DateTime, func
from sqlalchemy.orm import Mapped, mapped_column


class TimestampMixin:
    """``created_at`` / ``updated_at`` stored as timezone-aware UTC timestamps.

    Values are produced by PostgreSQL (``now()``), so every row uses the same
    clock regardless of which application server wrote it.
    """

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
