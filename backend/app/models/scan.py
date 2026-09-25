"""Scan model: one run of the analysers over one repository.

A scan is **history**. Findings are overwritten as code changes; scans never
are, so "what did this repository look like last Tuesday" has an answer.

The table doubles as the **job queue**. A row in `QUEUED` is work waiting to be
done, and the worker claims it with ``SELECT … FOR UPDATE SKIP LOCKED`` — which
is why two workers can run without a Redis, and why a crash mid-scan leaves a
row that says exactly what was happening.

The lifecycle:

```
QUEUED ──claimed──> RUNNING ──┬──> COMPLETED
   ▲                          └──> FAILED
   └──── requeued after a crash, up to SCAN_MAX_ATTEMPTS
```
"""

from datetime import datetime
from enum import StrEnum

from sqlalchemy import DateTime, Enum, ForeignKey, Index, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.base import Base
from app.models.mixins import TimestampMixin


class ScanStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


ACTIVE_STATUSES = (ScanStatus.QUEUED, ScanStatus.RUNNING)


class Scan(TimestampMixin, Base):
    __tablename__ = "scans"
    __table_args__ = (
        # The queue query: oldest QUEUED row first.
        Index("ix_scans_status_created", "status", "created_at"),
        # The history query: this repository's scans, newest first.
        Index("ix_scans_repository_created", "repository_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    repository_id: Mapped[int] = mapped_column(
        ForeignKey("repositories.id", ondelete="CASCADE"), index=True, nullable=False
    )
    # Who asked for it. Kept even if the account is deleted, because a scan is
    # a record of something that happened.
    triggered_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status", validate_strings=True),
        default=ScanStatus.QUEUED,
        server_default=ScanStatus.QUEUED.value,
        nullable=False,
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # What the run saw.
    files_scanned: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    files_skipped: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    unparsable_files: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )

    # What the run concluded. Stored on the scan rather than recomputed, so a
    # history row still tells the truth after the findings move on.
    total_findings: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    new_findings: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    fixed_findings: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    truncated: Mapped[bool] = mapped_column(default=False, server_default="false", nullable=False)

    # Set only when status is FAILED; safe to show the owner.
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    repository: Mapped["Repository"] = relationship(back_populates="scans")  # noqa: F821

    @property
    def is_active(self) -> bool:
        return self.status in ACTIVE_STATUSES

    def __repr__(self) -> str:
        return f"Scan(id={self.id!r}, repository_id={self.repository_id!r}, status={self.status!r})"
