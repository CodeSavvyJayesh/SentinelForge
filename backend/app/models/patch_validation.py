"""PatchValidation model: one attempt to check a proposed change by re-scanning.

A fourth table that doubles as its own job queue, on the loop the other three
share.

A validation is its own row rather than two more values on ``patches.status``,
and the reason is what the row has to hold. A verdict without its evidence is
an assertion: this table keeps every check that was made and how it came out,
the finding counts before and after, and what appeared that was not there
before. A patch can also be validated more than once — after the analyser's
rules change, say — and each run is a fact about a moment, not an overwrite.

The statuses separate two things that are easy to blur:

```
QUEUED → RUNNING → PASSED      ← the re-scan supports the change
                 → REJECTED    ← the re-scan contradicts it
                 → FAILED      ← it could not be judged (the code moved, …)
```

REJECTED is a verdict on the patch. FAILED is not: it says nothing was learned,
and counting it as a rejection would blame the model for a stale workspace.

What PASSED never does is touch the finding. The repository's real code has not
changed — only a copy of it did, and the copy is gone. The finding stays open
until a scan of the real code stops detecting it.
"""

from datetime import datetime
from enum import StrEnum

from sqlalchemy import DateTime, Enum, ForeignKey, Index, Integer, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.base import Base
from app.models.mixins import TimestampMixin


class PatchValidationStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    PASSED = "PASSED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"


ACTIVE_VALIDATION_STATUSES = (PatchValidationStatus.QUEUED, PatchValidationStatus.RUNNING)


class PatchValidation(TimestampMixin, Base):
    __tablename__ = "patch_validations"
    __table_args__ = (
        Index("ix_patch_validations_status_created", "status", "created_at"),
        Index("ix_patch_validations_patch_created", "patch_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    patch_id: Mapped[int] = mapped_column(
        ForeignKey("patches.id", ondelete="CASCADE"), index=True, nullable=False
    )
    requested_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    status: Mapped[PatchValidationStatus] = mapped_column(
        Enum(PatchValidationStatus, name="patch_validation_status", validate_strings=True),
        default=PatchValidationStatus.QUEUED,
        server_default=PatchValidationStatus.QUEUED.value,
        nullable=False,
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # -- the evidence ------------------------------------------------------
    # Every check, in order, as {"key", "outcome", "detail"}. Stored whole so
    # the UI shows what was tested rather than only how it came out.
    checks: Mapped[list[dict[str, str]] | None] = mapped_column(JSONB, nullable=True)
    findings_before: Mapped[int | None] = mapped_column(Integer, nullable=True)
    findings_after: Mapped[int | None] = mapped_column(Integer, nullable=True)
    also_resolved: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    new_findings: Mapped[list[dict[str, object]] | None] = mapped_column(JSONB, nullable=True)

    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    patch: Mapped["Patch"] = relationship(back_populates="validations")  # noqa: F821

    @property
    def is_active(self) -> bool:
        return self.status in ACTIVE_VALIDATION_STATUSES

    def __repr__(self) -> str:
        return (
            f"PatchValidation(id={self.id!r}, patch_id={self.patch_id!r}, status={self.status!r})"
        )


__all__ = ["ACTIVE_VALIDATION_STATUSES", "PatchValidation", "PatchValidationStatus"]
