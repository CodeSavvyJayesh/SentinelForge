"""Patch model: a proposed change to one finding's code.

Like `scans` and `explanations`, this table **doubles as its own job queue** —
same `SELECT … FOR UPDATE SKIP LOCKED` claim, same crash recovery, same attempt
limit.

The status vocabulary is the point of the phase:

```
QUEUED → RUNNING → PROPOSED     ← generated, checked, shown to a person
                 → FAILED       ← could not be generated or was refused
```

There is deliberately **no APPLIED and no FIXED here**. A generated patch is a
proposal and nothing more: it is not written to the repository, it does not
change the finding it addresses, and it does not lower the risk score. Phase 11
adds `VALIDATED` and `REJECTED`, and the only way to earn either is to apply the
diff to a throwaway copy and re-scan it.

That gap between `PROPOSED` and `VALIDATED` is the project's first principle
made into a database column.
"""

from datetime import datetime
from enum import StrEnum

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.base import Base
from app.models.mixins import TimestampMixin


class PatchStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    # Generated and checked, never applied. Phase 11 is what can promote this.
    PROPOSED = "PROPOSED"
    FAILED = "FAILED"


ACTIVE_PATCH_STATUSES = (PatchStatus.QUEUED, PatchStatus.RUNNING)


class Patch(TimestampMixin, Base):
    __tablename__ = "patches"
    __table_args__ = (
        Index("ix_patches_status_created", "status", "created_at"),
        Index("ix_patches_finding_created", "finding_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True, nullable=False
    )
    requested_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    # The explanation this was built on, when there was one. Recorded so a
    # reviewer can see what the model had been told before it proposed a fix.
    explanation_id: Mapped[int | None] = mapped_column(
        ForeignKey("explanations.id", ondelete="SET NULL"), nullable=True
    )

    status: Mapped[PatchStatus] = mapped_column(
        Enum(PatchStatus, name="patch_status", validate_strings=True),
        default=PatchStatus.QUEUED,
        server_default=PatchStatus.QUEUED.value,
        nullable=False,
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # -- provenance --------------------------------------------------------
    model: Mapped[str | None] = mapped_column(String(120), nullable=True)
    prompt_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    passage_chunk_ids: Mapped[list[int] | None] = mapped_column(ARRAY(Integer), nullable=True)
    prompt_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    completion_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # -- the proposal ------------------------------------------------------
    # A unified diff, generated here by difflib rather than by the model — so
    # its hunk headers cannot be wrong.
    diff: Mapped[str | None] = mapped_column(Text, nullable=True)
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    # The region the model was allowed to change, so a reviewer can see the
    # blast radius without reading the diff.
    first_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    lines_added: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    lines_removed: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )

    # How much tidying the model's output needed before it was usable code.
    # A measurement of the model rather than of the code, kept because it is
    # the sort of number an evaluation chapter needs and nobody collects later.
    fences_stripped: Mapped[bool] = mapped_column(
        default=False, server_default="false", nullable=False
    )
    gutters_stripped: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    # Whether the replacement had to be shifted back to the indentation of the
    # code it replaces. Models return the right line flush against the margin,
    # which is cosmetic in Java and fatal in Python.
    reindented: Mapped[bool] = mapped_column(default=False, server_default="false", nullable=False)

    # What the model actually returned, kept only when the proposal was
    # refused. Without it a rejection can only be reasoned about, not read —
    # the first real refusal in this phase had to be diagnosed by inference.
    # It is also the failure corpus the evaluation chapter needs, and nobody
    # collects that after the fact.
    rejected_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Recorded because it is the difference between two runs of the same
    # prompt. At 0 a retry is bit-identical, so retries use a little more.
    temperature: Mapped[float | None] = mapped_column(Float, nullable=True)

    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    finding: Mapped["Finding"] = relationship(back_populates="patches")  # noqa: F821

    @property
    def is_active(self) -> bool:
        return self.status in ACTIVE_PATCH_STATUSES

    def __repr__(self) -> str:
        return f"Patch(id={self.id!r}, finding_id={self.finding_id!r}, status={self.status!r})"


__all__ = ["ACTIVE_PATCH_STATUSES", "Patch", "PatchStatus"]
