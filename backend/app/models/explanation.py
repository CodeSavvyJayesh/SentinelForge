"""Explanation model: what the local model said about one finding, and when.

Like `scans`, this table **doubles as its own job queue**. A row in `QUEUED` is
a request waiting for the model; a background worker claims it with
``SELECT … FOR UPDATE SKIP LOCKED``, runs it, and commits. Same reasoning as
Phase 6 — the work is already in a database we run, and a queue in the same
transaction as the data cannot disagree with it.

An explanation is **stored rather than regenerated on demand**, for three
reasons that are worth keeping straight:

* Generation takes tens of seconds on a CPU. Nobody waits that per click.
* It is not deterministic across model versions. A stored explanation is the
  one a reader saw and a report quoted; regenerating on every view would mean
  the same finding read differently each time, which is unusable as evidence.
* Phase 10 needs it as input to patch generation.

And because it is stored, it records **what produced it** — the model, the
prompt version, the passages it was given. An explanation whose provenance is
unknown is an explanation nobody can audit, which for security guidance is the
same as one nobody should act on.
"""

from datetime import datetime
from enum import StrEnum

from sqlalchemy import DateTime, Enum, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.base import Base
from app.models.mixins import TimestampMixin


class ExplanationStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


ACTIVE_EXPLANATION_STATUSES = (ExplanationStatus.QUEUED, ExplanationStatus.RUNNING)


class Explanation(TimestampMixin, Base):
    __tablename__ = "explanations"
    __table_args__ = (
        # The queue query: oldest QUEUED row first.
        Index("ix_explanations_status_created", "status", "created_at"),
        Index("ix_explanations_finding_created", "finding_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True, nullable=False
    )
    # Null when a worker generated it after the requester's account was removed.
    requested_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    status: Mapped[ExplanationStatus] = mapped_column(
        Enum(ExplanationStatus, name="explanation_status", validate_strings=True),
        default=ExplanationStatus.QUEUED,
        server_default=ExplanationStatus.QUEUED.value,
        nullable=False,
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # -- provenance --------------------------------------------------------
    # Which model, and which version of our prompt. A prompt change bumps
    # PROMPT_VERSION, which makes older explanations visibly stale rather than
    # silently mixed in with newer ones.
    model: Mapped[str | None] = mapped_column(String(120), nullable=True)
    prompt_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # The knowledge chunks handed to the model, in the order they were numbered
    # in the prompt. This is what makes a citation resolvable afterwards, and
    # what lets a reviewer reconstruct exactly what the model was shown.
    passage_chunk_ids: Mapped[list[int] | None] = mapped_column(ARRAY(Integer), nullable=True)
    prompt_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    completion_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # -- the answer --------------------------------------------------------
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 1-based positions into passage_chunk_ids. Only ones that pointed at a real
    # passage survive; the rest are counted below.
    citations: Mapped[list[int] | None] = mapped_column(ARRAY(Integer), nullable=True)

    # -- what had to be cleaned up ----------------------------------------
    # Kept as data, not swallowed. These two numbers are the most direct
    # evidence this system has of a model inventing sources, and they are shown
    # to the reader rather than logged and forgotten.
    dropped_citations: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    links_removed: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )

    # Set only when status is FAILED; safe to show the owner.
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    finding: Mapped["Finding"] = relationship(back_populates="explanations")  # noqa: F821

    @property
    def is_active(self) -> bool:
        return self.status in ACTIVE_EXPLANATION_STATUSES

    @property
    def grounded(self) -> bool:
        """Did the model point at any real passage?

        An ungrounded explanation is not necessarily wrong, and it is not
        hidden. It is marked, because "the model wrote this without reference
        to any source" is exactly the thing a reader should weigh.
        """
        return bool(self.citations)

    def __repr__(self) -> str:
        return (
            f"Explanation(id={self.id!r}, finding_id={self.finding_id!r}, status={self.status!r})"
        )


__all__ = ["ACTIVE_EXPLANATION_STATUSES", "Explanation", "ExplanationStatus"]
