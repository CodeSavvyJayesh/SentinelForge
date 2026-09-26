"""Finding model: one vulnerability claim about one place in one repository.

The row stores what was found and where, never the vulnerable secret itself —
`snippet` arrives already redacted from the analysers, because a findings table
is read by more people, and kept for longer, than the file it came from.

`fingerprint` is unique per repository, so re-analysing the same code updates
rather than duplicates, and "is this the same issue as last week" is answerable.
"""

from enum import StrEnum

from sqlalchemy import Enum, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.base import Base
from app.models.mixins import TimestampMixin


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FindingStatus(StrEnum):
    """Where a finding sits between two scans.

    NEW and OPEN are both present in the code right now; the difference is
    whether the last scan is the first one that saw it. FIXED means the code
    changed and it is gone — the row is kept deliberately, because "you fixed
    two things" is information, and deleting it would make that invisible.
    """

    NEW = "NEW"
    OPEN = "OPEN"
    FIXED = "FIXED"


class Finding(TimestampMixin, Base):
    __tablename__ = "findings"
    __table_args__ = (
        # The same issue cannot be recorded twice for one repository.
        UniqueConstraint("repository_id", "fingerprint", name="uq_findings_repository_fingerprint"),
        # The dashboard's only question: this repository's findings, worst first.
        Index("ix_findings_repository_severity", "repository_id", "severity"),
        # "what changed in this scan" and "what is still open".
        Index("ix_findings_repository_status", "repository_id", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    repository_id: Mapped[int] = mapped_column(
        ForeignKey("repositories.id", ondelete="CASCADE"), index=True, nullable=False
    )

    rule_id: Mapped[str] = mapped_column(String(32), nullable=False)
    analyzer: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)

    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="finding_severity", validate_strings=True), nullable=False
    )
    confidence: Mapped[Confidence] = mapped_column(
        Enum(Confidence, name="finding_confidence", validate_strings=True), nullable=False
    )
    cwe_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    owasp_category: Mapped[str | None] = mapped_column(String(80), nullable=True)

    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    line_start: Mapped[int] = mapped_column(Integer, nullable=False)
    line_end: Mapped[int] = mapped_column(Integer, nullable=False)
    # Already redacted by the analyser. Stored as data, never interpreted.
    snippet: Mapped[str] = mapped_column(Text, nullable=False, default="")

    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)

    # --- lifecycle (Phase 6) ----------------------------------------------
    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus, name="finding_status", validate_strings=True),
        default=FindingStatus.NEW,
        server_default=FindingStatus.NEW.value,
        nullable=False,
    )
    # Which scan first saw it, which scan last saw it, and which scan noticed
    # it was gone. Nullable because a scan may be pruned one day; the finding
    # outlives it.
    first_seen_scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    last_seen_scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    fixed_in_scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )

    repository: Mapped["Repository"] = relationship(back_populates="findings")  # noqa: F821
    # Generated explanations, newest last. Deleted with the finding: an
    # explanation of a finding that no longer exists explains nothing.
    explanations: Mapped[list["Explanation"]] = relationship(  # noqa: F821
        back_populates="finding", cascade="all, delete-orphan", passive_deletes=True
    )

    def __repr__(self) -> str:
        return (
            f"Finding(id={self.id!r}, rule={self.rule_id!r}, "
            f"severity={self.severity!r}, file={self.file_path!r})"
        )
