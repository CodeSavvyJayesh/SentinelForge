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


class Finding(TimestampMixin, Base):
    __tablename__ = "findings"
    __table_args__ = (
        # The same issue cannot be recorded twice for one repository.
        UniqueConstraint("repository_id", "fingerprint", name="uq_findings_repository_fingerprint"),
        # The dashboard's only question: this repository's findings, worst first.
        Index("ix_findings_repository_severity", "repository_id", "severity"),
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

    repository: Mapped["Repository"] = relationship(back_populates="findings")  # noqa: F821

    def __repr__(self) -> str:
        return (
            f"Finding(id={self.id!r}, rule={self.rule_id!r}, "
            f"severity={self.severity!r}, file={self.file_path!r})"
        )
