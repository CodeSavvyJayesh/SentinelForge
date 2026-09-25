"""Project model.

A project is the unit everything later hangs off: repositories (Phase 4),
scans (Phase 6), findings, patches. It always belongs to exactly one user,
and that ownership is what every access check is built on.
"""

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.base import Base
from app.models.mixins import TimestampMixin

DEFAULT_BRANCH = "main"


class Project(TimestampMixin, Base):
    __tablename__ = "projects"
    __table_args__ = (
        # Two users may each have a project called "SecureBank";
        # one user may not have two of them.
        UniqueConstraint("owner_id", "name", name="uq_projects_owner_id_name"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    # Deleting a user removes their projects: nothing is left orphaned.
    owner_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Filled in properly in Phase 4 (repository ingestion); free text for now.
    repository_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    default_branch: Mapped[str] = mapped_column(
        String(100), default=DEFAULT_BRANCH, server_default=DEFAULT_BRANCH, nullable=False
    )
    # Detected during ingestion in Phase 4; never guessed here.
    language: Mapped[str | None] = mapped_column(String(50), nullable=True)

    owner: Mapped["User"] = relationship(back_populates="projects")  # noqa: F821

    def __repr__(self) -> str:
        return f"Project(id={self.id!r}, name={self.name!r}, owner_id={self.owner_id!r})"
