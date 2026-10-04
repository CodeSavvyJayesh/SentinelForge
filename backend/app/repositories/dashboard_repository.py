"""Database queries for the dashboard.

The dashboard is the first place that reads across projects, which makes it the
first place one forgotten join would show a user somebody else's findings. So
every query here starts from ``projects.owner_id`` and there is no method that
takes a bare list of ids from a caller: the owner is the only argument.

Five queries, whatever the number of repositories. The alternative — asking the
existing per-repository services once per repository — is correct and reads
well, and makes the page slower with every repository added.
"""

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import (
    Finding,
    Patch,
    PatchStatus,
    PatchValidation,
    PatchValidationStatus,
    Project,
    Repository,
    Scan,
    ScanStatus,
)


class DashboardRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def project_count(self, owner_id: int) -> int:
        statement = select(func.count()).select_from(Project).where(Project.owner_id == owner_id)
        return self.db.scalar(statement) or 0

    def repositories(self, owner_id: int) -> list[tuple[Repository, Project]]:
        statement = (
            select(Repository, Project)
            .join(Project, Repository.project_id == Project.id)
            .where(Project.owner_id == owner_id)
            .order_by(Repository.id.asc())
        )
        return [(repository, project) for repository, project in self.db.execute(statement)]

    def findings(self, owner_id: int) -> list[Finding]:
        """Every finding the owner has, fixed ones included.

        Whole rows rather than a ``GROUP BY``, because the score of a finding
        depends on its path, its age and whether it came back — none of which
        SQL can be asked for without rewriting the risk policy in a second
        language and keeping the two in step.
        """
        statement = (
            select(Finding)
            .join(Repository, Finding.repository_id == Repository.id)
            .join(Project, Repository.project_id == Project.id)
            .where(Project.owner_id == owner_id)
            .order_by(Finding.id.asc())
        )
        return list(self.db.scalars(statement))

    def completed_scans(self, owner_id: int) -> list[Scan]:
        """Completed scans, oldest first, so a trend reads left to right."""
        statement = (
            select(Scan)
            .join(Repository, Scan.repository_id == Repository.id)
            .join(Project, Repository.project_id == Project.id)
            .where(
                Project.owner_id == owner_id,
                Scan.status == ScanStatus.COMPLETED,
                Scan.finished_at.is_not(None),
            )
            .order_by(Scan.finished_at.asc(), Scan.id.asc())
        )
        return list(self.db.scalars(statement))

    def patch_outcomes(
        self, owner_id: int
    ) -> list[tuple[int, PatchStatus, PatchValidationStatus | None]]:
        """Each patch with the status of its **latest** validation, if any.

        Latest by the same ordering the patch endpoint uses, so the dashboard
        cannot count a proposal as passed while its own page says rejected.

        One statement, so there is one ownership filter rather than one per
        table: a patch brings its validations with it, and a validation cannot
        be reached except through a patch that already passed the filter.
        """
        statement = (
            select(Patch.id, Patch.status, PatchValidation.status)
            .join(Finding, Patch.finding_id == Finding.id)
            .join(Repository, Finding.repository_id == Repository.id)
            .join(Project, Repository.project_id == Project.id)
            .outerjoin(PatchValidation, PatchValidation.patch_id == Patch.id)
            .where(Project.owner_id == owner_id)
            .order_by(Patch.id.asc(), PatchValidation.created_at.asc(), PatchValidation.id.asc())
        )
        latest: dict[int, tuple[PatchStatus, PatchValidationStatus | None]] = {}
        for patch_id, status, validation in self.db.execute(statement):
            latest[patch_id] = (status, validation)  # later rows overwrite earlier ones
        return [(patch_id, status, validation) for patch_id, (status, validation) in latest.items()]


__all__ = ["DashboardRepository"]
