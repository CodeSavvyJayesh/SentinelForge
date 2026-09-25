"""Database queries for findings.

Same rule as projects and repositories: no query ignores ownership. A finding
belongs to a repository, which belongs to a project, which belongs to a user,
so every lookup joins all the way back to ``projects.owner_id``.
"""

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.models import Finding, FindingStatus, Project, Repository, Severity


class FindingRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def get_for_owner(self, finding_id: int, owner_id: int) -> Finding | None:
        statement = (
            select(Finding)
            .join(Repository, Finding.repository_id == Repository.id)
            .join(Project, Repository.project_id == Project.id)
            .where(Finding.id == finding_id, Project.owner_id == owner_id)
        )
        return self.db.scalars(statement).first()

    def list_for_repository(
        self,
        repository_id: int,
        *,
        severity: Severity | None = None,
        status: FindingStatus | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Finding]:
        statement = (
            self._for_repository(repository_id, severity, status)
            # Worst first, then stable: two runs list the same findings in the
            # same order, which is what makes a report diffable.
            .order_by(
                _severity_rank(),
                Finding.file_path.asc(),
                Finding.line_start.asc(),
                Finding.id.asc(),
            )
            .limit(limit)
            .offset(offset)
        )
        return list(self.db.scalars(statement))

    def count_for_repository(
        self,
        repository_id: int,
        severity: Severity | None = None,
        status: FindingStatus | None = None,
    ) -> int:
        statement = select(func.count()).select_from(
            self._for_repository(repository_id, severity, status).subquery()
        )
        return self.db.scalar(statement) or 0

    def counts_by_severity(self, repository_id: int) -> dict[str, int]:
        """Severity counts for findings that are still present.

        Fixed findings are excluded: a repository with one CRITICAL that was
        fixed last week should not still read "1 CRITICAL" on the dashboard.
        """
        statement = (
            select(Finding.severity, func.count())
            .where(
                Finding.repository_id == repository_id,
                Finding.status != FindingStatus.FIXED,
            )
            .group_by(Finding.severity)
        )
        return {str(severity): count for severity, count in self.db.execute(statement)}

    def counts_by_status(self, repository_id: int) -> dict[str, int]:
        statement = (
            select(Finding.status, func.count())
            .where(Finding.repository_id == repository_id)
            .group_by(Finding.status)
        )
        return {str(status): count for status, count in self.db.execute(statement)}

    def list_all(self, repository_id: int) -> list[Finding]:
        """Every finding for a repository, fixed ones included.

        The scan lifecycle needs the fixed rows too: a finding that comes back
        is a regression, and it can only be recognised as one if the old row is
        still there to compare against.
        """
        return list(self.db.scalars(select(Finding).where(Finding.repository_id == repository_id)))

    def add(self, finding: Finding) -> Finding:
        self.db.add(finding)
        return finding

    def _for_repository(
        self,
        repository_id: int,
        severity: Severity | None,
        status: FindingStatus | None = None,
    ) -> Select[tuple[Finding]]:
        statement = select(Finding).where(Finding.repository_id == repository_id)
        if severity is not None:
            statement = statement.where(Finding.severity == severity)
        if status is not None:
            statement = statement.where(Finding.status == status)
        return statement


def _severity_rank():  # noqa: ANN202 - a SQLAlchemy case expression
    """Order by how bad it is, not alphabetically ("CRITICAL" < "LOW" < "MEDIUM")."""
    from sqlalchemy import case

    return case(
        {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        },
        value=Finding.severity,
        else_=5,
    )
