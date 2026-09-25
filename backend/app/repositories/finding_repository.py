"""Database queries for findings.

Same rule as projects and repositories: no query ignores ownership. A finding
belongs to a repository, which belongs to a project, which belongs to a user,
so every lookup joins all the way back to ``projects.owner_id``.
"""

from sqlalchemy import Select, delete, func, select
from sqlalchemy.orm import Session

from app.models import Finding, Project, Repository, Severity


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
        limit: int = 50,
        offset: int = 0,
    ) -> list[Finding]:
        statement = (
            self._for_repository(repository_id, severity)
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

    def count_for_repository(self, repository_id: int, severity: Severity | None = None) -> int:
        statement = select(func.count()).select_from(
            self._for_repository(repository_id, severity).subquery()
        )
        return self.db.scalar(statement) or 0

    def counts_by_severity(self, repository_id: int) -> dict[str, int]:
        statement = (
            select(Finding.severity, func.count())
            .where(Finding.repository_id == repository_id)
            .group_by(Finding.severity)
        )
        return {str(severity): count for severity, count in self.db.execute(statement)}

    def replace_all(self, repository_id: int, findings: list[Finding]) -> None:
        """Swap in a fresh set of findings for one repository.

        Re-analysis replaces rather than appends: the findings are a statement
        about the code as it is now, not a history of every run. (History
        belongs to scans, in Phase 6.)
        """
        self.db.execute(delete(Finding).where(Finding.repository_id == repository_id))
        self.db.flush()
        if findings:
            self.db.add_all(findings)
        self.db.flush()

    def _for_repository(
        self, repository_id: int, severity: Severity | None
    ) -> Select[tuple[Finding]]:
        statement = select(Finding).where(Finding.repository_id == repository_id)
        if severity is not None:
            statement = statement.where(Finding.severity == severity)
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
