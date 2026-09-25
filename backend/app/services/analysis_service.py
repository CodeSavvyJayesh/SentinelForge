"""Reading findings.

Running the analysers moved to `scan_service.py` in Phase 6: a scan is queued,
a worker runs it, and the findings carry a lifecycle across runs. What is left
here is the read side — listing a repository's findings and fetching one —
with the same ownership rule as everywhere else: someone else's finding is a
404, never a 403.
"""

from dataclasses import dataclass
from http import HTTPStatus

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.errors import AppError
from app.core.logging import get_logger
from app.models import Finding, FindingStatus, Repository, Severity, User
from app.repositories.finding_repository import FindingRepository
from app.repositories.repository_repository import RepositoryRepository
from app.services.repository_service import RepositoryNotFoundError

logger = get_logger("sentinelforge.analysis.service")


class FindingNotFoundError(AppError):
    def __init__(self) -> None:
        super().__init__("FINDING_NOT_FOUND", "Finding not found", status_code=HTTPStatus.NOT_FOUND)


@dataclass(frozen=True)
class FindingPage:
    items: list[Finding]
    total: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    limit: int
    offset: int


class AnalysisService:
    def __init__(self, db: Session, settings: Settings) -> None:
        self.db = db
        self.settings = settings
        self.repositories = RepositoryRepository(db)
        self.findings = FindingRepository(db)

    # -- reads -------------------------------------------------------------

    def list_findings(
        self,
        repository_id: int,
        user: User,
        *,
        severity: Severity | None = None,
        status: FindingStatus | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> FindingPage:
        repository = self._owned_repository(repository_id, user)
        return FindingPage(
            items=self.findings.list_for_repository(
                repository.id, severity=severity, status=status, limit=limit, offset=offset
            ),
            total=self.findings.count_for_repository(repository.id, severity, status),
            # Whole-repository counts, so a filter cannot make the numbers
            # displayed beside it lie.
            by_severity=self.findings.counts_by_severity(repository.id),
            by_status=self.findings.counts_by_status(repository.id),
            limit=limit,
            offset=offset,
        )

    def get_finding(self, finding_id: int, user: User) -> Finding:
        finding = self.findings.get_for_owner(finding_id, user.id)
        if finding is None:
            raise FindingNotFoundError
        return finding

    # -- internals ---------------------------------------------------------

    def _owned_repository(self, repository_id: int, user: User) -> Repository:
        repository = self.repositories.get_for_owner(repository_id, user.id)
        if repository is None:
            # Exactly the error Phase 4 raises for a repository that does not
            # exist. A stranger must not be able to tell the two apart.
            raise RepositoryNotFoundError
        return repository


__all__ = ["AnalysisService", "FindingNotFoundError", "FindingPage"]
