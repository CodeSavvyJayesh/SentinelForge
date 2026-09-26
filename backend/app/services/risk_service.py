"""Risk for a repository, computed on demand.

Deliberately **not** stored per finding. A finding's score depends on how long
it has been open, so a stored value starts drifting from the truth the moment it
is written, and a nightly job to refresh it would be a scheduled way of being
slightly wrong. The arithmetic is microseconds over a few thousand rows; the
cheapest correct thing is to compute it when somebody asks.

What *is* stored is the repository score on each scan row, written when the scan
finishes. That is a different claim — a historical record of what a particular
run concluded — and it has to be frozen precisely because the live number moves.

Ownership is checked here, as everywhere: the findings belong to a repository,
which belongs to a project, which belongs to a user.
"""

from datetime import datetime

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import Repository, Scan, User
from app.repositories.finding_repository import FindingRepository
from app.repositories.repository_repository import RepositoryRepository
from app.repositories.scan_repository import ScanRepository
from app.risk.scoring import RepositoryRisk, aggregate
from app.services.repository_service import RepositoryNotFoundError


class RiskService:
    def __init__(self, db: Session, settings: Settings) -> None:
        self.db = db
        self.settings = settings
        self.repositories = RepositoryRepository(db)
        self.findings = FindingRepository(db)
        self.scans = ScanRepository(db)

    def for_repository(
        self, repository_id: int, user: User, *, now: datetime | None = None, top: int = 5
    ) -> tuple[Repository, RepositoryRisk]:
        repository = self._owned(repository_id, user)
        findings = self.findings.list_all(repository.id)
        return repository, aggregate(findings, now=now, top=top)

    def history(self, repository_id: int, user: User, *, limit: int = 20) -> list[Scan]:
        """Completed scans that carry a score, oldest first.

        Oldest first because this is a trend: a chart reads left to right, and
        reversing it in the frontend is a step that can be forgotten in one
        place and not another.

        Scans without a score are skipped rather than plotted as zero — they
        ran before this phase existed, and drawing them at the bottom of the
        chart would invent an improvement that never happened.
        """
        repository = self._owned(repository_id, user)
        scans = self.scans.list_for_repository(repository.id, limit=limit, offset=0)
        return [
            scan
            for scan in reversed(scans)
            if scan.risk_score is not None and scan.finished_at is not None
        ]

    def _owned(self, repository_id: int, user: User) -> Repository:
        repository = self.repositories.get_for_owner(repository_id, user.id)
        if repository is None:
            raise RepositoryNotFoundError
        return repository


__all__ = ["RiskService"]
