"""Database queries for reports.

The caller has already established that the repository belongs to the user —
:class:`app.services.report_service.ReportService` goes through
``RepositoryRepository.get_for_owner`` first, and nothing else constructs this
class. Everything here is then scoped to that one repository id.
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Finding, Patch, PatchStatus, PatchValidation, PatchValidationStatus


class ReportRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def patch_states(
        self, repository_id: int
    ) -> dict[int, tuple[PatchStatus, PatchValidationStatus | None]]:
        """For each finding, its **latest** patch and that patch's latest check.

        Latest by the orderings the patch endpoints use, so a report cannot say
        "passed" about a finding whose own page says "rejected". One statement:
        later rows overwrite earlier ones, so the last patch — and within it the
        last validation — is what is left.
        """
        statement = (
            select(Patch.finding_id, Patch.status, PatchValidation.status)
            .join(Finding, Patch.finding_id == Finding.id)
            .outerjoin(PatchValidation, PatchValidation.patch_id == Patch.id)
            .where(Finding.repository_id == repository_id)
            .order_by(
                Patch.created_at.asc(),
                Patch.id.asc(),
                PatchValidation.created_at.asc(),
                PatchValidation.id.asc(),
            )
        )
        states: dict[int, tuple[PatchStatus, PatchValidationStatus | None]] = {}
        for finding_id, status, validation in self.db.execute(statement):
            states[finding_id] = (status, validation)
        return states


__all__ = ["ReportRepository"]
