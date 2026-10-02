"""Database queries for patch validations, including the job-queue claim.

Same four-line claim as scans, explanations and patches. As with those, the
*worker* loop is shared (:class:`app.workers.job_worker.JobWorker`) and the
repository is not: what differs between them is the model, the enum and the
give-up message, and an abstraction over that would be longer than the code.
"""

from datetime import UTC, datetime, timedelta

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from app.models import (
    ACTIVE_VALIDATION_STATUSES,
    Finding,
    Patch,
    PatchValidation,
    PatchValidationStatus,
    Project,
    Repository,
)


class PatchValidationRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    # -- reads -------------------------------------------------------------

    def get(self, validation_id: int) -> PatchValidation | None:
        """Unscoped — for the worker only, which has no user."""
        return self.db.get(PatchValidation, validation_id)

    def get_for_owner(self, validation_id: int, owner_id: int) -> PatchValidation | None:
        """Ownership runs all the way back to the project that owns the code."""
        statement = (
            select(PatchValidation)
            .join(Patch, PatchValidation.patch_id == Patch.id)
            .join(Finding, Patch.finding_id == Finding.id)
            .join(Repository, Finding.repository_id == Repository.id)
            .join(Project, Repository.project_id == Project.id)
            .where(PatchValidation.id == validation_id, Project.owner_id == owner_id)
        )
        return self.db.scalars(statement).first()

    def latest_for_patch(self, patch_id: int) -> PatchValidation | None:
        """The current validation of a patch, whatever state it is in."""
        statement = (
            self._for_patch(patch_id)
            .order_by(PatchValidation.created_at.desc(), PatchValidation.id.desc())
            .limit(1)
        )
        return self.db.scalars(statement).first()

    def active_for_patch(self, patch_id: int) -> PatchValidation | None:
        statement = self._for_patch(patch_id).where(
            PatchValidation.status.in_(ACTIVE_VALIDATION_STATUSES)
        )
        return self.db.scalars(statement).first()

    # -- writes ------------------------------------------------------------

    def add(self, validation: PatchValidation) -> PatchValidation:
        self.db.add(validation)
        self.db.flush()
        return validation

    def claim_next(self, *, max_attempts: int) -> PatchValidation | None:
        """Take the oldest queued validation, or return None."""
        statement = (
            select(PatchValidation)
            .where(
                PatchValidation.status == PatchValidationStatus.QUEUED,
                PatchValidation.attempts < max_attempts,
            )
            .order_by(PatchValidation.created_at.asc(), PatchValidation.id.asc())
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        validation = self.db.scalars(statement).first()
        if validation is None:
            return None
        validation.status = PatchValidationStatus.RUNNING
        validation.attempts += 1
        validation.started_at = datetime.now(UTC)
        self.db.flush()
        return validation

    def requeue_stale(self, *, older_than_seconds: int, max_attempts: int) -> int:
        """Recover validations left RUNNING by a process that died."""
        cutoff = datetime.now(UTC) - timedelta(seconds=older_than_seconds)
        stale = list(
            self.db.scalars(
                select(PatchValidation).where(
                    PatchValidation.status == PatchValidationStatus.RUNNING,
                    PatchValidation.started_at.is_not(None),
                    PatchValidation.started_at < cutoff,
                )
            )
        )
        for validation in stale:
            if validation.attempts >= max_attempts:
                # FAILED, not REJECTED: an interrupted check learned nothing
                # about the patch, and must not be recorded as a verdict on it.
                validation.status = PatchValidationStatus.FAILED
                validation.finished_at = datetime.now(UTC)
                validation.error_message = (
                    "Checking this change was interrupted and has already been retried; giving up."
                )
            else:
                validation.status = PatchValidationStatus.QUEUED
                validation.started_at = None
        self.db.flush()
        return len(stale)

    def _for_patch(self, patch_id: int) -> Select[tuple[PatchValidation]]:
        return select(PatchValidation).where(PatchValidation.patch_id == patch_id)


__all__ = ["PatchValidationRepository"]
