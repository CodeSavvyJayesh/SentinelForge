"""The background validation worker.

Fourth user of :class:`app.workers.job_worker.JobWorker`, and the cheapest: it
needs no embedding model and no language model, because validating a patch is
the analyser from Phase 5 run twice. That is also why it is its own thread
rather than more work for the patch worker — a check that takes a second should
not wait behind a generation that takes ninety.
"""

from sqlalchemy.orm import Session

from app.repositories.patch_validation_repository import PatchValidationRepository
from app.services.patch_validation_service import PatchValidationService
from app.workers.job_worker import JobWorker


class ValidationWorker(JobWorker):
    """Claims queued validations and runs them, one at a time."""

    job_name = "validation"

    @property
    def poll_interval(self) -> float:
        return self.settings.VALIDATION_POLL_INTERVAL_SECONDS

    def claim(self, session: Session):  # noqa: ANN201
        return PatchValidationRepository(session).claim_next(
            max_attempts=self.settings.VALIDATION_MAX_ATTEMPTS
        )

    def reload(self, session: Session, job_id: int):  # noqa: ANN201
        return PatchValidationRepository(session).get(job_id)

    def run_job(self, session: Session, job) -> None:  # noqa: ANN001
        PatchValidationService(session, self.settings).run(job)

    def requeue_stale(self, session: Session) -> int:
        return PatchValidationRepository(session).requeue_stale(
            older_than_seconds=self.settings.VALIDATION_STALE_AFTER_SECONDS,
            max_attempts=self.settings.VALIDATION_MAX_ATTEMPTS,
        )


__all__ = ["ValidationWorker"]
