"""Database queries for patches, including the job-queue claim.

The third table in this project to double as its own queue, after `scans` and
`explanations`, and the point at which the rule of three came due: the *worker*
logic was extracted into :class:`app.workers.job_worker.JobWorker` when this
phase was written. The repositories stayed separate, because what they share is
a four-line SQL shape while what differs is the model, the status enum and the
give-up message — and a base class abstracting three lines of SQL behind two
type parameters would be harder to read than the duplication it removed.
"""

from datetime import UTC, datetime, timedelta

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.models import (
    ACTIVE_PATCH_STATUSES,
    Finding,
    Patch,
    PatchStatus,
    Project,
    Repository,
)


class PatchRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    # -- reads -------------------------------------------------------------

    def get_for_owner(self, patch_id: int, owner_id: int) -> Patch | None:
        """Ownership runs all the way back to the project that owns the code."""
        statement = (
            select(Patch)
            .join(Finding, Patch.finding_id == Finding.id)
            .join(Repository, Finding.repository_id == Repository.id)
            .join(Project, Repository.project_id == Project.id)
            .where(Patch.id == patch_id, Project.owner_id == owner_id)
        )
        return self.db.scalars(statement).first()

    def get(self, patch_id: int) -> Patch | None:
        """Unscoped — for the worker only, which has no user."""
        return self.db.get(Patch, patch_id)

    def latest_for_finding(self, finding_id: int) -> Patch | None:
        """The current patch of a finding, whatever state it is in.

        Includes failed and running rows on purpose: the UI needs to say "this
        is being generated" and "this failed, here is why" rather than showing
        nothing and implying the feature does not exist.
        """
        statement = (
            self._for_finding(finding_id)
            .order_by(Patch.created_at.desc(), Patch.id.desc())
            .limit(1)
        )
        return self.db.scalars(statement).first()

    def active_for_finding(self, finding_id: int) -> Patch | None:
        """A queued or running request, if there is one.

        Used to refuse a second request for the same finding. Without it, a
        double click costs a minute of CPU and produces two patchs that
        may not agree.
        """
        statement = self._for_finding(finding_id).where(Patch.status.in_(ACTIVE_PATCH_STATUSES))
        return self.db.scalars(statement).first()

    def count_for_finding(self, finding_id: int) -> int:
        return (
            self.db.scalar(
                select(func.count()).select_from(self._for_finding(finding_id).subquery())
            )
            or 0
        )

    # -- writes ------------------------------------------------------------

    def add(self, patch: Patch) -> Patch:
        self.db.add(patch)
        self.db.flush()
        return patch

    def claim_next(self, *, max_attempts: int) -> Patch | None:
        """Take the oldest queued request, or return None if there is nothing.

        The caller owns the transaction: the row stays locked until it commits,
        so a crash between claiming and finishing rolls the claim back and the
        request is picked up again.
        """
        statement = (
            select(Patch)
            .where(
                Patch.status == PatchStatus.QUEUED,
                Patch.attempts < max_attempts,
            )
            .order_by(Patch.created_at.asc(), Patch.id.asc())
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        patch = self.db.scalars(statement).first()
        if patch is None:
            return None
        patch.status = PatchStatus.RUNNING
        patch.attempts += 1
        patch.started_at = datetime.now(UTC)
        self.db.flush()
        return patch

    def requeue_stale(self, *, older_than_seconds: int, max_attempts: int) -> int:
        """Recover requests left RUNNING by a process that died.

        The stale window has to exceed a real generation, and a real generation
        on a CPU is tens of seconds — so this threshold is necessarily much
        larger than the scan one. Too small and a slow model looks like a crash;
        the job gets requeued while it is still running, and the machine ends up
        doing the same expensive work twice.
        """
        cutoff = datetime.now(UTC) - timedelta(seconds=older_than_seconds)
        stale = list(
            self.db.scalars(
                select(Patch).where(
                    Patch.status == PatchStatus.RUNNING,
                    Patch.started_at.is_not(None),
                    Patch.started_at < cutoff,
                )
            )
        )
        for patch in stale:
            if patch.attempts >= max_attempts:
                patch.status = PatchStatus.FAILED
                patch.finished_at = datetime.now(UTC)
                patch.error_message = (
                    "Generating this change was interrupted and has already been "
                    "retried; giving up."
                )
            else:
                patch.status = PatchStatus.QUEUED
                patch.started_at = None
        self.db.flush()
        return len(stale)

    def _for_finding(self, finding_id: int) -> Select[tuple[Patch]]:
        return select(Patch).where(Patch.finding_id == finding_id)


__all__ = ["PatchRepository"]
