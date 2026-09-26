"""Database queries for explanations, including the job-queue claim.

The same shape as :mod:`app.repositories.scan_repository`, because it is the
same problem: a table of pending work, claimed by a background worker with
``FOR UPDATE SKIP LOCKED`` so a second worker steps over a locked row instead of
queueing behind it.

The duplication between the two is deliberate and temporary. Extracting a
generic job-queue base from two instances would be guessing at what a third
needs; the rule of three applies, and Phase 10's patch generation is the third,
at which point the shape will be known rather than predicted. It is recorded
here so the next person sees a decision rather than an oversight.
"""

from datetime import UTC, datetime, timedelta

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.models import (
    ACTIVE_EXPLANATION_STATUSES,
    Explanation,
    ExplanationStatus,
    Finding,
    Project,
    Repository,
)


class ExplanationRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    # -- reads -------------------------------------------------------------

    def get_for_owner(self, explanation_id: int, owner_id: int) -> Explanation | None:
        """Ownership runs all the way back to the project that owns the code."""
        statement = (
            select(Explanation)
            .join(Finding, Explanation.finding_id == Finding.id)
            .join(Repository, Finding.repository_id == Repository.id)
            .join(Project, Repository.project_id == Project.id)
            .where(Explanation.id == explanation_id, Project.owner_id == owner_id)
        )
        return self.db.scalars(statement).first()

    def get(self, explanation_id: int) -> Explanation | None:
        """Unscoped — for the worker only, which has no user."""
        return self.db.get(Explanation, explanation_id)

    def latest_for_finding(self, finding_id: int) -> Explanation | None:
        """The current explanation of a finding, whatever state it is in.

        Includes failed and running rows on purpose: the UI needs to say "this
        is being generated" and "this failed, here is why" rather than showing
        nothing and implying the feature does not exist.
        """
        statement = (
            self._for_finding(finding_id)
            .order_by(Explanation.created_at.desc(), Explanation.id.desc())
            .limit(1)
        )
        return self.db.scalars(statement).first()

    def active_for_finding(self, finding_id: int) -> Explanation | None:
        """A queued or running request, if there is one.

        Used to refuse a second request for the same finding. Without it, a
        double click costs a minute of CPU and produces two explanations that
        may not agree.
        """
        statement = self._for_finding(finding_id).where(
            Explanation.status.in_(ACTIVE_EXPLANATION_STATUSES)
        )
        return self.db.scalars(statement).first()

    def count_for_finding(self, finding_id: int) -> int:
        return (
            self.db.scalar(
                select(func.count()).select_from(self._for_finding(finding_id).subquery())
            )
            or 0
        )

    # -- writes ------------------------------------------------------------

    def add(self, explanation: Explanation) -> Explanation:
        self.db.add(explanation)
        self.db.flush()
        return explanation

    def claim_next(self, *, max_attempts: int) -> Explanation | None:
        """Take the oldest queued request, or return None if there is nothing.

        The caller owns the transaction: the row stays locked until it commits,
        so a crash between claiming and finishing rolls the claim back and the
        request is picked up again.
        """
        statement = (
            select(Explanation)
            .where(
                Explanation.status == ExplanationStatus.QUEUED,
                Explanation.attempts < max_attempts,
            )
            .order_by(Explanation.created_at.asc(), Explanation.id.asc())
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        explanation = self.db.scalars(statement).first()
        if explanation is None:
            return None
        explanation.status = ExplanationStatus.RUNNING
        explanation.attempts += 1
        explanation.started_at = datetime.now(UTC)
        self.db.flush()
        return explanation

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
                select(Explanation).where(
                    Explanation.status == ExplanationStatus.RUNNING,
                    Explanation.started_at.is_not(None),
                    Explanation.started_at < cutoff,
                )
            )
        )
        for explanation in stale:
            if explanation.attempts >= max_attempts:
                explanation.status = ExplanationStatus.FAILED
                explanation.finished_at = datetime.now(UTC)
                explanation.error_message = (
                    "Generating this explanation was interrupted and has already been "
                    "retried; giving up."
                )
            else:
                explanation.status = ExplanationStatus.QUEUED
                explanation.started_at = None
        self.db.flush()
        return len(stale)

    def _for_finding(self, finding_id: int) -> Select[tuple[Explanation]]:
        return select(Explanation).where(Explanation.finding_id == finding_id)


__all__ = ["ExplanationRepository"]
