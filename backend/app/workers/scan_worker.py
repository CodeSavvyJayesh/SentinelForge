"""The background scan worker.

The loop lives in :class:`app.workers.job_worker.JobWorker`, which this and the
explanation and patch workers all share. What stays here is the part that is
about scanning: which repository claims a row, and which service runs it.

**Why a thread and not Celery.** Celery needs Redis, and Redis is a second
service to install, run and explain — on a laptop, in a demo, and in a viva. A
thread plus PostgreSQL's ``SELECT … FOR UPDATE SKIP LOCKED`` gives the two
properties that matter: work is never handed to two workers at once, and a
crash cannot lose a job. What it does not give is workers on other machines,
which is where Celery earns its keep — documented as the scale-out path rather
than pretended away.
"""

import time
from collections.abc import Callable

from sqlalchemy.orm import Session

from app.repositories.scan_repository import ScanRepository
from app.services.scan_service import ScanService
from app.workers.job_worker import JobWorker


class ScanWorker(JobWorker):
    """Claims queued scans and runs them, one at a time."""

    job_name = "scan"

    @property
    def poll_interval(self) -> float:
        return self.settings.SCAN_POLL_INTERVAL_SECONDS

    def claim(self, session: Session):  # noqa: ANN201
        return ScanRepository(session).claim_next(max_attempts=self.settings.SCAN_MAX_ATTEMPTS)

    def reload(self, session: Session, job_id: int):  # noqa: ANN201
        return ScanRepository(session).get(job_id)

    def run_job(self, session: Session, job) -> None:  # noqa: ANN001
        ScanService(session, self.settings).run(job)

    def requeue_stale(self, session: Session) -> int:
        return ScanRepository(session).requeue_stale(
            older_than_seconds=self.settings.SCAN_STALE_AFTER_SECONDS,
            max_attempts=self.settings.SCAN_MAX_ATTEMPTS,
        )

    # Kept as a name of its own: `scripts/run_scans.py` and the tests both call
    # it, and "recover_stale_scans" says more at a call site than "recover_stale".
    def recover_stale_scans(self) -> int:
        return self.recover_stale()


def wait_for(condition: Callable[[], bool], timeout: float = 10.0, interval: float = 0.05) -> bool:
    """Small helper for tests: poll a condition until it holds or time runs out."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(interval)
    return condition()


__all__ = ["ScanWorker", "wait_for"]
