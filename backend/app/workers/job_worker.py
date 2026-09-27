"""The queue-worker loop, shared by every background job in this project.

Three phases now run the same loop:

```
claim the oldest QUEUED row  →  commit the claim  →  do the work  →  commit
                 ↓ nothing queued
              sleep, waking immediately on shutdown
```

Phases 6 and 8 each wrote it out in full, with a comment saying the duplication
was deliberate until a third case arrived and the shape was known rather than
predicted. This is the third case, so here is the shape.

What is shared is everything about *being a worker*: claiming without two
workers taking the same row, committing the claim before starting so a long job
does not hold a lock and the UI can see RUNNING immediately, surviving one bad
job, recovering rows a dead process left RUNNING, and stopping without waiting
for work already in flight.

What stays in the subclasses is everything about *the job*: which repository
claims a row, which service runs it, and what the log lines are called.

Each job gets its own session and its own transaction. A process that dies
mid-job rolls back to QUEUED, and the startup sweep picks it up.
"""

import threading
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.database import SessionLocal
from app.core.logging import get_logger

logger = get_logger("sentinelforge.worker")


class JobWorker(ABC):
    """Claims queued rows and runs them, one at a time, in a thread."""

    #: Used in log events and the thread name: "scan", "explanation", "patch".
    job_name: str = "job"

    def __init__(
        self,
        settings: Settings,
        session_factory: Callable[[], Session] = SessionLocal,
    ) -> None:
        self.settings = settings
        self.session_factory = session_factory
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # -- what a subclass must say ------------------------------------------

    @abstractmethod
    def claim(self, session: Session) -> Any | None:
        """Claim the next queued row, or return None. Must not commit."""

    @abstractmethod
    def reload(self, session: Session, job_id: int) -> Any | None:
        """Re-read a claimed row after its claim has been committed."""

    @abstractmethod
    def run_job(self, session: Session, job: Any) -> None:
        """Do the work. Must not commit; the loop does that."""

    @abstractmethod
    def requeue_stale(self, session: Session) -> int:
        """Return rows a dead process left RUNNING to the queue."""

    @property
    def poll_interval(self) -> float:
        return 1.0

    # -- one unit of work --------------------------------------------------

    def tick(self) -> bool:
        """Claim and run one job. Returns True if there was work to do."""
        session = self.session_factory()
        try:
            job = self.claim(session)
            if job is None:
                session.rollback()  # release the snapshot, keep nothing
                return False

            # The claim is committed before the work starts. Otherwise a row
            # lock is held for the whole job — tens of seconds for a model
            # call — and the UI cannot show RUNNING until it is over.
            job_id = job.id
            session.commit()

            job = self.reload(session, job_id)
            if job is None:  # pragma: no cover - deleted between claim and run
                return True
            self.run_job(session, job)
            session.commit()
            return True
        except Exception:  # noqa: BLE001 - one bad job must not stop the worker
            logger.exception(f"{self.job_name}_worker_tick_failed")
            session.rollback()
            return True
        finally:
            session.close()

    def recover_stale(self) -> int:
        """Requeue rows a previous process left RUNNING. Called at startup."""
        session = self.session_factory()
        try:
            count = self.requeue_stale(session)
            session.commit()
            if count:
                logger.warning(f"stale_{self.job_name}s_recovered", extra={"count": count})
            return count
        finally:
            session.close()

    # -- the loop ----------------------------------------------------------

    def run_forever(self) -> None:
        logger.info(f"{self.job_name}_worker_started", extra={"poll_seconds": self.poll_interval})
        while not self._stop.is_set():
            try:
                did_work = self.tick()
            except Exception:  # pragma: no cover - tick already guards itself
                logger.exception(f"{self.job_name}_worker_loop_failed")
                did_work = False
            if not did_work:
                # Nothing queued: wait, but wake immediately on shutdown.
                self._stop.wait(self.poll_interval)
        logger.info(f"{self.job_name}_worker_stopped")

    def start(self) -> None:
        if self._thread is not None:  # pragma: no cover - guarded by the caller
            return
        self.recover_stale()
        self._thread = threading.Thread(
            target=self.run_forever, name=f"sentinelforge-{self.job_name}-worker", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Ask the loop to finish. Work already running is left to complete.

        The timeout is deliberately shorter than a model call: a job in flight
        finishes in its own thread and its row is recovered by the next
        startup's sweep. Blocking shutdown for a minute to be tidy is worse.
        """
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=timeout)
            if thread.is_alive():  # pragma: no cover - a job outlasting shutdown
                logger.warning(f"{self.job_name}_worker_did_not_stop_in_time")

    def drain(self, limit: int = 100) -> int:
        """Run every queued job now. For tests and for the runner scripts."""
        done = 0
        while done < limit and self.tick():
            done += 1
        return done


__all__ = ["JobWorker"]
