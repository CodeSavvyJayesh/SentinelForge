"""The background scan worker.

A thread, started with the application, that does one thing forever:

```
claim the oldest QUEUED scan  →  run it  →  commit  →  repeat
                 ↓ nothing queued
              sleep a second
```

**Why a thread and not Celery.** Celery needs Redis, and Redis is a second
service to install, run and explain — on a laptop, in a demo, and in a viva. A
thread plus PostgreSQL's ``SELECT … FOR UPDATE SKIP LOCKED`` gives the two
properties that actually matter here: work is never handed to two workers at
once, and a crash cannot lose a job. What it does not give is workers on other
machines, which is the point at which Celery earns its keep — documented as the
scale-out path rather than pretended away.

**Each scan gets its own session and its own transaction.** The claim, the
analysis and the result are one unit: if the process dies mid-scan, the
transaction rolls back, the row returns to QUEUED, and the startup sweep picks
it up. Nothing is left half-written.

The worker is a plain object with a `tick()` method, so the tests drive it
directly and deterministically instead of sleeping and hoping.
"""

import threading
import time
from collections.abc import Callable

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.database import SessionLocal
from app.core.logging import get_logger
from app.repositories.scan_repository import ScanRepository
from app.services.scan_service import ScanService

logger = get_logger("sentinelforge.worker")


class ScanWorker:
    """Claims queued scans and runs them, one at a time."""

    def __init__(
        self,
        settings: Settings,
        session_factory: Callable[[], Session] = SessionLocal,
    ) -> None:
        self.settings = settings
        self.session_factory = session_factory
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # -- one unit of work --------------------------------------------------

    def tick(self) -> bool:
        """Claim and run one scan. Returns True if there was work to do."""
        session = self.session_factory()
        try:
            scans = ScanRepository(session)
            scan = scans.claim_next(max_attempts=self.settings.SCAN_MAX_ATTEMPTS)
            if scan is None:
                session.rollback()  # release the snapshot, keep nothing
                return False

            # Committing the claim before the work means a long scan does not
            # hold a row lock for its whole duration, and the UI can see
            # RUNNING immediately instead of after the scan finishes.
            scan_id = scan.id
            session.commit()

            scan = scans.get(scan_id)
            if scan is None:  # pragma: no cover - deleted between claim and run
                return True
            ScanService(session, self.settings).run(scan)
            session.commit()
            return True
        except Exception:  # noqa: BLE001 - one bad scan must not stop the worker
            logger.exception("worker_tick_failed")
            session.rollback()
            return True
        finally:
            session.close()

    def recover_stale_scans(self) -> int:
        """Requeue scans a previous process left RUNNING. Called at startup."""
        session = self.session_factory()
        try:
            count = ScanRepository(session).requeue_stale(
                older_than_seconds=self.settings.SCAN_STALE_AFTER_SECONDS,
                max_attempts=self.settings.SCAN_MAX_ATTEMPTS,
            )
            session.commit()
            if count:
                logger.warning("stale_scans_recovered", extra={"count": count})
            return count
        finally:
            session.close()

    # -- the loop ----------------------------------------------------------

    def run_forever(self) -> None:
        logger.info(
            "scan_worker_started",
            extra={"poll_seconds": self.settings.SCAN_POLL_INTERVAL_SECONDS},
        )
        while not self._stop.is_set():
            try:
                did_work = self.tick()
            except Exception:  # pragma: no cover - tick already guards itself
                logger.exception("worker_loop_failed")
                did_work = False
            if not did_work:
                # Nothing queued: wait, but wake immediately on shutdown.
                self._stop.wait(self.settings.SCAN_POLL_INTERVAL_SECONDS)
        logger.info("scan_worker_stopped")

    def start(self) -> None:
        if self._thread is not None:  # pragma: no cover - guarded by the caller
            return
        self.recover_stale_scans()
        self._thread = threading.Thread(
            target=self.run_forever, name="sentinelforge-scan-worker", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Ask the loop to finish. A scan already running is allowed to end."""
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=timeout)
            if thread.is_alive():  # pragma: no cover - a scan outlasting shutdown
                logger.warning("scan_worker_did_not_stop_in_time")

    def drain(self, limit: int = 100) -> int:
        """Run every queued scan now. For tests and for `scripts/run_scans.py`."""
        done = 0
        while done < limit and self.tick():
            done += 1
        return done


def wait_for(condition: Callable[[], bool], timeout: float = 10.0, interval: float = 0.05) -> bool:
    """Small helper for tests: poll a condition until it holds or time runs out."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(interval)
    return condition()
