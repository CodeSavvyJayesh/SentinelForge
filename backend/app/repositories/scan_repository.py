"""Database queries for scans — including the job-queue claim.

The queue is the `scans` table itself. A row in `QUEUED` is work waiting to
happen, and `claim_next()` is the whole worker protocol:

```sql
SELECT ... WHERE status = 'QUEUED'
ORDER BY created_at
FOR UPDATE SKIP LOCKED
LIMIT 1
```

`FOR UPDATE` locks the row so no one else can take it. `SKIP LOCKED` is what
makes it a queue rather than a traffic jam: a second worker asking at the same
moment steps over the locked row and takes the next one, instead of blocking
until the first worker finishes.

This is why there is no Redis here. PostgreSQL has had the primitive since 9.5,
the work is already in a database we are already running, and a queue that
lives in the same transaction as the data cannot disagree with it.
"""

from datetime import UTC, datetime, timedelta

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.models import Project, Repository, Scan, ScanStatus


class ScanRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    # -- reads -------------------------------------------------------------

    def get_for_owner(self, scan_id: int, owner_id: int) -> Scan | None:
        statement = (
            select(Scan)
            .join(Repository, Scan.repository_id == Repository.id)
            .join(Project, Repository.project_id == Project.id)
            .where(Scan.id == scan_id, Project.owner_id == owner_id)
        )
        return self.db.scalars(statement).first()

    def get(self, scan_id: int) -> Scan | None:
        """Unscoped — for the worker only, which has no user."""
        return self.db.get(Scan, scan_id)

    def list_for_repository(self, repository_id: int, *, limit: int = 20, offset: int = 0):
        statement = (
            self._for_repository(repository_id)
            .order_by(Scan.created_at.desc(), Scan.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(self.db.scalars(statement))

    def count_for_repository(self, repository_id: int) -> int:
        return (
            self.db.scalar(
                select(func.count()).select_from(self._for_repository(repository_id).subquery())
            )
            or 0
        )

    def latest_for_repository(self, repository_id: int) -> Scan | None:
        statement = (
            self._for_repository(repository_id)
            .where(Scan.status == ScanStatus.COMPLETED)
            .order_by(Scan.finished_at.desc(), Scan.id.desc())
            .limit(1)
        )
        return self.db.scalars(statement).first()

    def active_for_repository(self, repository_id: int) -> Scan | None:
        """A queued or running scan, if there is one.

        Used to refuse a second scan of the same repository: two analysers
        writing the same findings would race, and the second result would
        silently win.
        """
        statement = self._for_repository(repository_id).where(
            Scan.status.in_((ScanStatus.QUEUED, ScanStatus.RUNNING))
        )
        return self.db.scalars(statement).first()

    # -- writes ------------------------------------------------------------

    def add(self, scan: Scan) -> Scan:
        self.db.add(scan)
        self.db.flush()
        return scan

    def claim_next(self, *, max_attempts: int) -> Scan | None:
        """Take the oldest queued scan, or return None if there is nothing to do.

        The caller owns the transaction: the row stays locked until it commits,
        so a crash between claiming and finishing rolls the claim back and the
        scan is picked up again.
        """
        statement = (
            select(Scan)
            .where(Scan.status == ScanStatus.QUEUED, Scan.attempts < max_attempts)
            .order_by(Scan.created_at.asc(), Scan.id.asc())
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        scan = self.db.scalars(statement).first()
        if scan is None:
            return None
        scan.status = ScanStatus.RUNNING
        scan.attempts += 1
        scan.started_at = datetime.now(UTC)
        self.db.flush()
        return scan

    def requeue_stale(self, *, older_than_seconds: int, max_attempts: int) -> int:
        """Recover scans left RUNNING by a process that died.

        Called at startup. Without it, a power cut during a scan leaves a row
        that says RUNNING forever and a repository that can never be scanned
        again, because the "already running" check keeps refusing.
        """
        cutoff = datetime.now(UTC) - timedelta(seconds=older_than_seconds)
        stale = list(
            self.db.scalars(
                select(Scan).where(
                    Scan.status == ScanStatus.RUNNING,
                    Scan.started_at.is_not(None),
                    Scan.started_at < cutoff,
                )
            )
        )
        for scan in stale:
            if scan.attempts >= max_attempts:
                scan.status = ScanStatus.FAILED
                scan.finished_at = datetime.now(UTC)
                scan.error_message = (
                    "The scan was interrupted and has already been retried; giving up."
                )
            else:
                scan.status = ScanStatus.QUEUED
                scan.started_at = None
        self.db.flush()
        return len(stale)

    def _for_repository(self, repository_id: int) -> Select[tuple[Scan]]:
        return select(Scan).where(Scan.repository_id == repository_id)
