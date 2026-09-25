"""The worker: claiming, recovering, retrying, and surviving.

These test the queue mechanics directly, without the API, because the failure
modes that matter here are the ones nobody sees: two workers taking the same
job, a crashed process leaving a repository unscannable forever, and one bad
repository stopping every other scan.
"""

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import Project, Repository, RepositoryStatus, Scan, ScanStatus, User
from app.repositories.scan_repository import ScanRepository
from app.workers.scan_worker import ScanWorker

pytestmark = pytest.mark.integration

PASSWORD = "a-long-enough-passphrase"


def make_repository(db: Session, *, username: str = "alice") -> Repository:
    """A READY repository with a real (empty) workspace on disk."""
    from app.core.security import hash_password
    from app.ingestion.workspace import WorkspaceManager

    settings = get_settings()
    user = User(
        email=f"{username}@example.com",
        username=username,
        hashed_password=hash_password(PASSWORD, settings),
    )
    db.add(user)
    db.flush()
    project = Project(owner_id=user.id, name=f"Project {username}")
    db.add(project)
    db.flush()
    repository = Repository(
        project_id=project.id,
        source="UPLOAD",
        status=RepositoryStatus.READY,
        origin="code.zip",
    )
    db.add(repository)
    db.flush()
    workspace, relative = WorkspaceManager(settings).create(
        project_id=project.id, repository_id=repository.id
    )
    (workspace / "app.py").write_text("import os\nos.system(cmd)\n")
    repository.workspace_path = relative
    db.flush()
    return repository


def queue(db: Session, repository: Repository, **overrides) -> Scan:
    scan = Scan(repository_id=repository.id, status=ScanStatus.QUEUED, **overrides)
    db.add(scan)
    db.flush()
    return scan


# --- claiming -------------------------------------------------------------


def test_a_claim_moves_the_scan_to_running(db_session: Session) -> None:
    repository = make_repository(db_session)
    scan = queue(db_session, repository)

    claimed = ScanRepository(db_session).claim_next(max_attempts=3)

    assert claimed is not None and claimed.id == scan.id
    assert claimed.status is ScanStatus.RUNNING
    assert claimed.attempts == 1
    assert claimed.started_at is not None


def test_claiming_takes_the_oldest_first(db_session: Session) -> None:
    repository = make_repository(db_session)
    first = queue(db_session, repository)
    second = queue(db_session, repository)

    claimed = ScanRepository(db_session).claim_next(max_attempts=3)

    assert claimed is not None
    assert claimed.id == first.id < second.id


def test_an_empty_queue_claims_nothing(db_session: Session) -> None:
    assert ScanRepository(db_session).claim_next(max_attempts=3) is None


def test_a_scan_that_has_used_its_attempts_is_not_claimed(db_session: Session) -> None:
    repository = make_repository(db_session)
    queue(db_session, repository, attempts=3)

    assert ScanRepository(db_session).claim_next(max_attempts=3) is None


def test_two_workers_do_not_take_the_same_scan(db_session: Session) -> None:
    """The SKIP LOCKED half of the queue, tested for real.

    This needs two genuine connections with genuine commits — inside the test
    transaction the row is not visible to anyone else, so an earlier version of
    this test passed happily with SKIP LOCKED removed. It asserts two things at
    once: the second worker gets *nothing*, and it gets it *immediately*.
    Without SKIP LOCKED it would instead sit waiting for the first worker's
    lock, which the short lock_timeout below turns into a failure.
    """
    import time

    from sqlalchemy import text

    from app.core.database import SessionLocal

    setup = SessionLocal()
    first_worker = SessionLocal()
    second_worker = SessionLocal()
    user_id = None
    try:
        repository = make_repository(setup, username=f"queue{int(time.time() * 1000) % 100000}")
        user_id = repository.project.owner_id
        queue(setup, repository)
        setup.commit()

        claimed = ScanRepository(first_worker).claim_next(max_attempts=3)
        assert claimed is not None  # and the row stays locked: no commit yet

        # A worker that blocks here instead of skipping will hit this timeout.
        second_worker.execute(text("SET LOCAL lock_timeout = '2s'"))
        started = time.monotonic()
        second = ScanRepository(second_worker).claim_next(max_attempts=3)
        elapsed = time.monotonic() - started

        assert second is None, "the locked row must be skipped, not handed out twice"
        assert elapsed < 1.0, f"claiming waited {elapsed:.1f}s: it blocked instead of skipping"
    finally:
        for session in (second_worker, first_worker):
            session.rollback()
            session.close()
        if user_id is not None:
            setup.execute(text("DELETE FROM users WHERE id = :id"), {"id": user_id})
            setup.commit()
        setup.close()


# --- recovery -------------------------------------------------------------


def test_a_scan_left_running_by_a_dead_process_is_requeued(db_session: Session) -> None:
    from datetime import UTC, datetime, timedelta

    repository = make_repository(db_session)
    stale = queue(db_session, repository)
    stale.status = ScanStatus.RUNNING
    stale.attempts = 1
    stale.started_at = datetime.now(UTC) - timedelta(hours=2)
    db_session.flush()

    recovered = ScanRepository(db_session).requeue_stale(older_than_seconds=60, max_attempts=3)

    assert recovered == 1
    assert stale.status is ScanStatus.QUEUED
    assert stale.started_at is None


def test_a_scan_still_running_normally_is_left_alone(db_session: Session) -> None:
    from datetime import UTC, datetime

    repository = make_repository(db_session)
    running = queue(db_session, repository)
    running.status = ScanStatus.RUNNING
    running.started_at = datetime.now(UTC)
    db_session.flush()

    assert ScanRepository(db_session).requeue_stale(older_than_seconds=900, max_attempts=3) == 0
    assert running.status is ScanStatus.RUNNING


def test_a_scan_that_keeps_dying_is_failed_rather_than_retried_forever(
    db_session: Session,
) -> None:
    from datetime import UTC, datetime, timedelta

    repository = make_repository(db_session)
    doomed = queue(db_session, repository)
    doomed.status = ScanStatus.RUNNING
    doomed.attempts = 3
    doomed.started_at = datetime.now(UTC) - timedelta(hours=2)
    db_session.flush()

    ScanRepository(db_session).requeue_stale(older_than_seconds=60, max_attempts=3)

    assert doomed.status is ScanStatus.FAILED
    assert "retried" in (doomed.error_message or "")
    assert doomed.finished_at is not None


# --- the loop -------------------------------------------------------------


def test_a_tick_with_nothing_queued_reports_no_work(scan_worker) -> None:
    assert scan_worker.tick() is False


def test_drain_runs_everything_queued(db_session: Session, scan_worker) -> None:
    first = make_repository(db_session, username="alice")
    second = make_repository(db_session, username="bob")
    queue(db_session, first)
    queue(db_session, second)

    assert scan_worker.drain() == 2
    db_session.expire_all()
    assert {scan.status for scan in db_session.scalars(select(Scan))} == {ScanStatus.COMPLETED}


def test_one_broken_repository_does_not_stop_the_others(db_session: Session, scan_worker) -> None:
    """A worker that dies on a bad scan stops scanning for everybody."""
    broken = make_repository(db_session, username="alice")
    healthy = make_repository(db_session, username="bob")
    broken.workspace_path = "project-0/does-not-exist"
    db_session.flush()
    broken_scan = queue(db_session, broken)
    healthy_scan = queue(db_session, healthy)

    scan_worker.drain()

    # The worker committed from its own session; refresh ours before asserting.
    db_session.expire_all()
    assert broken_scan.status is ScanStatus.FAILED
    assert healthy_scan.status is ScanStatus.COMPLETED
    assert healthy_scan.total_findings == 1


def test_an_unexpected_error_is_recorded_without_leaking_details(
    db_session: Session, scan_worker, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An exception string can carry a path or a fragment of analysed code."""
    from app.services import scan_service

    repository = make_repository(db_session)
    scan = queue(db_session, repository)

    def explode(*args: object, **kwargs: object) -> None:
        raise RuntimeError("/srv/secret/path/leaked.py exploded")

    monkeypatch.setattr(scan_service, "analyze_workspace", explode)

    scan_worker.tick()

    db_session.expire_all()
    assert scan.status is ScanStatus.FAILED
    assert scan.error_message == "The scan failed unexpectedly"
    assert "leaked.py" not in (scan.error_message or "")


def test_the_worker_can_be_disabled(db_session: Session) -> None:
    """Every deployment can turn it off and run scans from another process."""
    settings = get_settings().model_copy(update={"SCAN_WORKER_ENABLED": False})

    assert settings.SCAN_WORKER_ENABLED is False
    worker = ScanWorker(settings, session_factory=lambda: db_session)
    assert worker._thread is None  # noqa: SLF001 - the point of the assertion
