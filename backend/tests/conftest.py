"""Shared pytest configuration.

Safety rule: tests NEVER touch the development database. Database tests run
only against ``TEST_DATABASE_URL`` (environment variable or ``backend/.env``),
and only if that database name ends with ``_test``. Without it, database
tests are skipped and everything else still runs.
"""

import os
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from dotenv import dotenv_values
from sqlalchemy.engine import make_url

BACKEND_DIR = Path(__file__).resolve().parents[1]
_ENV_FILE_VALUES = dotenv_values(BACKEND_DIR / ".env")

TEST_DATABASE_URL: str | None = os.environ.get("TEST_DATABASE_URL") or _ENV_FILE_VALUES.get(
    "TEST_DATABASE_URL"
)

if TEST_DATABASE_URL:
    _db_name = make_url(TEST_DATABASE_URL).database or ""
    if not _db_name.endswith("_test"):
        raise pytest.UsageError(
            f"Refusing to run tests: TEST_DATABASE_URL database '{_db_name}' must end with '_test'."
        )

# Must happen before any `app.*` import: settings are read at import time.
# Environment variables override values from backend/.env.
os.environ["DATABASE_URL"] = (
    TEST_DATABASE_URL or "postgresql+psycopg://unused:unused@127.0.0.1:9/unconfigured_test"
)
os.environ["ENVIRONMENT"] = "test"
# Cheap password hashing so the suite stays fast; production cost is asserted
# separately in tests/unit/test_password_hashing.py.
os.environ.setdefault("SCRYPT_N", "1024")
os.environ.setdefault("SCRYPT_P", "1")
os.environ.setdefault("JWT_SECRET", "test-secret-key-that-is-long-enough-32+")
os.environ.setdefault("AUTH_RATE_LIMIT_ATTEMPTS", "5")
os.environ["DB_CONNECT_TIMEOUT_SECONDS"] = "2"

# Ingestion (Phase 4). Workspaces go to a throwaway directory so a test can
# never write into the repository, and the limits are small so that "too big"
# and "too many" can be proven with kilobytes instead of gigabytes.
_TEST_WORKSPACE_ROOT = Path(tempfile.mkdtemp(prefix="sentinelforge-test-workspaces-"))
os.environ["WORKSPACE_ROOT"] = str(_TEST_WORKSPACE_ROOT)
os.environ.setdefault("MAX_ARCHIVE_BYTES", str(1024 * 1024))  # 1 MB
os.environ.setdefault("MAX_UNCOMPRESSED_BYTES", str(4 * 1024 * 1024))  # 4 MB
os.environ.setdefault("MAX_FILE_BYTES", str(200 * 1024))  # 200 KB
os.environ.setdefault("MAX_FILES", "50")
os.environ.setdefault("MAX_REPOSITORIES_PER_PROJECT", "3")
os.environ.setdefault("CLONE_TIMEOUT_SECONDS", "30")

# Scans (Phase 6). The worker never starts itself during tests: a background
# thread racing the assertions is how a suite becomes flaky. Tests drive the
# worker explicitly through the `scan_worker` fixture, which is both
# deterministic and a more honest test of the claim-run-commit cycle.
os.environ["SCAN_WORKER_ENABLED"] = "false"

# Explanations (Phase 8). Same rule as the scan worker: nothing starts itself.
# The model is faked at the client boundary in every test, so the suite never
# needs Ollama running or a 4.7 GB model on disk.
os.environ["EXPLANATION_WORKER_ENABLED"] = "false"
os.environ.setdefault("EXPLANATION_POLL_INTERVAL_SECONDS", "0.05")
os.environ.setdefault("EXPLANATION_STALE_AFTER_SECONDS", "300")
os.environ.setdefault("OLLAMA_MODEL", "test-model:1b")
os.environ.setdefault("SCAN_POLL_INTERVAL_SECONDS", "0.05")
os.environ.setdefault("SCAN_STALE_AFTER_SECONDS", "60")
os.environ["LOG_FORMAT"] = "text"
os.environ["ENABLE_API_DOCS"] = "true"

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.core.database import engine  # noqa: E402
from app.main import create_app  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _clean_workspace_root() -> Iterator[None]:
    """Remove every workspace this test run created."""
    yield
    shutil.rmtree(_TEST_WORKSPACE_ROOT, ignore_errors=True)


@pytest.fixture
def scan_worker(db_session: Session):
    """A worker that shares the test transaction.

    Its sessions are bound to the same connection as `db_session` and join it
    as savepoints, so the worker's commits are real commits from its point of
    view and are still rolled back with the test. Each tick gets a fresh
    session, exactly as in production, and closing it does not close the
    test's own.
    """
    from app.core.config import get_settings
    from app.workers.scan_worker import ScanWorker

    def session_factory() -> Session:
        return Session(bind=db_session.connection(), join_transaction_mode="create_savepoint")

    return ScanWorker(get_settings(), session_factory=session_factory)


@pytest.fixture
def fake_llm():  # noqa: ANN201 - tests.helpers.FakeOllama
    """A stand-in Ollama. See `tests.helpers.FakeOllama` for why it fakes the
    daemon but never the contract."""
    from tests.helpers import FakeOllama

    return FakeOllama()


@pytest.fixture
def explanation_worker(db_session: Session, stub_embedder, fake_llm):  # noqa: ANN001, ANN201
    """A worker sharing the test transaction, driven tick by tick.

    Same arrangement as `scan_worker`: its sessions join the test's connection
    as savepoints, so its commits are real from its point of view and still
    roll back with the test.
    """
    from app.core.config import get_settings
    from app.workers.explanation_worker import ExplanationWorker

    def session_factory() -> Session:
        return Session(bind=db_session.connection(), join_transaction_mode="create_savepoint")

    return ExplanationWorker(
        get_settings(), session_factory=session_factory, embedder=stub_embedder, llm=fake_llm
    )


@pytest.fixture
def workspace_root() -> Path:
    """Where ingested code lands during tests."""
    return _TEST_WORKSPACE_ROOT


@pytest.fixture(autouse=True)
def _reset_rate_limiter() -> Iterator[None]:
    """Each test starts with a clean rate-limit window."""
    from app.core.deps import _AuthRateLimiterHolder

    _AuthRateLimiterHolder.reset()
    yield
    _AuthRateLimiterHolder.reset()


@pytest.fixture
def client() -> Iterator[TestClient]:
    """A fresh app instance. Server errors become 500 responses, not raised exceptions."""
    with TestClient(create_app(), raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.fixture
def stub_embedder():  # noqa: ANN201 - tests.helpers.HashingEmbedder
    """The embedder every test uses. See ``tests.helpers.HashingEmbedder``.

    Deterministic, dependency-free, and discriminating enough that a broken
    ranking fails a test. The real model is checked separately, by
    ``scripts/check_retrieval.py`` against a real knowledge base.
    """
    from tests.helpers import HashingEmbedder

    return HashingEmbedder()


@pytest.fixture(autouse=True)
def _reset_embedder() -> Iterator[None]:
    """Never let one test's embedder or model client leak into the next."""
    from app.core.deps import _EmbedderHolder, _LlmClientHolder

    _EmbedderHolder.reset()
    _LlmClientHolder.reset()
    yield
    _EmbedderHolder.reset()
    _LlmClientHolder.reset()


@pytest.fixture
def api_client(db_session: Session, stub_embedder, fake_llm) -> Iterator[TestClient]:  # noqa: ANN001
    """Client whose requests share one transaction that is rolled back afterwards.

    Endpoints may call ``commit()``; the surrounding transaction still undoes
    everything, so database tests never leave rows behind.

    The embedding model is overridden here rather than loaded: a test run must
    not depend on a 130 MB download, and the wiring that builds the real one is
    asserted separately in ``tests/unit/test_embedder.py``.
    """
    from app.core.deps import get_db, get_embedder, get_llm_client

    app = create_app()
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_embedder] = lambda: stub_embedder
    app.dependency_overrides[get_llm_client] = lambda: fake_llm
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture(scope="session")
def database_available() -> None:
    """Skip the requesting test when no test database is configured/reachable."""
    if not TEST_DATABASE_URL:
        pytest.skip("TEST_DATABASE_URL is not set")
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        # Show the driver's message so the cause (bad password, missing
        # database, server down) is visible instead of just the class name.
        reason = str(exc).strip().splitlines()[0][:300] if str(exc).strip() else type(exc).__name__
        pytest.skip(f"Test database not reachable: {reason}")


@pytest.fixture(scope="session")
def migrated_database(database_available: None) -> None:
    """Bring the test database schema to the latest migration."""
    from tests.helpers import alembic_upgrade

    alembic_upgrade("head")


@pytest.fixture
def db_session(migrated_database: None) -> Iterator[Session]:
    """A session whose changes are rolled back after each test."""
    connection = engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()
