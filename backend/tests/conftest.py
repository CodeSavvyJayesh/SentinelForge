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
def api_client(db_session: Session) -> Iterator[TestClient]:
    """Client whose requests share one transaction that is rolled back afterwards.

    Endpoints may call ``commit()``; the surrounding transaction still undoes
    everything, so database tests never leave rows behind.
    """
    from app.core.deps import get_db

    app = create_app()
    app.dependency_overrides[get_db] = lambda: db_session
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
