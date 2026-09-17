"""Shared pytest configuration.

Safety rule: tests NEVER touch the development database. Database tests run
only against ``TEST_DATABASE_URL`` (environment variable or ``backend/.env``),
and only if that database name ends with ``_test``. Without it, database
tests are skipped and everything else still runs.
"""

import os
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
os.environ["DB_CONNECT_TIMEOUT_SECONDS"] = "2"
os.environ["LOG_FORMAT"] = "text"
os.environ["ENABLE_API_DOCS"] = "true"

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.core.database import engine  # noqa: E402
from app.main import create_app  # noqa: E402


@pytest.fixture
def client() -> Iterator[TestClient]:
    """A fresh app instance. Server errors become 500 responses, not raised exceptions."""
    with TestClient(create_app(), raise_server_exceptions=False) as test_client:
        yield test_client


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
