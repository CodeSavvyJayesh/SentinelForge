"""Alembic migrations against a real PostgreSQL test database."""

from datetime import UTC, datetime

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import inspect, text

from app.core.base import Base
from app.core.database import engine
from tests.helpers import alembic_downgrade, alembic_upgrade

pytestmark = pytest.mark.integration

INITIAL_REVISION = "453fd78e5b07"


def test_models_and_migrations_are_in_sync(database_available: None) -> None:
    alembic_upgrade("head")
    with engine.connect() as connection:
        context = MigrationContext.configure(
            connection, opts={"compare_type": True, "compare_server_default": True}
        )
        diff = compare_metadata(context, Base.metadata)
    assert diff == [], f"Models changed without a migration: {diff}"


def test_full_downgrade_and_upgrade_round_trip(database_available: None) -> None:
    alembic_downgrade("base")
    assert "users" not in inspect(engine).get_table_names()
    alembic_upgrade("head")
    assert "users" in inspect(engine).get_table_names()


def test_timestamp_migration_preserves_existing_utc_values(database_available: None) -> None:
    """Rows written before the migration (naive UTC) must keep the same instant,
    even when the database session uses a non-UTC time zone."""
    alembic_downgrade("base")
    alembic_upgrade(INITIAL_REVISION)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO users "
                "(email, username, hashed_password, is_active, created_at, updated_at) "
                "VALUES ('legacy@example.com', 'legacy', 'x', true, "
                "'2026-08-16 07:30:00', '2026-08-16 07:30:00')"
            )
        )
    database = engine.url.database
    try:
        # Alembic opens its own connection, so set the zone at database level.
        with engine.begin() as connection:
            connection.exec_driver_sql(
                f"ALTER DATABASE \"{database}\" SET timezone TO 'Asia/Kolkata'"
            )
        alembic_upgrade("head")
        with engine.connect() as connection:
            created_at = connection.execute(
                text("SELECT created_at FROM users WHERE email = 'legacy@example.com'")
            ).scalar_one()
        assert created_at == datetime(2026, 8, 16, 7, 30, tzinfo=UTC)
    finally:
        with engine.begin() as connection:
            connection.exec_driver_sql(f'ALTER DATABASE "{database}" RESET timezone')
            connection.execute(text("DELETE FROM users WHERE email = 'legacy@example.com'"))
        alembic_upgrade("head")
