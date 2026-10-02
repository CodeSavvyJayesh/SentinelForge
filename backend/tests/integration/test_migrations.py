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


def test_patches_that_quote_credentials_are_removed_and_others_are_kept(
    database_available: None,
) -> None:
    """A proposed change for a credential finding held the secret in plain
    text. The migration deletes those rows, takes their validations with them,
    and leaves every other patch alone."""
    before, after = "e4b82c7d9a16", "f5c93d8eab27"
    alembic_downgrade("base")
    alembic_upgrade(before)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO users (id, email, username, hashed_password) "
                    "VALUES (9001, 'm@example.com', 'migrator', 'x')"
                )
            )
            connection.execute(
                text("INSERT INTO projects (id, name, owner_id) VALUES (9001, 'm', 9001)")
            )
            connection.execute(
                text(
                    "INSERT INTO repositories (id, project_id, source, status, origin) "
                    "VALUES (9001, 9001, 'UPLOAD', 'READY', 'x.zip')"
                )
            )
            for finding_id, rule_id, cwe in (
                (9001, "SEC005", "CWE-798"),
                (9002, "PY007", "CWE-327"),
            ):
                connection.execute(
                    text(
                        "INSERT INTO findings (id, repository_id, rule_id, analyzer, title, "
                        "message, severity, confidence, cwe_id, file_path, line_start, line_end, "
                        "snippet, fingerprint) VALUES (:id, 9001, :rule, 'x', 't', 'm', 'HIGH', "
                        "'HIGH', :cwe, 'f', 1, 1, 's', :fp)"
                    ),
                    {"id": finding_id, "rule": rule_id, "cwe": cwe, "fp": f"fp-{finding_id}"},
                )
                connection.execute(
                    text(
                        "INSERT INTO patches (id, finding_id, status, diff) "
                        "VALUES (:id, :id, 'PROPOSED', '-JWT_SECRET=the_actual_secret')"
                    ),
                    {"id": finding_id},
                )
                connection.execute(
                    text("INSERT INTO patch_validations (patch_id, status) VALUES (:id, 'PASSED')"),
                    {"id": finding_id},
                )

        alembic_upgrade(after)

        with engine.connect() as connection:
            patches = connection.execute(text("SELECT finding_id FROM patches")).scalars().all()
            validations = (
                connection.execute(text("SELECT patch_id FROM patch_validations")).scalars().all()
            )
            findings = connection.execute(text("SELECT count(*) FROM findings")).scalar_one()
        assert patches == [9002], "only the credential's patch should be gone"
        assert validations == [9002], "its validation goes with it"
        assert findings == 2, "the findings themselves are untouched"
    finally:
        alembic_downgrade("base")
        alembic_upgrade("head")
