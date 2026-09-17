"""Create the PostgreSQL test database named in TEST_DATABASE_URL (if missing).

Usage (from backend/, with the virtual environment active):

    python scripts/create_test_database.py

The database name must end with ``_test`` so tests can never target the
development database. The user in TEST_DATABASE_URL needs CREATEDB rights.
"""

import os
import sys
from pathlib import Path

import psycopg
from dotenv import dotenv_values
from psycopg import sql
from sqlalchemy.engine import make_url

BACKEND_DIR = Path(__file__).resolve().parents[1]


def main() -> int:
    raw_url = os.environ.get("TEST_DATABASE_URL") or dotenv_values(BACKEND_DIR / ".env").get(
        "TEST_DATABASE_URL"
    )
    if not raw_url:
        print("TEST_DATABASE_URL is not set (environment or backend/.env).", file=sys.stderr)
        return 1

    url = make_url(raw_url)
    database = url.database or ""
    if not database.endswith("_test"):
        print(f"Refusing: database name '{database}' must end with '_test'.", file=sys.stderr)
        return 1

    admin_dsn = url.set(drivername="postgresql", database="postgres").render_as_string(
        hide_password=False
    )
    with psycopg.connect(admin_dsn, autocommit=True) as connection:
        exists = connection.execute(
            "SELECT 1 FROM pg_database WHERE datname = %s", (database,)
        ).fetchone()
        if exists:
            print(f"Test database '{database}' already exists.")
            return 0
        connection.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
    print(f"Created test database '{database}'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
