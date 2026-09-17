"""Alembic migration environment.

The database URL is taken from application settings (``backend/.env`` or the
``DATABASE_URL`` environment variable) — never from ``alembic.ini``.
"""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

import app.models  # noqa: F401 - registers all models on Base.metadata
from app.core.base import Base
from app.core.config import settings

config = context.config

if config.config_file_name is not None:
    # Keep application loggers enabled (important when migrations run inside tests).
    fileConfig(config.config_file_name, disable_existing_loggers=False)

# ConfigParser treats "%" as interpolation, so escape it (e.g. URL-encoded passwords).
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL.replace("%", "%%"))

target_metadata = Base.metadata

COMPARE_OPTIONS = {
    "compare_type": True,
    "compare_server_default": True,
}


def run_migrations_offline() -> None:
    """Generate SQL without connecting to the database (``alembic upgrade --sql``)."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        **COMPARE_OPTIONS,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live database connection."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            **COMPARE_OPTIONS,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
