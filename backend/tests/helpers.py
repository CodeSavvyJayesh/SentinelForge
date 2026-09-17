"""Test helpers."""

from alembic import command
from alembic.config import Config

from app.core.config import BACKEND_DIR


def alembic_config() -> Config:
    return Config(str(BACKEND_DIR / "alembic.ini"))


def alembic_upgrade(revision: str) -> None:
    command.upgrade(alembic_config(), revision)


def alembic_downgrade(revision: str) -> None:
    command.downgrade(alembic_config(), revision)
