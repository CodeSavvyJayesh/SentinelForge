"""Settings parsing and validation."""

import pytest
from pydantic import ValidationError

from app.core.config import BACKEND_DIR, ENV_FILE, Settings

VALID_URL = "postgresql+psycopg://user:pass@localhost:5432/example_test"


def make_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {"DATABASE_URL": VALID_URL, **overrides}
    return Settings(_env_file=None, **values)


def test_env_file_is_resolved_relative_to_backend_directory() -> None:
    assert ENV_FILE.is_absolute()
    assert ENV_FILE.parent == BACKEND_DIR
    assert (BACKEND_DIR / "app" / "main.py").is_file()


def test_debug_defaults_to_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEBUG", raising=False)
    assert make_settings().DEBUG is False


def test_cors_origins_are_parsed_from_comma_separated_string() -> None:
    raw = " http://localhost:5173, https://app.example.com ,"
    settings = make_settings(CORS_ALLOWED_ORIGINS=raw)
    assert settings.cors_origins == ["http://localhost:5173", "https://app.example.com"]


def test_wildcard_cors_origin_is_rejected() -> None:
    with pytest.raises(ValidationError, match="explicit origins"):
        make_settings(CORS_ALLOWED_ORIGINS="*")


def test_non_postgresql_database_url_is_rejected() -> None:
    with pytest.raises(ValidationError, match="PostgreSQL"):
        make_settings(DATABASE_URL="sqlite:///./local.db")


def test_log_level_is_case_insensitive() -> None:
    assert make_settings(LOG_LEVEL="debug").LOG_LEVEL == "DEBUG"


def test_unknown_environment_is_rejected() -> None:
    with pytest.raises(ValidationError):
        make_settings(ENVIRONMENT="staging-ish")
