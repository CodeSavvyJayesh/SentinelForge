"""Application configuration.

All runtime configuration comes from environment variables, optionally loaded
from ``backend/.env``. Real environment variables always take precedence over
values in the ``.env`` file.

The ``.env`` path is resolved relative to this file (not the current working
directory), so the app, Alembic and tests behave the same no matter where they
are started from.
"""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/app/core/config.py -> parents[2] == backend/
BACKEND_DIR: Path = Path(__file__).resolve().parents[2]
ENV_FILE: Path = BACKEND_DIR / ".env"

Environment = Literal["development", "test", "production"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
LogFormat = Literal["json", "text"]


class Settings(BaseSettings):
    """Typed application settings."""

    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Application -------------------------------------------------------
    APP_NAME: str = "SentinelForge API"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: Environment = "development"
    DEBUG: bool = False
    API_V1_PREFIX: str = "/api/v1"
    ENABLE_API_DOCS: bool = True

    # --- Database ----------------------------------------------------------
    DATABASE_URL: str = Field(
        ...,
        description="SQLAlchemy URL, e.g. postgresql+psycopg://user:pass@host:5432/db",
    )
    DB_POOL_SIZE: int = Field(default=5, ge=1)
    DB_MAX_OVERFLOW: int = Field(default=10, ge=0)
    DB_POOL_TIMEOUT_SECONDS: int = Field(default=30, ge=1)
    DB_CONNECT_TIMEOUT_SECONDS: int = Field(default=5, ge=1)
    DB_ECHO: bool = False

    # --- Logging -----------------------------------------------------------
    LOG_LEVEL: LogLevel = "INFO"
    LOG_FORMAT: LogFormat = "json"

    # --- HTTP / CORS -------------------------------------------------------
    # Comma-separated list of exact origins allowed to call the API from a browser.
    CORS_ALLOWED_ORIGINS: str = "http://localhost:5173"

    @field_validator("DATABASE_URL")
    @classmethod
    def _require_postgresql(cls, value: str) -> str:
        if not value.startswith("postgresql"):
            raise ValueError("DATABASE_URL must be a PostgreSQL URL (postgresql+psycopg://...)")
        return value

    @field_validator("LOG_LEVEL", mode="before")
    @classmethod
    def _uppercase_log_level(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) else value

    @field_validator("CORS_ALLOWED_ORIGINS")
    @classmethod
    def _reject_wildcard_origin(cls, value: str) -> str:
        if "*" in value:
            raise ValueError("CORS_ALLOWED_ORIGINS must list explicit origins; '*' is not allowed")
        return value

    @property
    def cors_origins(self) -> list[str]:
        """CORS origins parsed from the comma-separated setting."""
        return [origin.strip() for origin in self.CORS_ALLOWED_ORIGINS.split(",") if origin.strip()]

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings instance (cached)."""
    return Settings()


settings: Settings = get_settings()
