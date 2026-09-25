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

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/app/core/config.py -> parents[2] == backend/
BACKEND_DIR: Path = Path(__file__).resolve().parents[2]
ENV_FILE: Path = BACKEND_DIR / ".env"

Environment = Literal["development", "test", "production"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
LogFormat = Literal["json", "text"]
CookieSameSite = Literal["lax", "strict", "none"]


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

    # --- Authentication ----------------------------------------------------
    # Signing key for access tokens. Generate with:
    #   python -c "import secrets; print(secrets.token_urlsafe(48))"
    JWT_SECRET: str = Field(..., min_length=32, description="HMAC key for access tokens")
    ACCESS_TOKEN_TTL_MINUTES: int = Field(default=15, ge=1, le=120)
    REFRESH_TOKEN_TTL_DAYS: int = Field(default=14, ge=1, le=90)

    # Password policy and scrypt cost. Higher SCRYPT_N is safer but slower:
    # 2**15 uses ~32 MiB and ~50-150 ms per hash on a typical laptop.
    PASSWORD_MIN_LENGTH: int = Field(default=12, ge=8, le=128)
    SCRYPT_N: int = Field(default=2**15, ge=2**10)
    SCRYPT_R: int = Field(default=8, ge=1)
    SCRYPT_P: int = Field(default=2, ge=1)

    # Refresh-token cookie. COOKIE_SECURE must be true anywhere but localhost.
    COOKIE_SECURE: bool = False
    COOKIE_SAMESITE: CookieSameSite = "lax"
    COOKIE_DOMAIN: str | None = None

    # Brute-force protection for login/register (per client IP).
    AUTH_RATE_LIMIT_ATTEMPTS: int = Field(default=10, ge=1)
    AUTH_RATE_LIMIT_WINDOW_SECONDS: int = Field(default=300, ge=1)

    # --- Repository ingestion ----------------------------------------------
    # Where uploaded and cloned code is stored. One directory per repository;
    # nothing is ever written outside this root.
    WORKSPACE_ROOT: str = str(BACKEND_DIR / "workspaces")

    # Upload limits. MAX_ARCHIVE_BYTES caps the compressed upload;
    # MAX_UNCOMPRESSED_BYTES and MAX_COMPRESSION_RATIO together stop zip bombs.
    MAX_ARCHIVE_BYTES: int = Field(default=100 * 1024 * 1024, ge=1024)  # 100 MB
    MAX_UNCOMPRESSED_BYTES: int = Field(default=500 * 1024 * 1024, ge=1024)  # 500 MB
    MAX_COMPRESSION_RATIO: int = Field(default=100, ge=2)
    MAX_FILES: int = Field(default=20_000, ge=1)
    MAX_FILE_BYTES: int = Field(default=5 * 1024 * 1024, ge=1024)  # 5 MB per file
    MAX_REPOSITORIES_PER_PROJECT: int = Field(default=20, ge=1)

    # Git cloning.
    CLONE_TIMEOUT_SECONDS: int = Field(default=120, ge=5, le=900)
    GIT_COMMAND_TIMEOUT_SECONDS: int = Field(default=15, ge=1, le=120)
    # Both default to false: http:// clone URLs and hosts that resolve to a
    # private address are refused unless a deployment deliberately opts in
    # (an internal Git server on a trusted network).
    ALLOW_INSECURE_GIT_URLS: bool = False
    ALLOW_PRIVATE_GIT_HOSTS: bool = False

    # --- Static analysis (Phase 5) -----------------------------------------
    # A file larger than this is not source code worth parsing (generated
    # bundles, vendored blobs); analysing it costs time and finds nothing.
    ANALYSIS_MAX_FILE_BYTES: int = Field(default=1024 * 1024, ge=1024)  # 1 MB
    # A repository that produces more findings than this has a systemic problem
    # that a longer list will not help with; the result says it was truncated.
    ANALYSIS_MAX_FINDINGS: int = Field(default=2000, ge=1)

    # --- Background scans (Phase 6) ----------------------------------------
    # The worker runs in the API process. Turn it off to run scans from a
    # separate process (scripts/run_scans.py) or to keep a test deterministic.
    SCAN_WORKER_ENABLED: bool = True
    SCAN_POLL_INTERVAL_SECONDS: float = Field(default=1.0, gt=0, le=60)
    # A scan still RUNNING after this long belongs to a process that died; the
    # next startup requeues it. Must comfortably exceed a real scan's duration.
    SCAN_STALE_AFTER_SECONDS: int = Field(default=900, ge=60)
    # How many times a scan may be claimed before it is marked FAILED. Stops a
    # repository that crashes the analyser from being retried forever.
    SCAN_MAX_ATTEMPTS: int = Field(default=3, ge=1, le=10)

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

    @model_validator(mode="after")
    def _check_cookie_and_secret_safety(self) -> "Settings":
        if self.COOKIE_SAMESITE == "none" and not self.COOKIE_SECURE:
            raise ValueError("COOKIE_SAMESITE=none requires COOKIE_SECURE=true")
        if self.is_production and not self.COOKIE_SECURE:
            raise ValueError("COOKIE_SECURE must be true in production")
        if self.is_production and self.DEBUG:
            raise ValueError("DEBUG must be false in production")
        if self.MAX_FILE_BYTES > self.MAX_UNCOMPRESSED_BYTES:
            raise ValueError("MAX_FILE_BYTES cannot exceed MAX_UNCOMPRESSED_BYTES")
        return self

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
