"""Health check schemas."""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class ComponentStatus(StrEnum):
    UP = "up"
    DOWN = "down"


class OverallStatus(StrEnum):
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"


class DependencyCheck(BaseModel):
    """Result of checking one dependency (database, later: Ollama, vector DB...)."""

    status: ComponentStatus
    latency_ms: float | None = Field(default=None, description="Round-trip time of the check")
    message: str | None = Field(default=None, description="Safe, non-sensitive failure summary")


class HealthChecks(BaseModel):
    database: DependencyCheck


class HealthResponse(BaseModel):
    """Readiness report: can this instance serve real requests?"""

    status: OverallStatus
    version: str
    checked_at: datetime
    checks: HealthChecks


class LivenessResponse(BaseModel):
    """Liveness report: is the process up? Does not touch dependencies."""

    status: str = Field(default="alive", examples=["alive"])
    version: str
