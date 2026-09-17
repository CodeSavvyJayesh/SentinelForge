"""Health checking logic, kept out of the API layer."""

import time
from datetime import UTC, datetime

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.schemas.health import (
    ComponentStatus,
    DependencyCheck,
    HealthChecks,
    HealthResponse,
    OverallStatus,
)

logger = get_logger("sentinelforge.health")


def check_database(db: Session) -> DependencyCheck:
    """Run a trivial query and report whether PostgreSQL is reachable.

    The raw exception is logged server-side only; the response carries a
    generic message so hostnames or credentials are never exposed.
    """
    started = time.perf_counter()
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError:
        logger.warning("database_health_check_failed", exc_info=True)
        return DependencyCheck(
            status=ComponentStatus.DOWN,
            message="Database connection failed",
        )
    return DependencyCheck(
        status=ComponentStatus.UP,
        latency_ms=round((time.perf_counter() - started) * 1000, 2),
    )


def build_health_report(db: Session, version: str) -> HealthResponse:
    database = check_database(db)
    overall = (
        OverallStatus.HEALTHY if database.status is ComponentStatus.UP else OverallStatus.UNHEALTHY
    )
    return HealthResponse(
        status=overall,
        version=version,
        checked_at=datetime.now(UTC),
        checks=HealthChecks(database=database),
    )
