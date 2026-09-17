"""Health endpoints.

- ``GET /health/live``: the process is running (no dependencies touched).
- ``GET /health``: the service is ready; checks PostgreSQL. Returns 503 with
  the same report body when a dependency is down, so monitors and the
  frontend can show *what* is broken.
"""

from fastapi import APIRouter, Response, status

from app.core.config import settings
from app.core.deps import DbSession
from app.schemas.health import HealthResponse, LivenessResponse, OverallStatus
from app.services.health_service import build_health_report

router = APIRouter(prefix="/health", tags=["health"])


@router.get(
    "/live",
    response_model=LivenessResponse,
    summary="Liveness probe",
)
def liveness() -> LivenessResponse:
    return LivenessResponse(version=settings.APP_VERSION)


@router.get(
    "",
    response_model=HealthResponse,
    summary="Readiness / dependency health",
    responses={
        status.HTTP_503_SERVICE_UNAVAILABLE: {
            "model": HealthResponse,
            "description": "One or more dependencies are unavailable",
        }
    },
)
def health(db: DbSession, response: Response) -> HealthResponse:
    report = build_health_report(db, version=settings.APP_VERSION)
    if report.status is OverallStatus.UNHEALTHY:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return report
