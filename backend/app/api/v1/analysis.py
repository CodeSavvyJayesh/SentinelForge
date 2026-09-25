"""Analysis endpoints.

Analysis runs synchronously, like ingestion, and for the same reason: Phase 6
owns background jobs, and a fake queue would be worse than an honest wait. The
engine is bounded (file size, finding cap), so the wait has a ceiling.
"""

from typing import Annotated

from fastapi import APIRouter, Query

from app.core.deps import AnalysisServiceDep, Context, CurrentUser, DbSession
from app.models.finding import Severity
from app.schemas.error import ErrorResponse
from app.schemas.finding import AnalysisSummaryResponse, FindingListResponse, FindingRead

router = APIRouter(tags=["analysis"])

SeverityFilter = Annotated[Severity | None, Query(description="Only findings of this severity")]

NOT_FOUND_RESPONSE: dict[int | str, dict[str, object]] = {
    404: {
        "model": ErrorResponse,
        "description": "No such repository or finding, or it belongs to someone else",
    },
}


@router.post(
    "/repositories/{repository_id}/analyze",
    response_model=AnalysisSummaryResponse,
    summary="Run static analysis over an ingested repository",
    responses={
        **NOT_FOUND_RESPONSE,
        409: {"model": ErrorResponse, "description": "The repository has no code to analyse"},
    },
)
def analyze_repository(
    repository_id: int,
    user: CurrentUser,
    service: AnalysisServiceDep,
    context: Context,
    db: DbSession,
) -> AnalysisSummaryResponse:
    summary = service.analyze(repository_id, user, context)
    db.commit()
    return AnalysisSummaryResponse(**vars(summary))


@router.get(
    "/repositories/{repository_id}/findings",
    response_model=FindingListResponse,
    summary="List the findings for a repository",
    responses=NOT_FOUND_RESPONSE,
)
def list_findings(
    repository_id: int,
    user: CurrentUser,
    service: AnalysisServiceDep,
    severity: SeverityFilter = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> FindingListResponse:
    page = service.list_findings(repository_id, user, severity=severity, limit=limit, offset=offset)
    return FindingListResponse(
        items=[FindingRead.model_validate(item) for item in page.items],
        total=page.total,
        by_severity=page.by_severity,
        limit=page.limit,
        offset=page.offset,
    )


@router.get(
    "/findings/{finding_id}",
    response_model=FindingRead,
    summary="Get one finding",
    responses=NOT_FOUND_RESPONSE,
)
def get_finding(
    finding_id: int,
    user: CurrentUser,
    service: AnalysisServiceDep,
) -> FindingRead:
    return FindingRead.model_validate(service.get_finding(finding_id, user))
