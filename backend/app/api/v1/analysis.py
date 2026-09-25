"""Finding endpoints.

Reading findings only. Running the analysers is a *scan* (see `scans.py`),
which is queued and executed by the background worker — Phase 5's synchronous
`POST /analyze` is gone, along with the request it used to hold open.
"""

from typing import Annotated

from fastapi import APIRouter, Query

from app.core.deps import AnalysisServiceDep, CurrentUser
from app.models.finding import FindingStatus, Severity
from app.schemas.error import ErrorResponse
from app.schemas.finding import FindingListResponse, FindingRead

router = APIRouter(tags=["findings"])

SeverityFilter = Annotated[Severity | None, Query(description="Only findings of this severity")]
StatusFilter = Annotated[
    FindingStatus | None,
    Query(description="NEW (since the previous scan), OPEN (still there) or FIXED"),
]

NOT_FOUND_RESPONSE: dict[int | str, dict[str, object]] = {
    404: {
        "model": ErrorResponse,
        "description": "No such repository or finding, or it belongs to someone else",
    },
}


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
    finding_status: StatusFilter = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> FindingListResponse:
    page = service.list_findings(
        repository_id,
        user,
        severity=severity,
        status=finding_status,
        limit=limit,
        offset=offset,
    )
    return FindingListResponse(
        items=[FindingRead.model_validate(item) for item in page.items],
        total=page.total,
        by_severity=page.by_severity,
        by_status=page.by_status,
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
