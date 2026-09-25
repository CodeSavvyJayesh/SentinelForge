"""Scan endpoints.

Queueing a scan returns **202 Accepted** with a `QUEUED` row: the work has been
accepted, not done. The client polls `GET /scans/{id}` until the status leaves
`QUEUED`/`RUNNING`. This replaces Phase 5's synchronous `/analyze`, which held
the request open for the whole analysis and left no record that a run happened.
"""

from fastapi import APIRouter, Query, status

from app.core.deps import Context, CurrentUser, DbSession, ScanServiceDep
from app.schemas.error import ErrorResponse
from app.schemas.scan import ScanListResponse, ScanRead

router = APIRouter(tags=["scans"])

NOT_FOUND_RESPONSE: dict[int | str, dict[str, object]] = {
    404: {
        "model": ErrorResponse,
        "description": "No such repository or scan, or it belongs to someone else",
    },
}


@router.post(
    "/repositories/{repository_id}/scans",
    response_model=ScanRead,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Queue a scan of a repository",
    responses={
        **NOT_FOUND_RESPONSE,
        409: {
            "model": ErrorResponse,
            "description": "Already being scanned, or there is no code to scan",
        },
    },
)
def queue_scan(
    repository_id: int,
    user: CurrentUser,
    service: ScanServiceDep,
    context: Context,
    db: DbSession,
) -> ScanRead:
    scan = service.queue(repository_id, user, context)
    db.commit()
    db.refresh(scan)
    return ScanRead.model_validate(scan)


@router.get(
    "/repositories/{repository_id}/scans",
    response_model=ScanListResponse,
    summary="Scan history for a repository, newest first",
    responses=NOT_FOUND_RESPONSE,
)
def list_scans(
    repository_id: int,
    user: CurrentUser,
    service: ScanServiceDep,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> ScanListResponse:
    items, total = service.list_for_repository(repository_id, user, limit=limit, offset=offset)
    return ScanListResponse(
        items=[ScanRead.model_validate(item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/scans/{scan_id}",
    response_model=ScanRead,
    summary="One scan — poll this while it is queued or running",
    responses=NOT_FOUND_RESPONSE,
)
def get_scan(
    scan_id: int,
    user: CurrentUser,
    service: ScanServiceDep,
) -> ScanRead:
    return ScanRead.model_validate(service.get(scan_id, user))
