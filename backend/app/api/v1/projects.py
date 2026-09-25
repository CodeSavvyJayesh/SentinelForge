"""Project endpoints.

Every endpoint takes the caller from the access token (`CurrentUser`) and
passes it to the service, which scopes all queries to that owner. Nothing here
trusts an id, a name or an owner sent by the client.
"""

from fastapi import APIRouter, Query, status

from app.core.deps import Context, CurrentUser, DbSession, ProjectServiceDep
from app.schemas.error import ErrorResponse
from app.schemas.project import (
    ProjectCreate,
    ProjectListResponse,
    ProjectRead,
    ProjectUpdate,
)

router = APIRouter(prefix="/projects", tags=["projects"])

NOT_FOUND_RESPONSE: dict[int | str, dict[str, object]] = {
    404: {"model": ErrorResponse, "description": "No such project, or it belongs to someone else"},
}
CONFLICT_RESPONSE: dict[int | str, dict[str, object]] = {
    409: {"model": ErrorResponse, "description": "Name already used by one of your projects"},
}


@router.post(
    "",
    response_model=ProjectRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a project",
    responses=CONFLICT_RESPONSE,
)
def create_project(
    payload: ProjectCreate,
    user: CurrentUser,
    service: ProjectServiceDep,
    context: Context,
    db: DbSession,
) -> ProjectRead:
    project = service.create(payload, user, context)
    db.commit()
    return ProjectRead.model_validate(project)


@router.get(
    "",
    response_model=ProjectListResponse,
    summary="List your projects",
)
def list_projects(
    user: CurrentUser,
    service: ProjectServiceDep,
    search: str | None = Query(default=None, max_length=120, description="Filter by name"),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> ProjectListResponse:
    page = service.list(user, search=search, limit=limit, offset=offset)
    return ProjectListResponse(
        items=[ProjectRead.model_validate(project) for project in page.items],
        total=page.total,
        limit=page.limit,
        offset=page.offset,
    )


@router.get(
    "/{project_id}",
    response_model=ProjectRead,
    summary="Get one of your projects",
    responses=NOT_FOUND_RESPONSE,
)
def get_project(
    project_id: int,
    user: CurrentUser,
    service: ProjectServiceDep,
) -> ProjectRead:
    return ProjectRead.model_validate(service.get(project_id, user))


@router.patch(
    "/{project_id}",
    response_model=ProjectRead,
    summary="Update one of your projects",
    responses={**NOT_FOUND_RESPONSE, **CONFLICT_RESPONSE},
)
def update_project(
    project_id: int,
    payload: ProjectUpdate,
    user: CurrentUser,
    service: ProjectServiceDep,
    context: Context,
    db: DbSession,
) -> ProjectRead:
    project = service.update(project_id, payload, user, context)
    db.commit()
    return ProjectRead.model_validate(project)


@router.delete(
    "/{project_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete one of your projects",
    responses=NOT_FOUND_RESPONSE,
)
def delete_project(
    project_id: int,
    user: CurrentUser,
    service: ProjectServiceDep,
    context: Context,
    db: DbSession,
) -> None:
    service.delete(project_id, user, context)
    db.commit()
