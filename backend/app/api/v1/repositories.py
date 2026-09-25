"""Repository endpoints.

Repositories live under a project, so the routes are nested:
``/projects/{project_id}/repositories``. The project id in the URL is checked
against the caller's ownership before anything is read or written — an id in a
path is a request, not a permission.

Reads and deletes take a bare ``/repositories/{repository_id}`` route because a
repository id is already scoped by the join to its project's owner.
"""

from fastapi import APIRouter, File, UploadFile, status

from app.core.deps import Context, CurrentUser, DbSession, RepositoryServiceDep
from app.schemas.error import ErrorResponse
from app.schemas.repository import (
    RepositoryConnectRequest,
    RepositoryListResponse,
    RepositoryRead,
)

router = APIRouter(tags=["repositories"])

NOT_FOUND_RESPONSE: dict[int | str, dict[str, object]] = {
    404: {
        "model": ErrorResponse,
        "description": "No such project or repository, or it belongs to someone else",
    },
}
INGEST_RESPONSES: dict[int | str, dict[str, object]] = {
    **NOT_FOUND_RESPONSE,
    400: {"model": ErrorResponse, "description": "The archive or URL was rejected"},
    409: {"model": ErrorResponse, "description": "Repository limit reached for this project"},
    413: {"model": ErrorResponse, "description": "The upload is larger than the limit"},
}


@router.post(
    "/projects/{project_id}/repositories/upload",
    response_model=RepositoryRead,
    status_code=status.HTTP_201_CREATED,
    summary="Upload a zip archive of source code",
    responses=INGEST_RESPONSES,
)
def upload_repository(
    project_id: int,
    user: CurrentUser,
    service: RepositoryServiceDep,
    context: Context,
    db: DbSession,
    file: UploadFile = File(description="A .zip archive of the codebase"),  # noqa: B008
) -> RepositoryRead:
    # ``file.file`` is a plain binary stream; the service reads it in chunks and
    # stops at the size limit rather than trusting the Content-Length header.
    repository = service.ingest_upload(
        project_id=project_id,
        filename=file.filename,
        stream=file.file,
        user=user,
        context=context,
    )
    db.commit()
    db.refresh(repository)
    return RepositoryRead.model_validate(repository)


@router.post(
    "/projects/{project_id}/repositories/git",
    response_model=RepositoryRead,
    status_code=status.HTTP_201_CREATED,
    summary="Clone a public Git repository",
    responses=INGEST_RESPONSES,
)
def connect_git_repository(
    project_id: int,
    payload: RepositoryConnectRequest,
    user: CurrentUser,
    service: RepositoryServiceDep,
    context: Context,
    db: DbSession,
) -> RepositoryRead:
    repository = service.ingest_git(
        project_id=project_id, payload=payload, user=user, context=context
    )
    db.commit()
    db.refresh(repository)
    return RepositoryRead.model_validate(repository)


@router.get(
    "/projects/{project_id}/repositories",
    response_model=RepositoryListResponse,
    summary="List the repositories connected to a project",
    responses=NOT_FOUND_RESPONSE,
)
def list_repositories(
    project_id: int,
    user: CurrentUser,
    service: RepositoryServiceDep,
) -> RepositoryListResponse:
    items = service.list_for_project(project_id, user)
    return RepositoryListResponse(
        items=[RepositoryRead.model_validate(item) for item in items], total=len(items)
    )


@router.get(
    "/repositories/{repository_id}",
    response_model=RepositoryRead,
    summary="Get one repository",
    responses=NOT_FOUND_RESPONSE,
)
def get_repository(
    repository_id: int,
    user: CurrentUser,
    service: RepositoryServiceDep,
) -> RepositoryRead:
    return RepositoryRead.model_validate(service.get(repository_id, user))


@router.delete(
    "/repositories/{repository_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a repository and its workspace",
    responses=NOT_FOUND_RESPONSE,
)
def delete_repository(
    repository_id: int,
    user: CurrentUser,
    service: RepositoryServiceDep,
    context: Context,
    db: DbSession,
) -> None:
    service.delete(repository_id, user, context)
    db.commit()
