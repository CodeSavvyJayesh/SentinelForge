"""User administration endpoints (admin only for now)."""

from fastapi import APIRouter, Query

from app.core.deps import AdminUser, DbSession
from app.repositories.user_repository import UserRepository
from app.schemas.error import ErrorResponse
from app.schemas.user import UserListResponse, UserRead

router = APIRouter(prefix="/users", tags=["users"])


@router.get(
    "",
    response_model=UserListResponse,
    summary="List user accounts (admin only)",
    responses={403: {"model": ErrorResponse, "description": "Admin role required"}},
)
def list_users(
    _admin: AdminUser,
    db: DbSession,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> UserListResponse:
    repository = UserRepository(db)
    return UserListResponse(
        items=[
            UserRead.model_validate(user)
            for user in repository.list_users(limit=limit, offset=offset)
        ],
        total=repository.count(),
        limit=limit,
        offset=offset,
    )
