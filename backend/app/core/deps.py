"""Reusable FastAPI dependencies."""

from collections.abc import Callable, Generator
from http import HTTPStatus
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.database import SessionLocal
from app.core.errors import AppError, ErrorCode
from app.core.rate_limit import InMemoryRateLimiter, RateLimiter
from app.core.security import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    InvalidTokenError,
    csrf_tokens_match,
    decode_access_token,
)
from app.models import User, UserRole
from app.repositories.user_repository import UserRepository
from app.services.auth_service import AuthService, RequestContext

UNAUTHENTICATED_HEADERS = {"WWW-Authenticate": "Bearer"}


def get_db() -> Generator[Session, None, None]:
    """Provide one database session per request and always close it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Use as a type annotation in endpoints: ``def endpoint(db: DbSession): ...``
DbSession = Annotated[Session, Depends(get_db)]
AppSettings = Annotated[Settings, Depends(get_settings)]

# auto_error=False so a missing header produces our own error envelope.
bearer_scheme = HTTPBearer(auto_error=False, description="Access token from /auth/login")


def get_request_context(request: Request) -> RequestContext:
    """Caller details recorded in the audit log."""
    return RequestContext(
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        request_id=getattr(request.state, "request_id", None),
    )


Context = Annotated[RequestContext, Depends(get_request_context)]


def get_auth_service(db: DbSession, settings: AppSettings) -> AuthService:
    return AuthService(db, settings)


AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]


def get_current_user(
    db: DbSession,
    settings: AppSettings,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> User:
    """Resolve the caller from the ``Authorization: Bearer`` access token.

    All failures return the same 401: telling a client *why* a token was
    rejected helps attackers more than users.
    """
    if credentials is None or not credentials.credentials:
        raise AppError(
            ErrorCode.UNAUTHORIZED,
            "Authentication required",
            status_code=HTTPStatus.UNAUTHORIZED,
            headers=UNAUTHENTICATED_HEADERS,
        )
    try:
        claims = decode_access_token(credentials.credentials, settings)
    except InvalidTokenError as exc:
        raise AppError(
            ErrorCode.UNAUTHORIZED,
            "Invalid or expired token",
            status_code=HTTPStatus.UNAUTHORIZED,
            headers=UNAUTHENTICATED_HEADERS,
        ) from exc

    # The token is only a claim: the database decides what is true now.
    user = UserRepository(db).get_by_id(claims.user_id)
    if user is None or not user.is_active:
        raise AppError(
            ErrorCode.UNAUTHORIZED,
            "Invalid or expired token",
            status_code=HTTPStatus.UNAUTHORIZED,
            headers=UNAUTHENTICATED_HEADERS,
        )
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_roles(*roles: UserRole) -> Callable[[User], User]:
    """Dependency factory: ``Depends(require_roles(UserRole.ADMIN))``."""
    allowed = set(roles)

    def dependency(user: CurrentUser) -> User:
        if user.role not in allowed:
            raise AppError(
                ErrorCode.FORBIDDEN,
                "You do not have permission to perform this action",
                status_code=HTTPStatus.FORBIDDEN,
            )
        return user

    return dependency


AdminUser = Annotated[User, Depends(require_roles(UserRole.ADMIN))]


def verify_csrf_token(request: Request) -> None:
    """Double-submit CSRF check for cookie-authenticated endpoints.

    The refresh token travels in a cookie, so a malicious site could trigger a
    refresh. It cannot read our CSRF cookie (same-origin policy), so requiring
    the value in a header proves the request came from our own frontend.
    """
    cookie_value = request.cookies.get(CSRF_COOKIE_NAME)
    header_value = request.headers.get(CSRF_HEADER_NAME)
    if not csrf_tokens_match(cookie_value, header_value):
        raise AppError(
            "CSRF_TOKEN_INVALID",
            "Missing or invalid CSRF token",
            status_code=HTTPStatus.FORBIDDEN,
        )


CsrfProtected = Depends(verify_csrf_token)


class _AuthRateLimiterHolder:
    """One limiter per process, created from settings on first use."""

    _limiter: RateLimiter | None = None

    @classmethod
    def get(cls, settings: Settings) -> RateLimiter:
        if cls._limiter is None:
            cls._limiter = InMemoryRateLimiter(
                max_attempts=settings.AUTH_RATE_LIMIT_ATTEMPTS,
                window_seconds=settings.AUTH_RATE_LIMIT_WINDOW_SECONDS,
            )
        return cls._limiter

    @classmethod
    def reset(cls) -> None:
        cls._limiter = None


def get_auth_rate_limiter(settings: AppSettings) -> RateLimiter:
    return _AuthRateLimiterHolder.get(settings)


def enforce_auth_rate_limit(
    request: Request,
    limiter: Annotated[RateLimiter, Depends(get_auth_rate_limiter)],
) -> None:
    """Throttle repeated login/register attempts from the same client."""
    client = request.client.host if request.client else "unknown"
    decision = limiter.hit(f"{request.url.path}:{client}")
    if not decision.allowed:
        raise AppError(
            ErrorCode.RATE_LIMITED,
            "Too many attempts. Please wait and try again.",
            status_code=HTTPStatus.TOO_MANY_REQUESTS,
            headers={"Retry-After": str(decision.retry_after_seconds)},
        )


RateLimited = Depends(enforce_auth_rate_limit)
