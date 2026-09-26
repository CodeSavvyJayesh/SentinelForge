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
from app.knowledge.embedder import Embedder, build_embedder
from app.llm.client import OllamaClient
from app.models import User, UserRole
from app.repositories.user_repository import UserRepository
from app.services.analysis_service import AnalysisService
from app.services.auth_service import AuthService, RequestContext
from app.services.explanation_service import ExplanationService
from app.services.knowledge_service import KnowledgeService
from app.services.project_service import ProjectService
from app.services.repository_service import RepositoryService
from app.services.scan_service import ScanService

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


def get_project_service(db: DbSession) -> ProjectService:
    return ProjectService(db)


ProjectServiceDep = Annotated[ProjectService, Depends(get_project_service)]


def get_repository_service(db: DbSession, settings: AppSettings) -> RepositoryService:
    return RepositoryService(db, settings)


RepositoryServiceDep = Annotated[RepositoryService, Depends(get_repository_service)]


def get_analysis_service(db: DbSession, settings: AppSettings) -> AnalysisService:
    return AnalysisService(db, settings)


AnalysisServiceDep = Annotated[AnalysisService, Depends(get_analysis_service)]


def get_scan_service(db: DbSession, settings: AppSettings) -> ScanService:
    return ScanService(db, settings)


ScanServiceDep = Annotated[ScanService, Depends(get_scan_service)]


class _EmbedderHolder:
    """One embedding model per process, loaded on first use.

    The model is roughly 130 MB of weights and takes a second or two to
    initialise. Building it per request would make the first knowledge lookup
    after every request pay that cost; building it at import time would make the
    API refuse to start on a machine where the knowledge base is not used at
    all. So: one instance, created the first time something asks for it, and the
    model file itself is loaded lazily inside that.
    """

    _embedder: Embedder | None = None

    @classmethod
    def get(cls, settings: Settings) -> Embedder:
        if cls._embedder is None:
            cls._embedder = build_embedder(settings)
        return cls._embedder

    @classmethod
    def reset(cls) -> None:
        cls._embedder = None


def get_embedder(settings: AppSettings) -> Embedder:
    return _EmbedderHolder.get(settings)


EmbedderDep = Annotated[Embedder, Depends(get_embedder)]


def get_knowledge_service(
    db: DbSession, settings: AppSettings, embedder: EmbedderDep
) -> KnowledgeService:
    return KnowledgeService(db, settings, embedder)


KnowledgeServiceDep = Annotated[KnowledgeService, Depends(get_knowledge_service)]


class _LlmClientHolder:
    """One Ollama client per process.

    The client holds no connection and no model, so this is only about not
    rebuilding a small object per request — but it is also the single place a
    test can swap in a fake daemon.
    """

    _client: OllamaClient | None = None

    @classmethod
    def get(cls, settings: Settings) -> OllamaClient:
        if cls._client is None:
            from app.workers.explanation_worker import build_llm_client

            cls._client = build_llm_client(settings)
        return cls._client

    @classmethod
    def reset(cls) -> None:
        cls._client = None


def get_llm_client(settings: AppSettings) -> OllamaClient:
    return _LlmClientHolder.get(settings)


LlmClientDep = Annotated[OllamaClient, Depends(get_llm_client)]


def get_explanation_service(
    db: DbSession, settings: AppSettings, embedder: EmbedderDep, llm: LlmClientDep
) -> ExplanationService:
    return ExplanationService(db, settings, embedder, llm)


ExplanationServiceDep = Annotated[ExplanationService, Depends(get_explanation_service)]


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
