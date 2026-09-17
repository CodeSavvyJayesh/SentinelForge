"""Authentication endpoints.

Token strategy:

* ``POST /auth/login`` returns a short-lived **access token in the response
  body**. The frontend keeps it in memory only, so a cross-site scripting bug
  cannot read it from storage.
* The **refresh token** is set as an httpOnly cookie scoped to ``/api/v1/auth``
  — JavaScript cannot read it, and it is only sent to the auth endpoints.
* A readable **CSRF cookie** accompanies it; ``/auth/refresh`` and
  ``/auth/logout`` require the same value in the ``X-CSRF-Token`` header.
"""

from http import HTTPStatus

from fastapi import APIRouter, Request, Response, status

from app.core.config import Settings
from app.core.deps import (
    AppSettings,
    AuthServiceDep,
    Context,
    CsrfProtected,
    CurrentUser,
    DbSession,
    RateLimited,
)
from app.core.security import (
    CSRF_COOKIE_NAME,
    REFRESH_COOKIE_NAME,
)
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse
from app.schemas.error import ErrorResponse
from app.schemas.user import UserRead
from app.services.auth_service import IssuedSession

router = APIRouter(prefix="/auth", tags=["auth"])

REFRESH_COOKIE_PATH = "/api/v1/auth"
ERROR_RESPONSES: dict[int | str, dict[str, object]] = {
    401: {"model": ErrorResponse, "description": "Authentication failed"},
    429: {"model": ErrorResponse, "description": "Too many attempts"},
}


def _set_session_cookies(response: Response, issued: IssuedSession, settings: Settings) -> None:
    max_age = settings.REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60
    response.set_cookie(
        REFRESH_COOKIE_NAME,
        issued.refresh_token,
        max_age=max_age,
        path=REFRESH_COOKIE_PATH,
        domain=settings.COOKIE_DOMAIN,
        secure=settings.COOKIE_SECURE,
        httponly=True,  # unreadable from JavaScript
        samesite=settings.COOKIE_SAMESITE,
    )
    response.set_cookie(
        CSRF_COOKIE_NAME,
        issued.csrf_token,
        max_age=max_age,
        path="/",
        domain=settings.COOKIE_DOMAIN,
        secure=settings.COOKIE_SECURE,
        httponly=False,  # the frontend must read it to echo it back
        samesite=settings.COOKIE_SAMESITE,
    )


def _clear_session_cookies(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        REFRESH_COOKIE_NAME, path=REFRESH_COOKIE_PATH, domain=settings.COOKIE_DOMAIN
    )
    response.delete_cookie(CSRF_COOKIE_NAME, path="/", domain=settings.COOKIE_DOMAIN)


def _token_response(issued: IssuedSession, settings: Settings) -> TokenResponse:
    return TokenResponse(
        access_token=issued.access_token,
        expires_in=settings.ACCESS_TOKEN_TTL_MINUTES * 60,
        user=UserRead.model_validate(issued.user),
    )


@router.post(
    "/register",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create an account",
    dependencies=[RateLimited],
    responses={409: {"model": ErrorResponse, "description": "Account already exists"}},
)
def register(
    payload: RegisterRequest,
    service: AuthServiceDep,
    context: Context,
    db: DbSession,
) -> UserRead:
    """Register a user. The very first account created becomes the admin."""
    user = service.register(
        email=payload.email,
        username=payload.username,
        password=payload.password,
        context=context,
    )
    db.commit()
    return UserRead.model_validate(user)


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Sign in and start a session",
    dependencies=[RateLimited],
    responses=ERROR_RESPONSES,
)
def login(
    payload: LoginRequest,
    response: Response,
    service: AuthServiceDep,
    context: Context,
    settings: AppSettings,
    db: DbSession,
) -> TokenResponse:
    try:
        issued = service.login(
            identifier=payload.identifier, password=payload.password, context=context
        )
    except Exception:
        # Failed attempts are audited too, so the transaction must be kept.
        db.commit()
        raise
    db.commit()
    _set_session_cookies(response, issued, settings)
    return _token_response(issued, settings)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Exchange the refresh cookie for a new access token",
    dependencies=[CsrfProtected],
    responses=ERROR_RESPONSES,
)
def refresh(
    request: Request,
    response: Response,
    service: AuthServiceDep,
    context: Context,
    settings: AppSettings,
    db: DbSession,
) -> TokenResponse:
    """Rotates the refresh token: the old one stops working immediately."""
    refresh_token = request.cookies.get(REFRESH_COOKIE_NAME, "")
    try:
        issued = service.refresh(refresh_token=refresh_token, context=context)
    except Exception:
        db.commit()  # keep reuse-detection revocations and audit rows
        _clear_session_cookies(response, settings)
        raise
    db.commit()
    _set_session_cookies(response, issued, settings)
    return _token_response(issued, settings)


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="End the current session",
    dependencies=[CsrfProtected],
)
def logout(
    request: Request,
    response: Response,
    service: AuthServiceDep,
    context: Context,
    settings: AppSettings,
    db: DbSession,
) -> Response:
    service.logout(refresh_token=request.cookies.get(REFRESH_COOKIE_NAME), context=context)
    db.commit()
    result = Response(status_code=HTTPStatus.NO_CONTENT)
    _clear_session_cookies(result, settings)
    return result


@router.get(
    "/me",
    response_model=UserRead,
    summary="The signed-in user",
    responses={401: {"model": ErrorResponse, "description": "Authentication required"}},
)
def me(user: CurrentUser) -> UserRead:
    return UserRead.model_validate(user)
