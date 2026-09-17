"""Authentication business logic.

Contains no HTTP objects: endpoints pass a small :class:`RequestContext` and
receive plain results, so this layer stays testable and reusable (CLI, jobs).
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from http import HTTPStatus

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.core.logging import get_logger
from app.core.security import (
    create_access_token,
    generate_csrf_token,
    generate_refresh_token,
    hash_password,
    hash_refresh_token,
    needs_rehash,
    verify_password,
)
from app.models import AuditAction, RefreshSession, User, UserRole
from app.repositories.audit_log_repository import AuditLogRepository
from app.repositories.refresh_session_repository import RefreshSessionRepository
from app.repositories.user_repository import UserRepository

logger = get_logger("sentinelforge.auth")


class InvalidCredentialsError(AppError):
    def __init__(self) -> None:
        super().__init__(
            ErrorCode.UNAUTHORIZED,
            "Incorrect username or password",
            status_code=HTTPStatus.UNAUTHORIZED,
            headers={"WWW-Authenticate": "Bearer"},
        )


class AccountInactiveError(AppError):
    def __init__(self) -> None:
        super().__init__(
            "ACCOUNT_INACTIVE",
            "This account has been deactivated",
            status_code=HTTPStatus.FORBIDDEN,
        )


class AccountAlreadyExistsError(AppError):
    def __init__(self) -> None:
        # Deliberately vague: saying *which* field is taken would let anyone
        # test whether an email address is registered here.
        super().__init__(
            ErrorCode.CONFLICT,
            "An account with those details already exists",
            status_code=HTTPStatus.CONFLICT,
        )


class InvalidRefreshTokenError(AppError):
    def __init__(self) -> None:
        super().__init__(
            "INVALID_REFRESH_TOKEN",
            "Your session has expired. Please sign in again.",
            status_code=HTTPStatus.UNAUTHORIZED,
        )


@dataclass(frozen=True)
class RequestContext:
    """Who is calling, for audit records. Built by an API dependency."""

    ip_address: str | None = None
    user_agent: str | None = None
    request_id: str | None = None


@dataclass(frozen=True)
class IssuedSession:
    """Everything the API layer needs to answer a login or refresh."""

    user: User
    access_token: str
    access_expires_at: datetime
    refresh_token: str
    refresh_expires_at: datetime
    csrf_token: str


@lru_cache(maxsize=4)
def _dummy_hash(secret_marker: str) -> str:
    """A throwaway hash used to spend the same time on unknown usernames."""
    from app.core.config import get_settings

    return hash_password(f"invalid-user-{secret_marker}", get_settings())


class AuthService:
    def __init__(self, db: Session, settings: Settings) -> None:
        self.db = db
        self.settings = settings
        self.users = UserRepository(db)
        self.sessions = RefreshSessionRepository(db)
        self.audit = AuditLogRepository(db)

    # -- registration ------------------------------------------------------

    def register(
        self, *, email: str, username: str, password: str, context: RequestContext
    ) -> User:
        email = email.strip().lower()
        username = username.strip()
        if self.users.get_by_email(email) or self.users.get_by_username(username):
            raise AccountAlreadyExistsError

        # The first account bootstraps the system, so it becomes the admin.
        role = UserRole.ADMIN if self.users.count() == 0 else UserRole.USER
        user = self.users.add(
            User(
                email=email,
                username=username,
                hashed_password=hash_password(password, self.settings),
                role=role,
            )
        )
        self._record(AuditAction.USER_REGISTERED, context, user_id=user.id, details={"role": role})
        logger.info("user_registered", extra={"user_id": user.id, "role": str(role)})
        return user

    # -- login -------------------------------------------------------------

    def authenticate(self, *, identifier: str, password: str, context: RequestContext) -> User:
        user = self.users.get_by_identifier(identifier.strip())
        if user is None:
            # Verify against a dummy hash so a missing account takes the same
            # time as a wrong password (no user enumeration by stopwatch).
            verify_password(password, _dummy_hash(self.settings.JWT_SECRET[:8]))
            self._record(
                AuditAction.LOGIN_FAILED, context, details={"reason": "unknown_identifier"}
            )
            raise InvalidCredentialsError

        if not verify_password(password, user.hashed_password):
            self._record(
                AuditAction.LOGIN_FAILED,
                context,
                user_id=user.id,
                details={"reason": "bad_password"},
            )
            raise InvalidCredentialsError

        if not user.is_active:
            self._record(
                AuditAction.LOGIN_FAILED, context, user_id=user.id, details={"reason": "inactive"}
            )
            raise AccountInactiveError

        # Upgrade the stored hash if the cost policy has been raised since.
        if needs_rehash(user.hashed_password, self.settings):
            user.hashed_password = hash_password(password, self.settings)
            self.db.flush()
            logger.info("password_hash_upgraded", extra={"user_id": user.id})

        return user

    def login(self, *, identifier: str, password: str, context: RequestContext) -> IssuedSession:
        user = self.authenticate(identifier=identifier, password=password, context=context)
        issued = self._issue_session(user, family_id=uuid.uuid4(), context=context)
        self._record(AuditAction.LOGIN_SUCCEEDED, context, user_id=user.id)
        logger.info("login_succeeded", extra={"user_id": user.id})
        return issued

    # -- refresh / logout --------------------------------------------------

    def refresh(self, *, refresh_token: str, context: RequestContext) -> IssuedSession:
        """Rotate a refresh token: the presented one is revoked and replaced."""
        session = self.sessions.get_by_token_hash(hash_refresh_token(refresh_token))
        if session is None:
            raise InvalidRefreshTokenError

        if not session.is_usable():
            # A revoked token being presented again means it was stolen or
            # replayed: kill every session in that family.
            if session.revoked_at is not None:
                revoked = self.sessions.revoke_family(session.family_id)
                self._record(
                    AuditAction.REFRESH_REUSE_DETECTED,
                    context,
                    user_id=session.user_id,
                    details={"family_id": str(session.family_id), "sessions_revoked": revoked},
                )
                logger.warning(
                    "refresh_reuse_detected",
                    extra={"user_id": session.user_id, "sessions_revoked": revoked},
                )
            raise InvalidRefreshTokenError

        user = self.users.get_by_id(session.user_id)
        if user is None or not user.is_active:
            self.sessions.revoke_family(session.family_id)
            raise InvalidRefreshTokenError

        self.sessions.revoke(session)
        issued = self._issue_session(user, family_id=session.family_id, context=context)
        self._record(AuditAction.TOKEN_REFRESHED, context, user_id=user.id)
        return issued

    def logout(self, *, refresh_token: str | None, context: RequestContext) -> None:
        """Revoke the presented session. Always succeeds, so logout is idempotent."""
        if not refresh_token:
            return
        session = self.sessions.get_by_token_hash(hash_refresh_token(refresh_token))
        if session is None:
            return
        self.sessions.revoke(session)
        self._record(AuditAction.LOGOUT, context, user_id=session.user_id)
        logger.info("logout", extra={"user_id": session.user_id})

    def revoke_all_sessions(self, user: User) -> int:
        return self.sessions.revoke_all_for_user(user.id)

    # -- internals ---------------------------------------------------------

    def _issue_session(
        self, user: User, *, family_id: uuid.UUID, context: RequestContext
    ) -> IssuedSession:
        access_token, access_expires_at = create_access_token(
            user_id=user.id, role=str(user.role), settings=self.settings
        )
        refresh_token = generate_refresh_token()
        refresh_expires_at = datetime.now(UTC) + timedelta(
            days=self.settings.REFRESH_TOKEN_TTL_DAYS
        )
        self.sessions.add(
            user_id=user.id,
            token_hash=hash_refresh_token(refresh_token),
            family_id=family_id,
            expires_at=refresh_expires_at,
            user_agent=context.user_agent,
        )
        return IssuedSession(
            user=user,
            access_token=access_token,
            access_expires_at=access_expires_at,
            refresh_token=refresh_token,
            refresh_expires_at=refresh_expires_at,
            csrf_token=generate_csrf_token(),
        )

    def _record(
        self,
        action: AuditAction,
        context: RequestContext,
        *,
        user_id: int | None = None,
        details: dict[str, object] | None = None,
    ) -> None:
        self.audit.add(
            action=str(action),
            user_id=user_id,
            entity_type="user" if user_id else None,
            entity_id=str(user_id) if user_id else None,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            details=dict(details) if details else None,
        )


def active_session_count(db: Session, user: User) -> int:
    """Convenience for endpoints that report how many devices are signed in."""
    return len(RefreshSessionRepository(db).active_sessions_for_user(user.id))


__all__ = [
    "AccountAlreadyExistsError",
    "AccountInactiveError",
    "AuthService",
    "InvalidCredentialsError",
    "InvalidRefreshTokenError",
    "IssuedSession",
    "RefreshSession",
    "RequestContext",
    "active_session_count",
]
