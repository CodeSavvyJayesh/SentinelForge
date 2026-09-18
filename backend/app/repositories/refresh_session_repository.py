"""Database queries for refresh sessions."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.models import RefreshSession


class RefreshSessionRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def add(
        self,
        *,
        user_id: int,
        token_hash: str,
        family_id: uuid.UUID,
        expires_at: datetime,
        user_agent: str | None,
    ) -> RefreshSession:
        session = RefreshSession(
            user_id=user_id,
            token_hash=token_hash,
            family_id=family_id,
            expires_at=expires_at,
            user_agent=user_agent[:255] if user_agent else None,
        )
        self.db.add(session)
        self.db.flush()
        return session

    def get_by_token_hash(self, token_hash: str) -> RefreshSession | None:
        statement = select(RefreshSession).where(RefreshSession.token_hash == token_hash)
        return self.db.scalars(statement).first()

    def revoke(self, session: RefreshSession, *, now: datetime | None = None) -> None:
        session.revoked_at = now or datetime.now(UTC)
        self.db.flush()

    def revoke_family(self, family_id: uuid.UUID, *, now: datetime | None = None) -> int:
        """Revoke every live session in a family (used on refresh-token reuse)."""
        statement = (
            update(RefreshSession)
            .where(RefreshSession.family_id == family_id, RefreshSession.revoked_at.is_(None))
            .values(revoked_at=now or datetime.now(UTC))
        )
        result = self.db.execute(statement)
        self.db.flush()
        return result.rowcount or 0

    def revoke_all_for_user(self, user_id: int, *, now: datetime | None = None) -> int:
        statement = (
            update(RefreshSession)
            .where(RefreshSession.user_id == user_id, RefreshSession.revoked_at.is_(None))
            .values(revoked_at=now or datetime.now(UTC))
        )
        result = self.db.execute(statement)
        self.db.flush()
        return result.rowcount or 0

    def active_sessions_for_user(self, user_id: int) -> list[RefreshSession]:
        statement = select(RefreshSession).where(
            RefreshSession.user_id == user_id,
            RefreshSession.revoked_at.is_(None),
            RefreshSession.expires_at > datetime.now(UTC),
        )
        return list(self.db.scalars(statement))
