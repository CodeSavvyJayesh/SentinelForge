"""Database writes for the append-only audit log."""

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditLog


class AuditLogRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def add(
        self,
        *,
        action: str,
        user_id: int | None = None,
        entity_type: str | None = None,
        entity_id: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditLog:
        entry = AuditLog(
            action=action,
            user_id=user_id,
            entity_type=entity_type,
            entity_id=entity_id,
            ip_address=ip_address,
            user_agent=user_agent[:255] if user_agent else None,
            request_id=request_id,
            details=details,
        )
        self.db.add(entry)
        self.db.flush()
        return entry

    def list_recent(self, *, limit: int = 50) -> list[AuditLog]:
        statement = select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)
        return list(self.db.scalars(statement))
