"""ORM models.

Every model must be imported here so that ``Base.metadata`` knows about it;
Alembic autogenerate imports this package to discover tables.
"""

from app.models.audit_log import AuditAction, AuditLog
from app.models.finding import Confidence, Finding, FindingStatus, Severity
from app.models.knowledge import KnowledgeChunk, KnowledgeDocument, KnowledgeSource
from app.models.project import Project
from app.models.refresh_session import RefreshSession
from app.models.repository import Repository, RepositorySource, RepositoryStatus
from app.models.scan import ACTIVE_STATUSES, Scan, ScanStatus
from app.models.user import User, UserRole

__all__ = [
    "AuditAction",
    "AuditLog",
    "Confidence",
    "ACTIVE_STATUSES",
    "Finding",
    "FindingStatus",
    "KnowledgeChunk",
    "KnowledgeDocument",
    "KnowledgeSource",
    "Project",
    "RefreshSession",
    "Repository",
    "RepositorySource",
    "RepositoryStatus",
    "Scan",
    "ScanStatus",
    "Severity",
    "User",
    "UserRole",
]
