"""Running the analysis, and storing what it found.

Ownership works exactly as it does everywhere else: the repository is resolved
through its project's owner, so someone else's code is a 404, not a 403.

Two rules specific to this phase:

* **Analysis never runs on code that is not there.** A repository that failed
  to ingest, or whose workspace has been removed, is refused with a message
  that says so, rather than reporting "0 findings" — which would read as
  "clean" and be a lie.
* **Re-analysis replaces.** The findings describe the code as it is now. A
  fixed vulnerability disappears on the next run instead of lingering as a
  false accusation.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from http import HTTPStatus

from sqlalchemy.orm import Session

from app.analysis.engine import analyze_workspace
from app.analysis.findings import Finding as EngineFinding
from app.core.config import Settings
from app.core.errors import AppError
from app.core.logging import get_logger
from app.ingestion.workspace import WorkspaceManager
from app.models import (
    AuditAction,
    Confidence,
    Finding,
    Repository,
    RepositoryStatus,
    Severity,
    User,
)
from app.repositories.audit_log_repository import AuditLogRepository
from app.repositories.finding_repository import FindingRepository
from app.repositories.repository_repository import RepositoryRepository
from app.services.auth_service import RequestContext
from app.services.repository_service import RepositoryNotFoundError

logger = get_logger("sentinelforge.analysis.service")


class RepositoryNotAnalysableError(AppError):
    """The repository exists and is yours, but there is nothing to analyse."""

    def __init__(self, reason: str) -> None:
        super().__init__("REPOSITORY_NOT_ANALYSABLE", reason, status_code=HTTPStatus.CONFLICT)


class FindingNotFoundError(AppError):
    def __init__(self) -> None:
        super().__init__("FINDING_NOT_FOUND", "Finding not found", status_code=HTTPStatus.NOT_FOUND)


@dataclass(frozen=True)
class AnalysisSummary:
    repository_id: int
    findings: int
    by_severity: dict[str, int]
    files_scanned: int
    files_skipped: int
    unparsable_files: int
    truncated: bool
    duration_ms: int
    analyzed_at: datetime


@dataclass(frozen=True)
class FindingPage:
    items: list[Finding]
    total: int
    by_severity: dict[str, int]
    limit: int
    offset: int


class AnalysisService:
    def __init__(self, db: Session, settings: Settings) -> None:
        self.db = db
        self.settings = settings
        self.repositories = RepositoryRepository(db)
        self.findings = FindingRepository(db)
        self.audit = AuditLogRepository(db)
        self.workspaces = WorkspaceManager(settings)

    # -- reads -------------------------------------------------------------

    def list_findings(
        self,
        repository_id: int,
        user: User,
        *,
        severity: Severity | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> FindingPage:
        repository = self._owned_repository(repository_id, user)
        return FindingPage(
            items=self.findings.list_for_repository(
                repository.id, severity=severity, limit=limit, offset=offset
            ),
            total=self.findings.count_for_repository(repository.id, severity),
            by_severity=self.findings.counts_by_severity(repository.id),
            limit=limit,
            offset=offset,
        )

    def get_finding(self, finding_id: int, user: User) -> Finding:
        finding = self.findings.get_for_owner(finding_id, user.id)
        if finding is None:
            raise FindingNotFoundError
        return finding

    # -- writes ------------------------------------------------------------

    def analyze(self, repository_id: int, user: User, context: RequestContext) -> AnalysisSummary:
        repository = self._owned_repository(repository_id, user)
        workspace = self._workspace_for(repository)

        result = analyze_workspace(workspace, self.settings)

        self.findings.replace_all(
            repository.id, [self._to_row(repository.id, item) for item in result.findings]
        )
        analyzed_at = datetime.now(UTC)
        repository.analyzed_at = analyzed_at
        self.db.flush()

        self.audit.add(
            action=str(AuditAction.REPOSITORY_ANALYZED),
            user_id=user.id,
            entity_type="repository",
            entity_id=str(repository.id),
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            # Counts, never the findings themselves: an audit log is not a
            # place to reproduce someone's vulnerable code.
            details={
                "findings": len(result.findings),
                "files_scanned": result.files_scanned,
                "truncated": result.truncated,
            },
        )
        logger.info(
            "repository_analyzed",
            extra={
                "repository_id": repository.id,
                "user_id": user.id,
                "findings": len(result.findings),
                "files_scanned": result.files_scanned,
                "duration_ms": result.duration_ms,
            },
        )
        return AnalysisSummary(
            repository_id=repository.id,
            findings=len(result.findings),
            by_severity=result.counts_by_severity,
            files_scanned=result.files_scanned,
            files_skipped=result.files_skipped,
            unparsable_files=result.unparsable_files,
            truncated=result.truncated,
            duration_ms=result.duration_ms,
            analyzed_at=analyzed_at,
        )

    # -- internals ---------------------------------------------------------

    def _owned_repository(self, repository_id: int, user: User) -> Repository:
        repository = self.repositories.get_for_owner(repository_id, user.id)
        if repository is None:
            # Exactly the error Phase 4 raises for a repository that does not
            # exist. A stranger must not be able to tell the two apart.
            raise RepositoryNotFoundError
        return repository

    def _workspace_for(self, repository: Repository):  # noqa: ANN202 - Path
        if repository.status is not RepositoryStatus.READY or not repository.workspace_path:
            raise RepositoryNotAnalysableError(
                "This repository has no ingested code to analyse. Upload or clone it again first."
            )
        workspace = self.workspaces.absolute(repository.workspace_path)
        if not workspace.is_dir():
            raise RepositoryNotAnalysableError(
                "The stored copy of this repository is missing from the server. "
                "Connect the code again."
            )
        return workspace

    def _to_row(self, repository_id: int, finding: EngineFinding) -> Finding:
        return Finding(
            repository_id=repository_id,
            rule_id=finding.rule_id,
            analyzer=finding.analyzer,
            title=finding.title,
            message=finding.message,
            severity=Severity(str(finding.severity)),
            confidence=Confidence(str(finding.confidence)),
            cwe_id=finding.cwe_id,
            owasp_category=finding.owasp_category,
            file_path=finding.file_path,
            line_start=finding.line_start,
            line_end=finding.line_end,
            snippet=finding.snippet,
            fingerprint=finding.fingerprint,
        )


__all__ = [
    "AnalysisService",
    "AnalysisSummary",
    "FindingNotFoundError",
    "FindingPage",
    "RepositoryNotAnalysableError",
]
