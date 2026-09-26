"""Queueing scans, running them, and keeping the finding lifecycle honest.

Two callers, deliberately separated:

* **The API** calls :meth:`ScanService.queue`. It checks ownership, refuses a
  second scan of a repository that is already being scanned, writes a `QUEUED`
  row and returns immediately. No analysis happens inside the request.
* **The worker** calls :meth:`ScanService.run`. It has no user, so every query
  it makes is unscoped by design — it is trusted code acting on a row the API
  already authorised.

The lifecycle rule, in one sentence: **a finding row survives across scans, and
the scan changes its status.** Phase 5 deleted and re-inserted findings on every
run, which made "you fixed two things" impossible to say — the fixed ones simply
vanished.
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
    FindingStatus,
    Repository,
    RepositoryStatus,
    Scan,
    ScanStatus,
    Severity,
    User,
)
from app.repositories.audit_log_repository import AuditLogRepository
from app.repositories.finding_repository import FindingRepository
from app.repositories.repository_repository import RepositoryRepository
from app.repositories.scan_repository import ScanRepository
from app.risk.scoring import aggregate
from app.services.auth_service import RequestContext
from app.services.repository_service import RepositoryNotFoundError

logger = get_logger("sentinelforge.scans")


class ScanNotFoundError(AppError):
    def __init__(self) -> None:
        super().__init__("SCAN_NOT_FOUND", "Scan not found", status_code=HTTPStatus.NOT_FOUND)


class ScanAlreadyRunningError(AppError):
    """One scan at a time per repository.

    Two scans writing the same findings would race, and the loser's results
    would be silently overwritten — including its idea of what is fixed.
    """

    def __init__(self, scan_id: int) -> None:
        super().__init__(
            "SCAN_ALREADY_RUNNING",
            f"A scan of this repository is already in progress (scan {scan_id})",
            status_code=HTTPStatus.CONFLICT,
        )


class RepositoryNotScannableError(AppError):
    def __init__(self, reason: str) -> None:
        super().__init__("REPOSITORY_NOT_SCANNABLE", reason, status_code=HTTPStatus.CONFLICT)


@dataclass
class LifecycleCounts:
    total: int = 0
    new: int = 0
    fixed: int = 0


class ScanService:
    def __init__(self, db: Session, settings: Settings) -> None:
        self.db = db
        self.settings = settings
        self.scans = ScanRepository(db)
        self.repositories = RepositoryRepository(db)
        self.findings = FindingRepository(db)
        self.audit = AuditLogRepository(db)
        self.workspaces = WorkspaceManager(settings)

    # -- API side ----------------------------------------------------------

    def queue(self, repository_id: int, user: User, context: RequestContext) -> Scan:
        repository = self._owned_repository(repository_id, user)
        self._assert_scannable(repository)

        active = self.scans.active_for_repository(repository.id)
        if active is not None:
            raise ScanAlreadyRunningError(active.id)

        scan = self.scans.add(
            Scan(
                repository_id=repository.id,
                triggered_by_id=user.id,
                status=ScanStatus.QUEUED,
            )
        )
        self.audit.add(
            action=str(AuditAction.SCAN_QUEUED),
            user_id=user.id,
            entity_type="scan",
            entity_id=str(scan.id),
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            details={"repository_id": repository.id},
        )
        logger.info(
            "scan_queued",
            extra={"scan_id": scan.id, "repository_id": repository.id, "user_id": user.id},
        )
        return scan

    def get(self, scan_id: int, user: User) -> Scan:
        scan = self.scans.get_for_owner(scan_id, user.id)
        if scan is None:
            raise ScanNotFoundError
        return scan

    def list_for_repository(
        self, repository_id: int, user: User, *, limit: int = 20, offset: int = 0
    ) -> tuple[list[Scan], int]:
        repository = self._owned_repository(repository_id, user)
        return (
            self.scans.list_for_repository(repository.id, limit=limit, offset=offset),
            self.scans.count_for_repository(repository.id),
        )

    # -- worker side -------------------------------------------------------

    def run(self, scan: Scan) -> None:
        """Analyse the repository this scan points at, and record what happened.

        Called by the worker with the scan already claimed (status RUNNING).
        Any exception is caught and written to the row: a worker that dies on a
        bad repository would stop processing every other repository too.
        """
        started = datetime.now(UTC)
        repository = self.repositories.get(scan.repository_id)
        try:
            if repository is None:
                raise RepositoryNotScannableError("The repository no longer exists")
            workspace = self._workspace_for(repository)
            result = analyze_workspace(workspace, self.settings)
            counts = self._apply_lifecycle(scan, repository, result.findings)

            scan.status = ScanStatus.COMPLETED
            scan.files_scanned = result.files_scanned
            scan.files_skipped = result.files_skipped
            scan.unparsable_files = result.unparsable_files
            scan.truncated = result.truncated
            scan.total_findings = counts.total
            scan.new_findings = counts.new
            scan.fixed_findings = counts.fixed

            # Phase 9: freeze what this run judged the repository to be worth
            # worrying about. Computed here, at the end of the run, from the
            # findings as they now stand — so the number belongs to the scan
            # rather than to whenever somebody next opens the page.
            risk = aggregate(self.findings.list_all(repository.id))
            scan.risk_score = risk.score
            scan.risk_grade = risk.grade
            scan.risk_policy_version = risk.policy_version
            repository.analyzed_at = started
            self._finish(scan, started)
            self._record(
                AuditAction.SCAN_COMPLETED,
                scan,
                details={
                    "repository_id": scan.repository_id,
                    "total": counts.total,
                    "new": counts.new,
                    "fixed": counts.fixed,
                    "risk_score": risk.score,
                    "risk_grade": risk.grade,
                },
            )
            logger.info(
                "scan_completed",
                extra={
                    "scan_id": scan.id,
                    "repository_id": scan.repository_id,
                    "total_findings": counts.total,
                    "new_findings": counts.new,
                    "fixed_findings": counts.fixed,
                    "risk_score": risk.score,
                    "risk_grade": risk.grade,
                    "duration_ms": scan.duration_ms,
                },
            )
        except AppError as error:
            self._fail(scan, started, error.message, error.code)
        except Exception:  # noqa: BLE001 - the worker must survive anything
            # The message is generic on purpose: an exception string can carry
            # a path or a fragment of the analysed code.
            logger.exception("scan_crashed", extra={"scan_id": scan.id})
            self._fail(scan, started, "The scan failed unexpectedly", "SCAN_CRASHED")

    # -- lifecycle ---------------------------------------------------------

    def _apply_lifecycle(
        self, scan: Scan, repository: Repository, engine_findings: list[EngineFinding]
    ) -> LifecycleCounts:
        """Merge this run's findings into the repository's existing ones."""
        existing = {row.fingerprint: row for row in self.findings.list_all(repository.id)}
        counts = LifecycleCounts()
        seen: set[str] = set()

        for item in engine_findings:
            seen.add(item.fingerprint)
            row = existing.get(item.fingerprint)
            if row is None:
                self.findings.add(self._to_row(repository.id, scan.id, item))
                counts.new += 1
                continue

            # Still here. A finding that was FIXED and has come back is a
            # regression, and counts as new again — silently calling it OPEN
            # would hide that the fix was reverted.
            if row.status is FindingStatus.FIXED:
                row.status = FindingStatus.NEW
                row.fixed_in_scan_id = None
                row.first_seen_scan_id = scan.id
                counts.new += 1
            else:
                row.status = FindingStatus.OPEN
            row.last_seen_scan_id = scan.id
            # The code may have moved, and the rules may have changed.
            row.line_start = item.line_start
            row.line_end = item.line_end
            row.severity = Severity(str(item.severity))
            row.confidence = Confidence(str(item.confidence))
            row.message = item.message
            row.snippet = item.snippet

        for fingerprint, row in existing.items():
            if fingerprint in seen or row.status is FindingStatus.FIXED:
                continue
            row.status = FindingStatus.FIXED
            row.fixed_in_scan_id = scan.id
            counts.fixed += 1

        counts.total = len(seen)
        self.db.flush()
        return counts

    # -- internals ---------------------------------------------------------

    def _owned_repository(self, repository_id: int, user: User) -> Repository:
        repository = self.repositories.get_for_owner(repository_id, user.id)
        if repository is None:
            raise RepositoryNotFoundError
        return repository

    def _assert_scannable(self, repository: Repository) -> None:
        if repository.status is not RepositoryStatus.READY or not repository.workspace_path:
            raise RepositoryNotScannableError(
                "This repository has no ingested code to scan. Upload or clone it again first."
            )

    def _workspace_for(self, repository: Repository):  # noqa: ANN202 - Path
        self._assert_scannable(repository)
        workspace = self.workspaces.absolute(repository.workspace_path or "")
        if not workspace.is_dir():
            raise RepositoryNotScannableError(
                "The stored copy of this repository is missing from the server. "
                "Connect the code again."
            )
        return workspace

    def _finish(self, scan: Scan, started: datetime) -> None:
        scan.finished_at = datetime.now(UTC)
        scan.duration_ms = int((scan.finished_at - started).total_seconds() * 1000)
        self.db.flush()

    def _fail(self, scan: Scan, started: datetime, message: str, code: str) -> None:
        scan.status = ScanStatus.FAILED
        scan.error_message = message
        self._finish(scan, started)
        self._record(
            AuditAction.SCAN_FAILED,
            scan,
            details={"repository_id": scan.repository_id, "reason": code},
        )
        logger.warning(
            "scan_failed",
            extra={"scan_id": scan.id, "repository_id": scan.repository_id, "reason": code},
        )

    def _record(self, action: AuditAction, scan: Scan, *, details: dict[str, object]) -> None:
        self.audit.add(
            action=str(action),
            user_id=scan.triggered_by_id,
            entity_type="scan",
            entity_id=str(scan.id),
            ip_address=None,  # the worker has no request
            user_agent=None,
            request_id=None,
            details=details,
        )

    def _to_row(self, repository_id: int, scan_id: int, finding: EngineFinding) -> Finding:
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
            status=FindingStatus.NEW,
            first_seen_scan_id=scan_id,
            last_seen_scan_id=scan_id,
        )


__all__ = [
    "LifecycleCounts",
    "RepositoryNotScannableError",
    "ScanAlreadyRunningError",
    "ScanNotFoundError",
    "ScanService",
]
