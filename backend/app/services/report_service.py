"""Building and exporting a repository's report.

A report is generated on request and never stored. It is a view of the current
rows, and a stored copy would be a second version of the truth that starts
going stale as soon as the next scan finishes. What *is* stored is that one was
generated: a report is the point at which findings leave this system, so who
took one, of what, and in which format goes in the audit log.

Ownership is checked once, here, before anything is read.
"""

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from http import HTTPStatus

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.errors import AppError
from app.core.logging import get_logger
from app.models import AuditAction, User
from app.reports import html as html_report
from app.reports import markdown as markdown_report
from app.reports import sarif as sarif_report
from app.reports.model import Report, build_report
from app.repositories.audit_log_repository import AuditLogRepository
from app.repositories.finding_repository import FindingRepository
from app.repositories.report_repository import ReportRepository
from app.repositories.repository_repository import RepositoryRepository
from app.repositories.scan_repository import ScanRepository
from app.schemas.report import ReportRead
from app.services.auth_service import RequestContext
from app.services.repository_service import RepositoryNotFoundError

logger = get_logger("sentinelforge.reports")


class ReportNotAvailableError(AppError):
    """There is nothing to report on until a scan has completed.

    Refused rather than answered with an empty report: a document that says
    "0 findings" about code nobody has analysed would be read as a clean bill
    of health by whoever it was forwarded to.
    """

    def __init__(self) -> None:
        super().__init__(
            "REPORT_NOT_AVAILABLE",
            "This repository has not been scanned yet. Scan it, then ask for the report.",
            status_code=HTTPStatus.CONFLICT,
        )


class ReportFormat(StrEnum):
    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"
    SARIF = "sarif"


EXTENSIONS = {
    ReportFormat.JSON: "json",
    ReportFormat.MARKDOWN: "md",
    ReportFormat.HTML: "html",
    ReportFormat.SARIF: "sarif",
}
MEDIA_TYPES = {
    ReportFormat.JSON: "application/json",
    ReportFormat.MARKDOWN: "text/markdown; charset=utf-8",
    ReportFormat.HTML: "text/html; charset=utf-8",
    ReportFormat.SARIF: "application/sarif+json",
}


@dataclass(frozen=True)
class ReportExport:
    format: ReportFormat
    filename: str
    media_type: str
    content: str


def filename_for(origin: str, generated_at: datetime, export_format: ReportFormat) -> str:
    """A download name built only from characters every filesystem accepts.

    ``origin`` is the name of an uploaded archive or a clone URL — text a user
    chose — and it ends up in a ``Content-Disposition`` header. Anything that is
    not a lowercase letter, a digit or a hyphen is dropped, which removes
    quotes, path separators and line breaks in one rule.
    """
    stem = origin.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    stem = re.sub(r"\.(git|zip)$", "", stem, flags=re.IGNORECASE)
    slug = re.sub(r"[^a-z0-9]+", "-", stem.lower()).strip("-")[:40].strip("-")
    date = generated_at.astimezone(UTC).strftime("%Y%m%d")
    return f"sentinelforge-{slug or 'repository'}-{date}.{EXTENSIONS[export_format]}"


class ReportService:
    def __init__(self, db: Session, settings: Settings) -> None:
        self.db = db
        self.settings = settings
        self.repositories = RepositoryRepository(db)
        self.findings = FindingRepository(db)
        self.scans = ScanRepository(db)
        self.queries = ReportRepository(db)
        self.audit = AuditLogRepository(db)

    def build(self, repository_id: int, user: User, *, now: datetime | None = None) -> Report:
        repository = self.repositories.get_for_owner(repository_id, user.id)
        if repository is None:
            raise RepositoryNotFoundError
        scan = self.scans.latest_for_repository(repository.id)
        if scan is None or scan.finished_at is None:
            raise ReportNotAvailableError
        return build_report(
            repository=repository,
            project=repository.project,
            scan=scan,
            findings=self.findings.list_all(repository.id),
            patches=self.queries.patch_states(repository.id),
            now=now or datetime.now(UTC),
            tool_version=self.settings.APP_VERSION,
        )

    def export(
        self,
        repository_id: int,
        user: User,
        export_format: ReportFormat,
        context: RequestContext,
        *,
        now: datetime | None = None,
    ) -> ReportExport:
        report = self.build(repository_id, user, now=now)
        content = render(report, export_format)
        self.audit.add(
            action=str(AuditAction.REPORT_EXPORTED),
            user_id=user.id,
            entity_type="repository",
            entity_id=str(report.repository_id),
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            details={
                "format": str(export_format),
                "scan_id": report.scan.id,
                "open_findings": report.open_count,
            },
        )
        logger.info(
            "report_exported",
            extra={
                "repository_id": report.repository_id,
                "user_id": user.id,
                "format": str(export_format),
            },
        )
        return ReportExport(
            format=export_format,
            filename=filename_for(report.origin, report.generated_at, export_format),
            media_type=MEDIA_TYPES[export_format],
            content=content,
        )


def render(report: Report, export_format: ReportFormat) -> str:
    if export_format is ReportFormat.MARKDOWN:
        return markdown_report.render(report)
    if export_format is ReportFormat.HTML:
        return html_report.render(report)
    if export_format is ReportFormat.SARIF:
        return json.dumps(sarif_report.render(report), indent=2, ensure_ascii=False) + "\n"
    return ReportRead.from_report(report).model_dump_json(indent=2) + "\n"


__all__ = [
    "EXTENSIONS",
    "MEDIA_TYPES",
    "ReportExport",
    "ReportFormat",
    "ReportNotAvailableError",
    "ReportService",
    "filename_for",
    "render",
]
