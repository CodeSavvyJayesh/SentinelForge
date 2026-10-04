"""Scanning a folder and building its report, with no database involved.

The web application stores findings as rows and builds a report from the rows.
Here there are no rows, so the analyser's findings are wrapped in the same
model objects — never added to a session, never flushed — and handed to the
same report builder. One builder means a pipeline's report and the web
application's report of the same code say the same thing.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from fnmatch import fnmatchcase
from pathlib import Path

from app.analysis.engine import AnalysisResult, analyze_workspace
from app.analysis.findings import Finding as AnalysisFinding
from app.core.config import Settings
from app.models import (
    Finding,
    FindingStatus,
    Project,
    Repository,
    RepositorySource,
    RepositoryStatus,
    Scan,
    ScanStatus,
)
from app.reports.model import Report, build_report


@dataclass(frozen=True)
class ScanOptions:
    name: str
    origin: str
    branch: str | None = None
    commit: str | None = None
    excludes: tuple[str, ...] = ()
    max_file_bytes: int | None = None
    max_findings: int | None = None


@dataclass(frozen=True)
class ScanOutcome:
    report: Report
    # Findings dropped because their path matched an --exclude pattern. Counted
    # and reported: an exclusion nobody can see is how a gate is quietly emptied.
    excluded: int


def is_excluded(file_path: str, patterns: tuple[str, ...]) -> bool:
    """True when a repository-relative path matches an exclusion.

    A pattern is either a glob over the whole path (``**/fixtures/*.py``,
    ``*.min.js``) or a directory prefix (``tests`` or ``tests/`` excludes
    everything under ``tests/``). Matching is case-sensitive and uses forward
    slashes on every platform, so one pattern means one thing everywhere.
    """
    for pattern in patterns:
        cleaned = pattern.strip().replace("\\", "/").lstrip("./").rstrip("/")
        if file_path == cleaned or file_path.startswith(f"{cleaned}/"):
            return True
        if fnmatchcase(file_path, cleaned) or fnmatchcase(file_path, f"{cleaned}/*"):
            return True
    return False


def analysis_settings(options: ScanOptions) -> Settings:
    """Settings for the analyser alone.

    Built without validation and without reading the environment or a ``.env``
    file: the application's settings require a database URL and a signing key,
    and a scan in a pipeline has neither and needs neither. Only the two
    analyser limits are ever read from this object.
    """
    overrides: dict[str, int] = {}
    if options.max_file_bytes is not None:
        overrides["ANALYSIS_MAX_FILE_BYTES"] = options.max_file_bytes
    if options.max_findings is not None:
        overrides["ANALYSIS_MAX_FINDINGS"] = options.max_findings
    return Settings.model_construct(**overrides)


def scan(root: Path, options: ScanOptions, *, now: datetime | None = None) -> ScanOutcome:
    now = now or datetime.now(UTC)
    result = analyze_workspace(root, analysis_settings(options))
    kept = [item for item in result.findings if not is_excluded(item.file_path, options.excludes)]
    return ScanOutcome(
        report=_report(result, kept, options, now),
        excluded=len(result.findings) - len(kept),
    )


def _report(
    result: AnalysisResult, findings: list[AnalysisFinding], options: ScanOptions, now: datetime
) -> Report:
    repository = Repository(
        id=0,
        project_id=0,
        source=RepositorySource.UPLOAD,
        status=RepositoryStatus.READY,
        origin=options.origin,
        branch=options.branch,
        commit_hash=options.commit,
    )
    project = Project(id=0, owner_id=0, name=options.name)
    completed = Scan(
        id=0,
        repository_id=0,
        status=ScanStatus.COMPLETED,
        finished_at=now,
        duration_ms=result.duration_ms,
        files_scanned=result.files_scanned,
        files_skipped=result.files_skipped,
        unparsable_files=result.unparsable_files,
        truncated=result.truncated,
    )
    rows = [
        Finding(
            id=number,
            repository_id=0,
            rule_id=item.rule_id,
            analyzer=item.analyzer,
            title=item.title,
            message=item.message,
            severity=item.severity,
            confidence=item.confidence,
            cwe_id=item.cwe_id,
            owasp_category=item.owasp_category,
            file_path=item.file_path,
            line_start=item.line_start,
            line_end=item.line_end,
            snippet=item.snippet,
            fingerprint=item.fingerprint,
            # Every finding of a one-off scan is being seen for the first time
            # as far as this run knows, and has been open for no time at all.
            status=FindingStatus.NEW,
            created_at=now,
        )
        for number, item in enumerate(findings, start=1)
    ]
    return build_report(
        repository=repository,
        project=project,
        scan=completed,
        findings=rows,
        patches={},
        now=now,
        tool_version=Settings.model_fields["APP_VERSION"].default,
    )


__all__ = ["ScanOptions", "ScanOutcome", "analysis_settings", "is_excluded", "scan"]
