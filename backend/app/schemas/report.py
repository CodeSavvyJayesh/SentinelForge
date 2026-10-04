"""Report response schemas.

``ReportRead`` is the report as data — the same object the Markdown, HTML and
SARIF renderers are given, so a client that wants to draw its own report has
exactly what they had. ``ReportExportRead`` is a rendered document wrapped in
JSON, for a client that wants to save or preview one.
"""

from dataclasses import asdict
from datetime import datetime

from pydantic import BaseModel

from app.reports.model import Report


class ReportScanRead(BaseModel):
    id: int
    finished_at: datetime
    duration_ms: int | None
    files_scanned: int
    files_skipped: int
    unparsable_files: int
    truncated: bool


class ReportRuleRead(BaseModel):
    rule_id: str
    title: str
    count: int
    worst_severity: str
    cwe_id: str | None
    owasp_category: str | None
    risk_note: str | None
    fix_note: str | None


class ReportFindingRead(BaseModel):
    id: int
    rule_id: str
    title: str
    message: str
    severity: str
    confidence: str
    cwe_id: str | None
    owasp_category: str | None
    file_path: str
    line_start: int
    line_end: int
    snippet: str
    status: str
    fingerprint: str
    is_credential: bool
    score: float
    score_explanation: str
    fix_state: str
    fix_label: str


class ReportRead(BaseModel):
    tool_name: str
    tool_version: str
    policy_version: int
    generated_at: datetime
    project_name: str
    repository_id: int
    origin: str
    branch: str | None
    commit_hash: str | None
    primary_language: str | None
    scan: ReportScanRead
    score: float
    grade: str
    grade_label: str
    open_count: int
    new_count: int
    fixed_count: int
    counts_by_severity: dict[str, int]
    rules: list[ReportRuleRead]
    findings: list[ReportFindingRead]
    fixed: list[ReportFindingRead]
    limitations: list[str]

    @classmethod
    def from_report(cls, report: Report) -> "ReportRead":
        return cls.model_validate(asdict(report))


class ReportExportRead(BaseModel):
    format: str
    filename: str
    media_type: str
    content: str


__all__ = [
    "ReportExportRead",
    "ReportFindingRead",
    "ReportRead",
    "ReportRuleRead",
    "ReportScanRead",
]
