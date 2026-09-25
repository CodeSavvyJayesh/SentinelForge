"""Finding request/response schemas.

``snippet`` is code from someone else's repository, already redacted by the
analyser. It travels as a plain JSON string and is rendered as text by the UI —
never as HTML, and never interpreted.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.finding import Confidence, Severity


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    repository_id: int
    rule_id: str
    analyzer: str
    title: str
    message: str
    severity: Severity
    confidence: Confidence
    cwe_id: str | None
    owasp_category: str | None
    file_path: str
    line_start: int
    line_end: int
    snippet: str
    fingerprint: str
    created_at: datetime


class FindingListResponse(BaseModel):
    items: list[FindingRead]
    total: int
    # Counts for the whole repository, not just this page: a severity filter
    # must not change the numbers the summary shows.
    by_severity: dict[str, int]
    limit: int
    offset: int


class AnalysisSummaryResponse(BaseModel):
    repository_id: int
    findings: int
    by_severity: dict[str, int]
    files_scanned: int
    files_skipped: int
    unparsable_files: int
    # True when the finding cap was reached; the list is partial and says so
    # rather than pretending it is complete.
    truncated: bool
    duration_ms: int
    analyzed_at: datetime
