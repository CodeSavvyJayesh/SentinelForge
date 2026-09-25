"""Finding request/response schemas.

``snippet`` is code from someone else's repository, already redacted by the
analyser. It travels as a plain JSON string and is rendered as text by the UI —
never as HTML, and never interpreted.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.finding import Confidence, FindingStatus, Severity


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
    # Where this finding sits between scans, and which scans saw it.
    status: FindingStatus
    first_seen_scan_id: int | None
    last_seen_scan_id: int | None
    fixed_in_scan_id: int | None
    created_at: datetime


class FindingListResponse(BaseModel):
    items: list[FindingRead]
    total: int
    # Counts for the whole repository, not just this page: a filter must not
    # change the numbers the summary shows. Severity counts exclude fixed
    # findings — a CRITICAL you fixed last week is not still a CRITICAL.
    by_severity: dict[str, int]
    by_status: dict[str, int]
    limit: int
    offset: int
