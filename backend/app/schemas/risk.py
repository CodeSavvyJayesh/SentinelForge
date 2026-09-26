"""Risk request/response schemas.

Every response carries the arithmetic, not just the answer. ``factors`` on each
finding and ``policy_version`` on the total are what let a reader disagree with
a specific step instead of with the number as a whole — which is the only way a
risk model ever gets corrected.
"""

from datetime import datetime

from pydantic import BaseModel


class RiskFactor(BaseModel):
    name: str
    value: float
    reason: str


class FindingRiskRead(BaseModel):
    finding_id: int
    score: float
    base: float
    factors: list[RiskFactor]
    # The multiplication written out, so a tooltip does not have to rebuild it.
    explanation: str
    # Enough of the finding to recognise it without a second request.
    title: str
    severity: str
    file_path: str
    line_start: int


class RepositoryRiskRead(BaseModel):
    repository_id: int
    score: float
    grade: str
    policy_version: int
    # Findings that still count — fixed ones score zero and are excluded.
    finding_count: int
    counts_by_severity: dict[str, int]
    top: list[FindingRiskRead]


class RiskPointRead(BaseModel):
    """One scan's frozen score, for the trend line."""

    scan_id: int
    score: float
    grade: str
    policy_version: int | None
    total_findings: int
    finished_at: datetime


class RiskHistoryRead(BaseModel):
    repository_id: int
    # Oldest first: a chart reads left to right.
    points: list[RiskPointRead]


__all__ = [
    "FindingRiskRead",
    "RepositoryRiskRead",
    "RiskFactor",
    "RiskHistoryRead",
    "RiskPointRead",
]
