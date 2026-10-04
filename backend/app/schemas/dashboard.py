"""Dashboard response schema.

Flat and explicit on purpose: every list is already in the order it should be
shown, and every count that could be zero is present as zero rather than
missing, so the interface draws what it is given and decides nothing.
"""

from datetime import datetime

from pydantic import BaseModel


class DashboardTotals(BaseModel):
    projects: int
    repositories: int
    # Repositories with at least one completed scan. The rest have no score.
    repositories_scanned: int
    scans_completed: int
    open_findings: int
    fixed_findings: int


class DashboardTrendPoint(BaseModel):
    scan_id: int
    score: float
    grade: str
    total_findings: int
    finished_at: datetime


class DashboardRepository(BaseModel):
    repository_id: int
    project_id: int
    project_name: str
    origin: str
    primary_language: str | None
    # Null until a scan has completed. Never scanned is not the same as clean.
    score: float | None
    grade: str | None
    open_findings: int
    fixed_findings: int
    counts_by_severity: dict[str, int]
    last_scan_at: datetime | None
    # Oldest first, one point per completed scan, as each scan recorded it.
    trend: list[DashboardTrendPoint]


class DashboardFinding(BaseModel):
    finding_id: int
    repository_id: int
    project_id: int
    project_name: str
    origin: str
    rule_id: str
    title: str
    severity: str
    cwe_id: str | None
    file_path: str
    line_start: int
    score: float
    # The multiplication written out, as on the repository page.
    explanation: str


class DashboardWeakness(BaseModel):
    cwe_id: str | None
    owasp_category: str | None
    title: str
    count: int
    worst_severity: str


class DashboardFixes(BaseModel):
    """What happened to every change that was asked for.

    ``requested = generating + refused + proposed`` and
    ``proposed = passed + rejected + not_judged + checking + unchecked``.
    Both are asserted by a test, so a count can always be traced to its rows.
    """

    requested: int
    generating: int
    refused: int
    proposed: int
    passed: int
    rejected: int
    not_judged: int
    checking: int
    unchecked: int
    # passed + rejected: proposals with a verdict from a re-scan.
    labelled: int


class DashboardRead(BaseModel):
    generated_at: datetime
    policy_version: int
    totals: DashboardTotals
    # Always all five severities, worst first.
    open_by_severity: dict[str, int]
    # Worst first; repositories that were never scanned come last.
    repositories: list[DashboardRepository]
    top_findings: list[DashboardFinding]
    weaknesses: list[DashboardWeakness]
    fixes: DashboardFixes


__all__ = [
    "DashboardFinding",
    "DashboardFixes",
    "DashboardRead",
    "DashboardRepository",
    "DashboardTotals",
    "DashboardTrendPoint",
    "DashboardWeakness",
]
