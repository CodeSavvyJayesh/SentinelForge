"""One page of everything a user owns, and nothing they do not.

Every number here is counted from rows the earlier phases wrote. There is no
sample data, no placeholder and no figure that is filled in "until real data
exists": an account with nothing in it gets zeros and empty lists, and the
interface is responsible for saying so plainly.

Three decisions worth knowing before reading the code.

**A repository that has never been scanned has no score.** Not zero and not an
A. "Nothing found" and "never looked" are different facts, and a dashboard that
drew them the same way would reward not scanning.

**The current score is computed now; the trend is what each scan recorded.**
Same split as the repository page (see :mod:`app.services.risk_service`): the
live number moves with age, so the history has to be the frozen one.

**A patch is counted by its latest validation.** A proposal that was rejected,
re-checked after a re-scan and passed is one passed proposal, not one of each.
Proposals that could not be judged (the stored code had moved) are counted
separately and are never added to either verdict — they say nothing about the
change, which is also why they are not usable as training labels.
"""

from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.models import (
    ACTIVE_PATCH_STATUSES,
    ACTIVE_VALIDATION_STATUSES,
    Finding,
    FindingStatus,
    PatchStatus,
    PatchValidationStatus,
    Project,
    Repository,
    Scan,
    Severity,
    User,
)
from app.repositories.dashboard_repository import DashboardRepository
from app.risk import policy
from app.risk.scoring import FindingRisk, aggregate, score_finding

SEVERITY_ORDER = tuple(str(severity) for severity in Severity)
TREND_POINTS = 12
TOP_FINDINGS = 8
TOP_WEAKNESSES = 6


@dataclass(frozen=True)
class TrendPoint:
    scan_id: int
    score: float
    grade: str
    total_findings: int
    finished_at: datetime


@dataclass(frozen=True)
class RepositorySummary:
    repository: Repository
    project: Project
    # None until a scan has completed: never scanned is not the same as clean.
    score: float | None
    grade: str | None
    open_findings: int
    fixed_findings: int
    counts_by_severity: dict[str, int]
    last_scan_at: datetime | None
    trend: list[TrendPoint]


@dataclass(frozen=True)
class RankedFinding:
    finding: Finding
    repository: Repository
    project: Project
    risk: FindingRisk


@dataclass(frozen=True)
class Weakness:
    cwe_id: str | None
    owasp_category: str | None
    # The commonest finding title in the group: a CWE number alone tells a
    # reader nothing, and the knowledge base is not consulted for a count.
    title: str
    count: int
    worst_severity: str


@dataclass(frozen=True)
class FixOutcomes:
    requested: int = 0
    generating: int = 0
    # The model's answer was thrown away before it became a proposal.
    refused: int = 0
    proposed: int = 0
    # Of the proposals, by their latest check:
    passed: int = 0
    rejected: int = 0
    not_judged: int = 0
    checking: int = 0
    unchecked: int = 0

    @property
    def labelled(self) -> int:
        """Proposals with a verdict — the examples a classifier could learn from."""
        return self.passed + self.rejected


@dataclass(frozen=True)
class Dashboard:
    generated_at: datetime
    policy_version: int
    projects: int
    repositories_total: int
    repositories_scanned: int
    scans_completed: int
    open_findings: int
    fixed_findings: int
    open_by_severity: dict[str, int]
    repositories: list[RepositorySummary] = field(default_factory=list)
    top_findings: list[RankedFinding] = field(default_factory=list)
    weaknesses: list[Weakness] = field(default_factory=list)
    fixes: FixOutcomes = field(default_factory=FixOutcomes)


class DashboardService:
    def __init__(self, db: Session) -> None:
        self.queries = DashboardRepository(db)

    def for_user(self, user: User, *, now: datetime | None = None) -> Dashboard:
        # One clock for the whole page, so two repositories are never compared
        # using ages measured a few milliseconds apart.
        now = now or datetime.now(UTC)
        owned = self.queries.repositories(user.id)
        findings = self.queries.findings(user.id)
        scans = self.queries.completed_scans(user.id)

        findings_by_repository: dict[int, list[Finding]] = {}
        for finding in findings:
            findings_by_repository.setdefault(finding.repository_id, []).append(finding)
        scans_by_repository: dict[int, list[Scan]] = {}
        for scan in scans:
            scans_by_repository.setdefault(scan.repository_id, []).append(scan)

        summaries = [
            _summarise(
                repository,
                project,
                findings_by_repository.get(repository.id, []),
                scans_by_repository.get(repository.id, []),
                now,
            )
            for repository, project in owned
        ]
        # Worst first. Unscanned repositories last: they have no score to rank
        # by, and putting them at the top would bury the ones that do.
        summaries.sort(
            key=lambda item: (
                item.score is None,
                -(item.score or 0.0),
                item.repository.id,
            )
        )

        open_findings = [item for item in findings if item.status is not FindingStatus.FIXED]
        severity_counts = Counter(str(item.severity) for item in open_findings)
        homes = {repository.id: (repository, project) for repository, project in owned}

        return Dashboard(
            generated_at=now,
            policy_version=policy.POLICY_VERSION,
            projects=self.queries.project_count(user.id),
            repositories_total=len(owned),
            repositories_scanned=sum(1 for item in summaries if item.score is not None),
            scans_completed=len(scans),
            open_findings=len(open_findings),
            fixed_findings=len(findings) - len(open_findings),
            # Every severity is always present, so a chart never has to guess
            # whether a missing key means zero.
            open_by_severity={key: severity_counts.get(key, 0) for key in SEVERITY_ORDER},
            repositories=summaries,
            top_findings=_rank(open_findings, homes, now),
            weaknesses=_weaknesses(open_findings),
            fixes=_fix_outcomes(self.queries.patch_outcomes(user.id)),
        )


def _summarise(
    repository: Repository,
    project: Project,
    findings: list[Finding],
    scans: list[Scan],
    now: datetime,
) -> RepositorySummary:
    risk = aggregate(findings, now=now, top=0)
    scanned = bool(scans)
    fixed = sum(1 for item in findings if item.status is FindingStatus.FIXED)
    trend = [
        TrendPoint(
            scan_id=scan.id,
            score=scan.risk_score,
            grade=scan.risk_grade or "?",
            total_findings=scan.total_findings,
            finished_at=scan.finished_at,
        )
        for scan in scans
        # Scans from before scoring existed have no score. Skipped, not drawn
        # as zero: a bar at the bottom would invent an improvement.
        if scan.risk_score is not None and scan.finished_at is not None
    ][-TREND_POINTS:]
    return RepositorySummary(
        repository=repository,
        project=project,
        score=risk.score if scanned else None,
        grade=risk.grade if scanned else None,
        # Counted here rather than taken from the aggregate, which counts what
        # scores above zero: the rows of this table must add up to the total.
        open_findings=len(findings) - fixed,
        fixed_findings=fixed,
        counts_by_severity={key: risk.counts_by_severity.get(key, 0) for key in SEVERITY_ORDER},
        last_scan_at=scans[-1].finished_at if scans else None,
        trend=trend,
    )


def _rank(
    findings: list[Finding],
    homes: dict[int, tuple[Repository, Project]],
    now: datetime,
) -> list[RankedFinding]:
    scored = [(score_finding(finding, now=now), finding) for finding in findings]
    # Ties broken by id so two requests return the same order.
    scored.sort(key=lambda pair: (-pair[0].score, pair[1].id))
    ranked = []
    for risk, finding in scored[:TOP_FINDINGS]:
        repository, project = homes[finding.repository_id]
        ranked.append(
            RankedFinding(finding=finding, repository=repository, project=project, risk=risk)
        )
    return ranked


def _weaknesses(findings: list[Finding]) -> list[Weakness]:
    groups: dict[str | None, list[Finding]] = {}
    for finding in findings:
        groups.setdefault(finding.cwe_id, []).append(finding)

    weaknesses = []
    for cwe_id, members in groups.items():
        titles = Counter(item.title for item in members)
        categories = Counter(item.owasp_category for item in members if item.owasp_category)
        weaknesses.append(
            Weakness(
                cwe_id=cwe_id,
                owasp_category=categories.most_common(1)[0][0] if categories else None,
                # Commonest title, alphabetical on a tie, so the answer is stable.
                title=min(titles, key=lambda title: (-titles[title], title)),
                count=len(members),
                worst_severity=min(
                    (str(item.severity) for item in members), key=SEVERITY_ORDER.index
                ),
            )
        )
    weaknesses.sort(key=lambda item: (-item.count, item.cwe_id or ""))
    return weaknesses[:TOP_WEAKNESSES]


def _fix_outcomes(
    rows: list[tuple[int, PatchStatus, PatchValidationStatus | None]],
) -> FixOutcomes:
    counts: Counter[str] = Counter()
    for _patch_id, status, validation in rows:
        counts["requested"] += 1
        if status in ACTIVE_PATCH_STATUSES:
            counts["generating"] += 1
        elif status is PatchStatus.FAILED:
            counts["refused"] += 1
        else:
            counts["proposed"] += 1
            if validation is None:
                counts["unchecked"] += 1
            elif validation in ACTIVE_VALIDATION_STATUSES:
                counts["checking"] += 1
            elif validation is PatchValidationStatus.PASSED:
                counts["passed"] += 1
            elif validation is PatchValidationStatus.REJECTED:
                counts["rejected"] += 1
            else:
                counts["not_judged"] += 1
    return FixOutcomes(**counts)


__all__ = [
    "Dashboard",
    "DashboardService",
    "FixOutcomes",
    "RankedFinding",
    "RepositorySummary",
    "TrendPoint",
    "Weakness",
]
