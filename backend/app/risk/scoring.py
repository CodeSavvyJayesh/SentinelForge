"""Turning findings into numbers, and showing the working.

Pure functions over plain data. Nothing here touches the database, the network
or a model, which is what makes a score reproducible: the same finding and the
same policy produce the same number today, next month, and on somebody else's
machine.

**Every score carries its factors.** That is not a debugging convenience — it is
the feature. A reviewer told "this is 34" can only accept or ignore it. A
reviewer shown ``40 base × 0.8 confidence × 0.4 test path × 1.06 age`` can
disagree with a specific step, and disagreement is how a risk model gets better.
It is also the difference between a number this project can defend and one it
merely produces.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import PurePosixPath

from app.models import Finding, FindingStatus, Severity
from app.risk import policy


@dataclass(frozen=True)
class Factor:
    """One multiplier, with the reason it applied."""

    name: str
    value: float
    reason: str


@dataclass(frozen=True)
class FindingRisk:
    finding_id: int
    score: float
    base: float
    factors: list[Factor] = field(default_factory=list)

    @property
    def explanation(self) -> str:
        """The arithmetic as a sentence, for a report or a tooltip."""
        parts = [f"{self.base:g} base"]
        parts += [f"× {factor.value:g} {factor.name}" for factor in self.factors]
        return f"{' '.join(parts)} = {self.score:g}"


@dataclass(frozen=True)
class RepositoryRisk:
    score: float
    grade: str
    policy_version: int
    finding_count: int
    counts_by_severity: dict[str, int]
    # Worst first. The aggregate is built from this order, so showing it is
    # showing how the total was reached.
    top: list[FindingRisk] = field(default_factory=list)


def path_factor(finding: Finding) -> Factor:
    """How much the finding's location discounts it.

    Matched on path *segments*, never substrings: ``latest/`` contains "test"
    and has nothing to do with testing, and a scoring system that quietly
    discounted a whole directory because of a coincidence of spelling would be
    worse than one with no path heuristic at all.
    """
    # A credential is exposed wherever it lives. The path says nothing about
    # whether a committed key is real, so it gets no discount.
    if finding.rule_id.startswith(policy.CREDENTIAL_RULE_PREFIX):
        return Factor(
            "secret in any location",
            policy.SECRET_PATH_FACTOR,
            "a committed credential is exposed wherever it sits, including in tests",
        )

    segments = {segment.lower() for segment in PurePosixPath(finding.file_path).parts}
    # Filenames like `test_auth.py` and `auth.spec.ts` are the same signal.
    name = PurePosixPath(finding.file_path).name.lower()
    looks_like_test = any(name.startswith(prefix) for prefix in ("test_", "tests_")) or any(
        f".{marker}." in name or name.endswith(f"_{marker}.py") for marker in ("spec", "test")
    )

    if segments & policy.TEST_MARKERS or looks_like_test:
        return Factor("test path", policy.TEST_PATH_FACTOR, "in test or fixture code")
    if segments & policy.VENDORED_MARKERS:
        return Factor(
            "vendored path", policy.VENDORED_PATH_FACTOR, "in dependency or generated code"
        )
    if segments & policy.EXAMPLE_MARKERS:
        return Factor(
            "example path", policy.EXAMPLE_PATH_FACTOR, "in example or documentation code"
        )
    return Factor("application path", policy.DEFAULT_PATH_FACTOR, "in application code")


def age_factor(finding: Finding, *, now: datetime | None = None) -> Factor:
    """How long this has gone unaddressed, as a capped bonus.

    Uses the finding row's own creation time, which Phase 6 keeps stable across
    scans — a finding that survives ten scans keeps the date it was first seen,
    so this measures how long it has been *open* rather than how recently it was
    looked at.
    """
    created = finding.created_at
    if created is None:  # pragma: no cover - only before the row is flushed
        return Factor("age", 1.0, "not yet recorded")
    reference = now or datetime.now(UTC)
    if created.tzinfo is None:  # pragma: no cover - the column is timezone-aware
        created = created.replace(tzinfo=UTC)

    days = max(0.0, (reference - created).total_seconds() / 86_400)
    capped = min(days, policy.AGE_CAP_DAYS)
    value = 1.0 + (capped / policy.AGE_CAP_DAYS) * policy.MAX_AGE_BONUS
    return Factor("age", round(value, 3), f"open for {days:.0f} day{'' if days == 1 else 's'}")


def score_finding(finding: Finding, *, now: datetime | None = None) -> FindingRisk:
    """Score one finding, and record how.

    A FIXED finding scores zero. It is evidence that work was done, not an
    outstanding risk, and letting it contribute would mean a repository's score
    never improved no matter how much was fixed — which would make the number
    useless for the one thing it is for.
    """
    if finding.status is FindingStatus.FIXED:
        return FindingRisk(
            finding_id=finding.id,
            score=0.0,
            base=0.0,
            factors=[Factor("fixed", 0.0, "no longer present in the code")],
        )

    base = policy.SEVERITY_BASE.get(Severity(str(finding.severity)), 0.0)
    factors = [
        Factor(
            "confidence",
            policy.CONFIDENCE_FACTOR.get(str(finding.confidence), 1.0),
            f"{finding.confidence} confidence that this is a real match",
        ),
        path_factor(finding),
        age_factor(finding, now=now),
    ]

    # A finding that was fixed and returned. Phase 6 records this by marking it
    # NEW again while keeping the scan that fixed it, so the two are
    # distinguishable — a first occurrence is not a regression.
    if finding.status is FindingStatus.NEW and finding.fixed_in_scan_id is not None:
        factors.append(
            Factor("regression", policy.REGRESSION_FACTOR, "was fixed once and has come back")
        )

    score = base
    for factor in factors:
        score *= factor.value
    return FindingRisk(
        finding_id=finding.id,
        base=base,
        score=round(min(score, policy.MAX_SCORE), 1),
        factors=factors,
    )


def grade_for(score: float) -> str:
    for threshold, grade in policy.GRADE_THRESHOLDS:
        if score < threshold:
            return grade
    return policy.GRADE_THRESHOLDS[-1][1]  # pragma: no cover - the last band is open-ended


def aggregate(
    findings: list[Finding], *, now: datetime | None = None, top: int = 5
) -> RepositoryRisk:
    """Combine finding scores into one number for the repository.

    Geometric decay by rank: the worst finding counts fully, the second at 0.6,
    the third at 0.36, and so on. A plain sum would let a hundred INFO findings
    outrank one CRITICAL, which is how a score teaches people to ignore it;
    taking only the maximum would make a repository with thirty CRITICALs look
    exactly like one with a single one. Both are wrong in ways a reviewer would
    notice immediately, and the decay sits between them.
    """
    scored = [score_finding(finding, now=now) for finding in findings]
    live = sorted(
        (risk for risk in scored if risk.score > 0), key=lambda risk: risk.score, reverse=True
    )

    total = 0.0
    weight = 1.0
    for risk in live:
        total += risk.score * weight
        weight *= policy.RANK_DECAY

    score = round(min(total, policy.MAX_SCORE), 1)
    counts: dict[str, int] = {}
    for finding in findings:
        if finding.status is FindingStatus.FIXED:
            continue
        key = str(finding.severity)
        counts[key] = counts.get(key, 0) + 1

    return RepositoryRisk(
        score=score,
        grade=grade_for(score),
        policy_version=policy.POLICY_VERSION,
        finding_count=len(live),
        counts_by_severity=counts,
        top=live[:top],
    )


__all__ = [
    "Factor",
    "FindingRisk",
    "RepositoryRisk",
    "age_factor",
    "aggregate",
    "grade_for",
    "path_factor",
    "score_finding",
]
