"""Scoring findings.

A risk score is only worth having if it is reproducible and arguable, so these
tests pin two different kinds of claim, and the second kind matters more.

The first kind is arithmetic: given this finding, the number is that. Those
tests are exact, and they will need updating whenever the policy changes — which
is correct, because changing a policy constant *should* be a deliberate act that
shows up in a diff.

The second kind is **ordering**: a CRITICAL always outranks a HIGH, a test-file
finding always scores below the same finding in application code, a fixed
finding never contributes. Those hold whatever the constants are, and they are
the properties a reviewer actually relies on.
"""

from datetime import UTC, datetime, timedelta

from app.models import Confidence, Finding, FindingStatus, Severity
from app.risk import policy
from app.risk.scoring import aggregate, grade_for, path_factor, score_finding

NOW = datetime(2026, 9, 27, tzinfo=UTC)


def finding(**overrides) -> Finding:  # noqa: ANN003
    defaults = {
        "id": 1,
        "repository_id": 1,
        "rule_id": "PY010",
        "analyzer": "python-ast",
        "title": "SQL query built by string formatting",
        "message": "A value formatted into SQL can change the statement.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021 Injection",
        "file_path": "app/users.py",
        "line_start": 24,
        "line_end": 24,
        "snippet": "cursor.execute(f'...')",
        "fingerprint": "f1",
        "status": FindingStatus.OPEN,
        "created_at": NOW,
    }
    return Finding(**{**defaults, **overrides})


# --- the arithmetic -------------------------------------------------------


def test_a_fresh_high_confidence_critical_scores_its_base() -> None:
    """Nothing discounts it and nothing inflates it, so the number is the base."""
    risk = score_finding(finding(), now=NOW)
    assert risk.base == 40.0
    assert risk.score == 40.0


def test_confidence_scales_the_score() -> None:
    medium = score_finding(finding(confidence=Confidence.MEDIUM), now=NOW)
    low = score_finding(finding(confidence=Confidence.LOW), now=NOW)
    assert medium.score == 32.0  # 40 × 0.8
    assert low.score == 24.0  # 40 × 0.6


def test_the_explanation_shows_the_whole_multiplication() -> None:
    """A reviewer who cannot see the working can only accept or ignore the
    number, and neither is a review."""
    risk = score_finding(finding(confidence=Confidence.MEDIUM), now=NOW)
    assert "40 base" in risk.explanation
    assert "× 0.8 confidence" in risk.explanation
    assert risk.explanation.endswith("= 32")


def test_age_adds_a_capped_bonus() -> None:
    old = score_finding(finding(created_at=NOW - timedelta(days=365)), now=NOW)
    # Capped at the maximum bonus however old it gets.
    assert old.score == 50.0  # 40 × 1.25


def test_age_is_capped_rather_than_unbounded() -> None:
    """Otherwise a stale LOW eventually outranks a fresh CRITICAL, and the
    ordering stops meaning what a reader assumes it means."""
    year = score_finding(finding(created_at=NOW - timedelta(days=365)), now=NOW)
    decade = score_finding(finding(created_at=NOW - timedelta(days=3650)), now=NOW)
    assert year.score == decade.score


def test_a_regression_is_weighted_above_a_first_occurrence() -> None:
    """Phase 6 can tell a returning finding from a new one. A fix that was
    reverted says something about the process that a first sighting does not."""
    first = score_finding(finding(status=FindingStatus.NEW), now=NOW)
    again = score_finding(finding(status=FindingStatus.NEW, fixed_in_scan_id=7), now=NOW)
    assert again.score > first.score
    assert any(factor.name == "regression" for factor in again.factors)


def test_a_fixed_finding_scores_zero() -> None:
    """Otherwise a repository's score never improves no matter how much work is
    done, which makes the number useless for the one thing it is for."""
    risk = score_finding(finding(status=FindingStatus.FIXED), now=NOW)
    assert risk.score == 0.0


# --- ordering, which survives any policy change ---------------------------


def test_severity_ordering_holds() -> None:
    scores = [
        score_finding(finding(severity=level), now=NOW).score
        for level in (
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        )
    ]
    assert scores == sorted(scores, reverse=True)
    assert len(set(scores)) == len(scores), "each severity must be distinguishable"


def test_confidence_never_scores_a_finding_away() -> None:
    """A low-confidence CRITICAL is still worth a human's attention. Scoring it
    to zero would be the tool deciding on the reviewer's behalf."""
    assert score_finding(finding(confidence=Confidence.LOW), now=NOW).score > 0
    assert min(policy.CONFIDENCE_FACTOR.values()) > 0


def test_the_same_finding_scores_lower_in_a_test_file() -> None:
    app_code = score_finding(finding(file_path="app/users.py"), now=NOW)
    test_code = score_finding(finding(file_path="tests/test_users.py"), now=NOW)
    assert test_code.score < app_code.score
    assert test_code.score > 0, "reduced, never dismissed"


# --- the path heuristic ---------------------------------------------------


def test_path_matching_uses_segments_not_substrings() -> None:
    """ "latest/" contains "test" and has nothing to do with testing. A scoring
    system that quietly discounted a whole directory over a coincidence of
    spelling would be worse than one with no path heuristic at all."""
    assert path_factor(finding(file_path="latest/release.py")).value == 1.0
    assert path_factor(finding(file_path="src/contest/entry.py")).value == 1.0
    assert path_factor(finding(file_path="tests/helpers.py")).value == policy.TEST_PATH_FACTOR


def test_test_filenames_are_recognised_as_well_as_directories() -> None:
    for path in ("app/test_auth.py", "src/auth.spec.ts", "lib/auth.test.js"):
        assert path_factor(finding(file_path=path)).value == policy.TEST_PATH_FACTOR, path


def test_vendored_and_example_paths_are_discounted_differently() -> None:
    vendored = path_factor(finding(file_path="node_modules/x/index.js")).value
    example = path_factor(finding(file_path="examples/quickstart.py")).value
    assert vendored == policy.VENDORED_PATH_FACTOR
    assert example == policy.EXAMPLE_PATH_FACTOR
    assert vendored < 1.0 and example < 1.0


def test_a_committed_credential_is_not_discounted_by_its_location() -> None:
    """The path heuristic asks "is this code reachable". That question does not
    apply to a key: it is exposed to everyone who can read the repository
    wherever it sits, and it stays in git history after the line is deleted."""
    in_tests = path_factor(finding(rule_id="SEC001", file_path="tests/fixtures/aws.py"))
    assert in_tests.value == 1.0
    assert "exposed wherever" in in_tests.reason


def test_a_secret_in_a_test_file_outranks_an_ordinary_finding_there() -> None:
    secret = score_finding(
        finding(rule_id="SEC003", severity=Severity.CRITICAL, file_path="tests/conftest.py"),
        now=NOW,
    )
    ordinary = score_finding(
        finding(rule_id="PY010", severity=Severity.CRITICAL, file_path="tests/conftest.py"),
        now=NOW,
    )
    assert secret.score > ordinary.score


# --- grades ---------------------------------------------------------------


def test_grades_are_ordered_and_cover_the_whole_range() -> None:
    grades = [grade_for(score) for score in (0, 9.9, 10, 24.9, 25, 44.9, 45, 69.9, 70, 100)]
    assert grades == ["A", "A", "B", "B", "C", "C", "D", "D", "F", "F"]


# --- aggregation ----------------------------------------------------------


def make(count: int, severity: Severity, **overrides) -> list[Finding]:  # noqa: ANN003
    return [
        finding(id=index, fingerprint=f"f{index}", severity=severity, **overrides)
        for index in range(1, count + 1)
    ]


def test_one_critical_outranks_many_low_findings() -> None:
    """A plain sum would let a hundred INFO findings outrank one CRITICAL, which
    is how a scoring system teaches people to ignore it."""
    critical = aggregate(make(1, Severity.CRITICAL), now=NOW).score
    many_low = aggregate(make(100, Severity.LOW), now=NOW).score
    assert critical > many_low


def test_more_findings_of_the_same_severity_still_raise_the_score() -> None:
    """Taking only the maximum would say one CRITICAL and thirty are equally
    risky, which a reviewer would notice immediately."""
    one = aggregate(make(1, Severity.CRITICAL), now=NOW).score
    three = aggregate(make(3, Severity.CRITICAL), now=NOW).score
    assert three > one


def test_additional_findings_have_diminishing_effect() -> None:
    scores = [aggregate(make(count, Severity.HIGH), now=NOW).score for count in (1, 2, 3, 4)]
    gaps = [b - a for a, b in zip(scores, scores[1:], strict=False)]
    assert gaps == sorted(gaps, reverse=True), "each extra finding must add less than the last"


def test_the_score_is_bounded() -> None:
    """With fresh findings the series converges to exactly 100, so the cap was
    never reached and the first version of this test could not have failed.

    Age and regression push a single finding above its base — 40 × 1.25 × 1.15
    — and the series then exceeds 100, which is where the bound has to hold.
    """
    aged = make(
        500,
        Severity.CRITICAL,
        created_at=NOW - timedelta(days=365),
        status=FindingStatus.NEW,
        fixed_in_scan_id=1,
    )
    assert score_finding(aged[0], now=NOW).score > policy.SEVERITY_BASE[Severity.CRITICAL]
    assert aggregate(aged, now=NOW).score == policy.MAX_SCORE


def test_aggregation_ranks_before_it_weights() -> None:
    """Decay applies by rank, so the findings have to be sorted first.

    Every other aggregation test here fed findings that were already in
    descending order, which meant removing the sort changed nothing. This one
    hands them over worst-last.
    """
    ascending = [
        finding(id=1, fingerprint="f1", severity=Severity.LOW),
        finding(id=2, fingerprint="f2", severity=Severity.CRITICAL),
    ]
    descending = list(reversed(ascending))
    assert aggregate(ascending, now=NOW).score == aggregate(descending, now=NOW).score
    # The critical must carry full weight whichever order it arrived in:
    # 40 + 4 × 0.6 = 42.4, not 4 + 40 × 0.6 = 28.
    assert aggregate(ascending, now=NOW).score == 42.4


def test_a_clean_repository_scores_zero_and_grades_a() -> None:
    risk = aggregate([], now=NOW)
    assert risk.score == 0.0
    assert risk.grade == "A"
    assert risk.finding_count == 0


def test_fixed_findings_are_excluded_from_the_total_and_the_counts() -> None:
    mixed = make(2, Severity.CRITICAL) + make(3, Severity.HIGH, status=FindingStatus.FIXED)
    risk = aggregate(mixed, now=NOW)
    assert risk.finding_count == 2
    assert risk.counts_by_severity == {"CRITICAL": 2}


def test_the_top_list_is_worst_first_and_bounded() -> None:
    """The aggregate is built in this order, so showing it is showing how the
    total was reached."""
    risk = aggregate(make(3, Severity.CRITICAL) + make(4, Severity.LOW), now=NOW, top=3)
    scores = [item.score for item in risk.top]
    assert len(risk.top) == 3
    assert scores == sorted(scores, reverse=True)


def test_the_policy_version_travels_with_the_score() -> None:
    """Two scores from different policies are not two points on the same line."""
    assert aggregate(make(1, Severity.HIGH), now=NOW).policy_version == policy.POLICY_VERSION


def test_scoring_is_deterministic() -> None:
    """The property that rules out asking a model for this number."""
    findings = make(5, Severity.HIGH) + make(2, Severity.MEDIUM)
    first = aggregate(findings, now=NOW)
    second = aggregate(findings, now=NOW)
    assert first.score == second.score
    assert [item.score for item in first.top] == [item.score for item in second.top]
