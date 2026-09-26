"""The risk policy: every number this project uses to rank a finding.

**These constants are a policy, not a measurement.** Nothing here was derived
from incident data, because this project has none. They encode a defensible set
of opinions — a CRITICAL matters more than a HIGH, a low-confidence match is
less likely to be real, a hard-coded key in a test fixture is less urgent than
one in production code — and they are gathered in a single file precisely so
that anyone who disagrees can argue with the numbers rather than with the code.

That is the whole design constraint of Phase 9: a risk score has to be
**reproducible, explainable and arguable**. A reviewer who cannot see why a
finding scored 34 cannot act on it, and a score that changes between runs cannot
be quoted. Both rule out asking a language model — which is why this phase is
arithmetic, and why every score is returned with the factors that produced it.

The scale is 0–100 and is **not CVSS**. It is not derived from CVSS, it does not
map onto CVSS, and calling it a CVSS score would be borrowing rigour this
project has not done the work for.
"""

from app.models import Severity

# --- the base: how bad this class of weakness is ---------------------------
# Deliberately not linear. The gap between CRITICAL and HIGH is larger than the
# gap between LOW and INFO, because the decisions they drive are further apart:
# one is "stop and fix", the other is "note it".
SEVERITY_BASE: dict[Severity, float] = {
    Severity.CRITICAL: 40.0,
    Severity.HIGH: 25.0,
    Severity.MEDIUM: 12.0,
    Severity.LOW: 4.0,
    Severity.INFO: 1.0,
}

# --- confidence: how likely the analyser is to be right --------------------
# Risk is impact multiplied by likelihood, and confidence is the only honest
# proxy this project has for likelihood. It never reaches zero: a LOW-confidence
# CRITICAL is still worth a human's attention, and scoring it away would be the
# tool deciding on the reviewer's behalf.
CONFIDENCE_FACTOR: dict[str, float] = {
    "HIGH": 1.0,
    "MEDIUM": 0.8,
    "LOW": 0.6,
}

# --- context: where in the repository the finding lives --------------------
# A heuristic, and labelled as one. Without data-flow analysis there is no way
# to know whether user input reaches a dangerous call, so this project does not
# pretend to: it uses the one signal it genuinely has, which is the path.
#
# `os.system` in a test fixture is usually deliberate. The same call in
# application code usually is not. Neither is a certainty, so neither factor is
# 0 or 1 — a test-file finding is reduced, never dismissed.
TEST_PATH_FACTOR = 0.4
VENDORED_PATH_FACTOR = 0.5
EXAMPLE_PATH_FACTOR = 0.6
DEFAULT_PATH_FACTOR = 1.0

# Directory and filename markers, matched against path segments rather than
# substrings: "latest/" must not match because it contains "test".
TEST_MARKERS = frozenset(
    {
        "test",
        "tests",
        "testing",
        "spec",
        "specs",
        "__tests__",
        "fixtures",
        "fixture",
        "mocks",
        "mock",
    }
)
VENDORED_MARKERS = frozenset(
    {
        "node_modules",
        "vendor",
        "vendored",
        "third_party",
        "thirdparty",
        "dist",
        "build",
        "target",
        "generated",
        "migrations",
        ".venv",
        "venv",
        "site-packages",
    }
)
EXAMPLE_MARKERS = frozenset({"example", "examples", "sample", "samples", "demo", "demos", "docs"})

# --- secrets are different -------------------------------------------------
# A hard-coded credential is not a weakness that *might* be exploited — it is
# one that is already exposed to everyone who can read the repository, and it
# stays exposed in git history after the line is deleted. So the path heuristic
# does not apply: a real key in a test fixture is a real key.
CREDENTIAL_RULE_PREFIX = "SEC"
SECRET_PATH_FACTOR = 1.0

# --- age: how long it has gone unaddressed ---------------------------------
# An old open finding is worse than a new one, for a reason that is about the
# process rather than the code: it has survived review. The effect is capped and
# modest — age is a nudge in the ordering, not a way for a stale LOW to outrank
# a fresh CRITICAL.
AGE_CAP_DAYS = 90
MAX_AGE_BONUS = 0.25

# --- regression: it was fixed, and it came back ----------------------------
# Phase 6 can tell the difference between a new finding and a returning one.
# A regression means a fix was reverted or re-broken, which says something about
# the change process that a first occurrence does not.
REGRESSION_FACTOR = 1.15

# --- aggregation -----------------------------------------------------------
# Repository risk is the sum of its findings with geometric decay by rank, so
# the worst finding dominates and each subsequent one contributes less.
#
# A plain sum would let a hundred INFO findings outrank one CRITICAL, which is
# how a scoring system teaches people to ignore it. Taking only the maximum
# would say a repository with one CRITICAL is exactly as risky as one with
# thirty, which is just as wrong. Decay sits between the two: with this value,
# an unlimited number of identical findings converges to 2.5× a single one.
RANK_DECAY = 0.6
MAX_SCORE = 100.0

# --- grades ----------------------------------------------------------------
# Bands exist because a number alone invites false precision: 34 and 37 are not
# meaningfully different, and a reader who sees two digits will treat them as if
# they were. The letter is what belongs in a summary; the number is for ordering.
GRADE_THRESHOLDS: tuple[tuple[float, str], ...] = (
    (10.0, "A"),
    (25.0, "B"),
    (45.0, "C"),
    (70.0, "D"),
    (MAX_SCORE + 1, "F"),
)

POLICY_VERSION = 1
"""Bumped whenever a constant above changes.

Stored with every snapshot, so a score taken last month is comparable only to
another score from the same policy — and visibly not comparable to one from a
different policy. A trend line that silently mixes two scoring schemes is worse
than no trend line.
"""

__all__ = [
    "AGE_CAP_DAYS",
    "CONFIDENCE_FACTOR",
    "DEFAULT_PATH_FACTOR",
    "EXAMPLE_MARKERS",
    "EXAMPLE_PATH_FACTOR",
    "GRADE_THRESHOLDS",
    "MAX_AGE_BONUS",
    "MAX_SCORE",
    "POLICY_VERSION",
    "RANK_DECAY",
    "REGRESSION_FACTOR",
    "SECRET_PATH_FACTOR",
    "CREDENTIAL_RULE_PREFIX",
    "SEVERITY_BASE",
    "TEST_MARKERS",
    "TEST_PATH_FACTOR",
    "VENDORED_MARKERS",
    "VENDORED_PATH_FACTOR",
]
