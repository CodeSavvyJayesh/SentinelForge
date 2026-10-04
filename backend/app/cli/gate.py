"""The quality gate: turning a report into pass or fail.

A gate that fails on everything is switched off within a week, and a gate that
is switched off protects nothing. So this one is built to be adopted on a
repository that already has findings:

* **A severity threshold.** Fail when a finding at or above it is present.
* **A baseline.** Given the SARIF from an earlier run, only findings that were
  not in it count. The build then asks "did this change make things worse?",
  which a team can keep green, instead of "is this repository perfect?", which
  it cannot.
* **A score ceiling**, optionally, on the repository's risk score as a whole.

Every reason for failing is returned as a sentence. A red build that does not
say why teaches people to re-run it.
"""

from dataclasses import dataclass, field

from app.reports.model import SEVERITY_ORDER, Report, ReportFinding

# "none" switches the severity check off; the score ceiling can still apply.
FAIL_ON_CHOICES = (*[severity.lower() for severity in SEVERITY_ORDER], "none")
DEFAULT_FAIL_ON = "high"
MAX_LISTED = 10


@dataclass(frozen=True)
class Gate:
    fail_on: str = DEFAULT_FAIL_ON
    max_score: float | None = None


@dataclass(frozen=True)
class GateResult:
    passed: bool
    reasons: list[str] = field(default_factory=list)
    # The findings that failed the severity check, worst first.
    blocking: list[ReportFinding] = field(default_factory=list)


def evaluate(report: Report, gate: Gate, *, baseline: frozenset[str] | None = None) -> GateResult:
    """Judge ``report`` against ``gate``.

    With a baseline, the severity check looks only at findings whose
    fingerprint the baseline does not contain. The score ceiling always applies
    to the whole repository: it is a statement about the code as it stands.
    """
    reasons: list[str] = []
    blocking: list[ReportFinding] = []

    if gate.fail_on != "none":
        limit = SEVERITY_ORDER.index(gate.fail_on.upper())
        candidates = [
            finding
            for finding in report.findings
            if baseline is None or finding.fingerprint not in baseline
        ]
        blocking = [
            finding for finding in candidates if SEVERITY_ORDER.index(finding.severity) <= limit
        ]
        if blocking:
            scope = "new finding" if baseline is not None else "finding"
            plural = "" if len(blocking) == 1 else "s"
            reasons.append(
                f"{len(blocking)} {scope}{plural} at {gate.fail_on.upper()} severity or above."
            )

    if gate.max_score is not None and report.score > gate.max_score:
        reasons.append(f"The risk score is {report.score:g}, above the allowed {gate.max_score:g}.")

    return GateResult(passed=not reasons, reasons=reasons, blocking=blocking)


__all__ = ["DEFAULT_FAIL_ON", "FAIL_ON_CHOICES", "MAX_LISTED", "Gate", "GateResult", "evaluate"]
