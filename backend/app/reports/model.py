"""What a report says, independent of how it is written down.

One :class:`Report` is built per request and handed to whichever renderer was
asked for, so the Markdown, the HTML and the SARIF cannot disagree about a
number: there is only one place the number is computed.

Everything here is either counted from stored rows or copied from them. The
only prose is this project's own remediation notes (written per rule, in
:mod:`app.knowledge.rule_notes`) and a fixed list of what the report does not
claim. **No model output is included**: an explanation or a diff written by a
language model is advice to be read in context, next to its warnings, and a
document that leaves the building is the wrong place for it. What a report
does say about a proposed fix is the one thing that was checked — the verdict
of the re-scan.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from app.knowledge.rule_notes import NOTES_BY_RULE
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
)
from app.risk.scoring import aggregate, score_finding

TOOL_NAME = "SentinelForge"
SEVERITY_ORDER = tuple(str(severity) for severity in Severity)

GRADE_LABELS = {
    "A": "Nothing outstanding",
    "B": "Minor issues",
    "C": "Worth addressing",
    "D": "Needs attention",
    "F": "Act on this",
}


class FixState(StrEnum):
    """Where a finding stands with respect to a proposed fix."""

    NONE = "none"
    ROTATE = "rotate"
    GENERATING = "generating"
    REFUSED = "refused"
    UNCHECKED = "unchecked"
    CHECKING = "checking"
    PASSED = "passed"
    REJECTED = "rejected"
    NOT_JUDGED = "not_judged"


FIX_LABELS: dict[FixState, str] = {
    FixState.NONE: "No fix has been requested.",
    FixState.ROTATE: (
        "Rotate this credential. No code change is proposed: the value is in the "
        "repository's history and an edit does not un-leak it."
    ),
    FixState.GENERATING: "A fix is being generated.",
    FixState.REFUSED: "A fix was requested and none was acceptable.",
    FixState.UNCHECKED: "A fix was proposed and has not been checked.",
    FixState.CHECKING: "A proposed fix is being checked.",
    FixState.PASSED: (
        "A proposed fix passed the re-scan on a throwaway copy. It has not been "
        "applied to the code."
    ),
    FixState.REJECTED: "A proposed fix was rejected by the re-scan.",
    FixState.NOT_JUDGED: (
        "A proposed fix could not be checked because the stored code had changed."
    ),
}

# What this report does not claim. Fixed text, printed in every format, because
# a document that is forwarded loses the interface that used to sit around it.
LIMITATIONS: tuple[str, ...] = (
    "The analysis is rule-based and reads the code without running it. A finding "
    "says a dangerous construct is present, not that an attacker can reach it.",
    "No findings means these rules did not match. It is not a statement that the code is secure.",
    "The risk score is a fixed policy over the findings, shown with its "
    "arithmetic. It is not CVSS and is not derived from incident data.",
    "A fix that passed the re-scan was applied to a throwaway copy only. The "
    "finding stays open until the real code is scanned without it, and passing "
    "does not show that the program still behaves the same.",
    "Code snippets for credentials are redacted before they are stored. At most "
    "the first four characters of a value are kept; the full value is not stored "
    "and does not appear in this report.",
)

PatchState = tuple[PatchStatus, PatchValidationStatus | None]


@dataclass(frozen=True)
class ReportFinding:
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
    # The multiplication written out, as everywhere else a score is shown.
    score_explanation: str
    fix_state: FixState
    fix_label: str


@dataclass(frozen=True)
class ReportRule:
    """Open findings of one rule, with what to do about them."""

    rule_id: str
    title: str
    count: int
    worst_severity: str
    cwe_id: str | None
    owasp_category: str | None
    # This project's own notes for the rule. None for a rule without one.
    risk_note: str | None
    fix_note: str | None


@dataclass(frozen=True)
class ReportScan:
    id: int
    finished_at: datetime
    duration_ms: int | None
    files_scanned: int
    files_skipped: int
    unparsable_files: int
    # The analyser stopped at its limit, so the findings are a lower bound.
    truncated: bool


@dataclass(frozen=True)
class Report:
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
    scan: ReportScan
    score: float
    grade: str
    grade_label: str
    open_count: int
    new_count: int
    fixed_count: int
    counts_by_severity: dict[str, int]
    rules: list[ReportRule] = field(default_factory=list)
    # Open findings, highest risk first.
    findings: list[ReportFinding] = field(default_factory=list)
    fixed: list[ReportFinding] = field(default_factory=list)
    limitations: tuple[str, ...] = LIMITATIONS


def format_when(value: datetime) -> str:
    """A timestamp as a reader wants it, always in UTC and saying so.

    The database hands timestamps back in its session's time zone. A report is
    read somewhere else, by someone who cannot ask which one that was.
    """
    if value.tzinfo is not None:
        value = value.astimezone(UTC)
    return value.strftime("%d %B %Y, %H:%M UTC")


def fix_state(finding: Finding, patch: PatchState | None) -> FixState:
    """One word for where a finding's fix stands, from its latest patch.

    A credential is always ROTATE, whatever rows exist: patches for credentials
    were removed in Phase 11 and none can be created, and the advice does not
    depend on either.
    """
    if finding.is_credential:
        return FixState.ROTATE
    if patch is None:
        return FixState.NONE
    status, validation = patch
    if status in ACTIVE_PATCH_STATUSES:
        return FixState.GENERATING
    if status is PatchStatus.FAILED:
        return FixState.REFUSED
    if validation is None:
        return FixState.UNCHECKED
    if validation in ACTIVE_VALIDATION_STATUSES:
        return FixState.CHECKING
    if validation is PatchValidationStatus.PASSED:
        return FixState.PASSED
    if validation is PatchValidationStatus.REJECTED:
        return FixState.REJECTED
    return FixState.NOT_JUDGED


def build_report(
    *,
    repository: Repository,
    project: Project,
    scan: Scan,
    findings: list[Finding],
    patches: dict[int, PatchState],
    now: datetime,
    tool_version: str,
) -> Report:
    risk = aggregate(findings, now=now, top=0)

    def describe(finding: Finding) -> ReportFinding:
        scored = score_finding(finding, now=now)
        fixed = finding.status is FindingStatus.FIXED
        # A fixed finding needs no advice about fixing it.
        state = FixState.NONE if fixed else fix_state(finding, patches.get(finding.id))
        return ReportFinding(
            id=finding.id,
            rule_id=finding.rule_id,
            title=finding.title,
            message=finding.message,
            severity=str(finding.severity),
            confidence=str(finding.confidence),
            cwe_id=finding.cwe_id,
            owasp_category=finding.owasp_category,
            file_path=finding.file_path,
            line_start=finding.line_start,
            line_end=finding.line_end,
            snippet=finding.snippet,
            status=str(finding.status),
            fingerprint=finding.fingerprint,
            is_credential=finding.is_credential,
            score=scored.score,
            score_explanation=scored.explanation,
            fix_state=state,
            fix_label="" if fixed else FIX_LABELS[state],
        )

    described = [describe(finding) for finding in findings]
    open_findings = [item for item in described if item.status != FindingStatus.FIXED]
    fixed_findings = [item for item in described if item.status == FindingStatus.FIXED]
    # Highest risk first; then a stable order, so two reports of the same code
    # can be compared line by line.
    open_findings.sort(key=_reading_order)
    fixed_findings.sort(key=lambda item: (item.file_path, item.line_start, item.id))

    counts = {key: 0 for key in SEVERITY_ORDER}
    for item in open_findings:
        counts[item.severity] = counts.get(item.severity, 0) + 1

    return Report(
        tool_name=TOOL_NAME,
        tool_version=tool_version,
        policy_version=risk.policy_version,
        generated_at=now,
        project_name=project.name,
        repository_id=repository.id,
        origin=repository.origin,
        branch=repository.branch,
        commit_hash=repository.commit_hash,
        primary_language=repository.primary_language,
        scan=ReportScan(
            id=scan.id,
            finished_at=scan.finished_at,
            duration_ms=scan.duration_ms,
            files_scanned=scan.files_scanned,
            files_skipped=scan.files_skipped,
            unparsable_files=scan.unparsable_files,
            truncated=scan.truncated,
        ),
        score=risk.score,
        grade=risk.grade,
        grade_label=GRADE_LABELS.get(risk.grade, ""),
        open_count=len(open_findings),
        new_count=sum(1 for item in open_findings if item.status == FindingStatus.NEW),
        fixed_count=len(fixed_findings),
        counts_by_severity=counts,
        rules=_rules(open_findings),
        findings=open_findings,
        fixed=fixed_findings,
    )


def _reading_order(item: ReportFinding) -> tuple[float, int, str, int, int]:
    return (
        -item.score,
        SEVERITY_ORDER.index(item.severity),
        item.file_path,
        item.line_start,
        item.id,
    )


def _rules(open_findings: list[ReportFinding]) -> list[ReportRule]:
    groups: dict[str, list[ReportFinding]] = {}
    for item in open_findings:
        groups.setdefault(item.rule_id, []).append(item)

    rules = []
    for rule_id, members in groups.items():
        note = NOTES_BY_RULE.get(rule_id)
        first = members[0]
        rules.append(
            ReportRule(
                rule_id=rule_id,
                title=first.title,
                count=len(members),
                worst_severity=min((item.severity for item in members), key=SEVERITY_ORDER.index),
                cwe_id=first.cwe_id,
                owasp_category=first.owasp_category,
                risk_note=note.risk if note else None,
                fix_note=note.fix if note else None,
            )
        )
    # Worst severity first, then the commonest, then by id so the order is fixed.
    rules.sort(
        key=lambda rule: (SEVERITY_ORDER.index(rule.worst_severity), -rule.count, rule.rule_id)
    )
    return rules


__all__ = [
    "FIX_LABELS",
    "GRADE_LABELS",
    "LIMITATIONS",
    "SEVERITY_ORDER",
    "TOOL_NAME",
    "FixState",
    "PatchState",
    "Report",
    "ReportFinding",
    "ReportRule",
    "ReportScan",
    "build_report",
    "fix_state",
    "format_when",
]
