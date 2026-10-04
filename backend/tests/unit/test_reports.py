"""The report, and the three ways it is written down.

Most of this file is hostile input. A report is the one place where text from
an uploaded repository — a file name, a line of code, a project somebody named —
ends up in a document that is opened somewhere else by someone else, so each
renderer is given text built to break its format and asked for a document that
is still the same shape.
"""

import json
import re
from datetime import UTC, datetime, timedelta, timezone
from html.parser import HTMLParser

import pytest

from app.models import (
    Confidence,
    Finding,
    FindingStatus,
    PatchStatus,
    PatchValidationStatus,
    Project,
    Repository,
    RepositorySource,
    RepositoryStatus,
    Scan,
    ScanStatus,
    Severity,
)
from app.reports import html as html_report
from app.reports import markdown as markdown_report
from app.reports import sarif as sarif_report
from app.reports.model import FIX_LABELS, FixState, build_report, fix_state, format_when
from app.services.report_service import ReportFormat, filename_for, render

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
SCRIPT = "<script>alert(1)</script>"
BREAKOUT = '"><img src=x onerror=alert(1)>'


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


def report(findings=None, patches=None, **overrides):  # noqa: ANN001, ANN003, ANN201
    repository = Repository(
        id=7,
        project_id=3,
        source=RepositorySource.UPLOAD,
        status=RepositoryStatus.READY,
        origin=overrides.pop("origin", "payments.zip"),
        branch=overrides.pop("branch", None),
        commit_hash=overrides.pop("commit_hash", None),
        primary_language=overrides.pop("primary_language", "Python"),
    )
    project = Project(id=3, owner_id=1, name=overrides.pop("project_name", "Payments"))
    scan = Scan(
        id=11,
        repository_id=7,
        status=ScanStatus.COMPLETED,
        finished_at=NOW - timedelta(hours=1),
        duration_ms=420,
        files_scanned=12,
        files_skipped=1,
        unparsable_files=overrides.pop("unparsable_files", 0),
        truncated=overrides.pop("truncated", False),
    )
    assert not overrides, overrides
    return build_report(
        repository=repository,
        project=project,
        scan=scan,
        findings=[finding()] if findings is None else findings,
        patches=patches or {},
        now=NOW,
        tool_version="0.1.0",
    )


def hostile(payload: str):  # noqa: ANN201
    """A report in which every field a repository or a user controls is the payload."""
    return report(
        [
            finding(
                title=payload,
                message=payload,
                file_path=payload,
                snippet=payload,
                rule_id="ZZ999",
                cwe_id=payload[:16],
                owasp_category=payload,
            ),
            finding(id=2, fingerprint="f2", title=payload, file_path=payload,
                    status=FindingStatus.FIXED),
        ],
        project_name=payload,
        origin=payload,
        branch=payload,
        commit_hash=payload,
        primary_language=payload,
    )  # fmt: skip


# --- the model --------------------------------------------------------------


def test_open_findings_are_listed_highest_risk_first_and_fixed_ones_apart() -> None:
    built = report(
        [
            finding(id=1, fingerprint="a", severity=Severity.LOW),
            finding(id=2, fingerprint="b", severity=Severity.CRITICAL),
            finding(id=3, fingerprint="c", severity=Severity.HIGH, status=FindingStatus.NEW),
            finding(id=4, fingerprint="d", severity=Severity.CRITICAL, status=FindingStatus.FIXED),
        ]
    )

    assert [item.id for item in built.findings] == [2, 3, 1]
    assert [item.id for item in built.fixed] == [4]
    assert (built.open_count, built.new_count, built.fixed_count) == (3, 1, 1)
    assert built.counts_by_severity == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 1, "INFO": 0}


def test_risk_orders_the_findings_not_severity_alone() -> None:
    """A CRITICAL in test code scores below a HIGH in application code, and the
    report follows the score: it is the order to read them in."""
    built = report(
        [
            finding(id=1, fingerprint="a", severity=Severity.CRITICAL, file_path="tests/test_a.py"),
            finding(id=2, fingerprint="b", severity=Severity.HIGH, file_path="app/a.py"),
        ]
    )

    assert [item.severity for item in built.findings] == ["HIGH", "CRITICAL"]
    assert built.findings[0].score > built.findings[1].score


def test_equal_scores_fall_back_to_a_stable_reading_order() -> None:
    # Ids chosen so that id order is not the answer.
    built = report(
        [
            finding(id=2, fingerprint="c", file_path="b.py", line_start=1),
            finding(id=1, fingerprint="b", file_path="a.py", line_start=9),
            finding(id=3, fingerprint="a", file_path="a.py", line_start=2),
        ]
    )

    assert [(item.file_path, item.line_start) for item in built.findings] == [
        ("a.py", 2),
        ("a.py", 9),
        ("b.py", 1),
    ]


def test_a_rules_worst_severity_is_the_worst_not_the_highest_scoring() -> None:
    built = report(
        [
            finding(id=1, fingerprint="a", severity=Severity.HIGH, file_path="app/a.py"),
            finding(id=2, fingerprint="b", severity=Severity.CRITICAL, file_path="tests/test_a.py"),
        ]
    )

    assert built.findings[0].severity == "HIGH"  # the first member of the group
    assert built.rules[0].worst_severity == "CRITICAL"


def test_the_score_is_the_one_the_risk_engine_gives_with_its_arithmetic() -> None:
    built = report([finding(confidence=Confidence.MEDIUM)])

    assert built.findings[0].score == 32.0
    assert built.findings[0].score_explanation.startswith("40 base × 0.8 confidence")
    assert built.score == 32.0
    assert built.grade_label


def test_findings_are_grouped_by_rule_with_this_projects_own_notes() -> None:
    built = report(
        [
            finding(id=1, fingerprint="a", severity=Severity.MEDIUM),
            finding(id=2, fingerprint="b", severity=Severity.CRITICAL, line_start=30),
            finding(id=3, fingerprint="c", rule_id="ZZ999", title="Unknown", severity=Severity.HIGH,
                    cwe_id=None, owasp_category=None),
            finding(id=4, fingerprint="d", status=FindingStatus.FIXED),
        ]
    )  # fmt: skip

    assert [(rule.rule_id, rule.count, rule.worst_severity) for rule in built.rules] == [
        ("PY010", 2, "CRITICAL"),
        ("ZZ999", 1, "HIGH"),
    ]
    assert "parameter" in built.rules[0].fix_note.lower()
    assert built.rules[0].risk_note
    # A rule with no note says nothing rather than borrowing another rule's.
    assert built.rules[1].fix_note is None
    assert built.rules[1].risk_note is None


@pytest.mark.parametrize(
    ("patch", "expected"),
    [
        (None, FixState.NONE),
        ((PatchStatus.QUEUED, None), FixState.GENERATING),
        ((PatchStatus.RUNNING, None), FixState.GENERATING),
        ((PatchStatus.FAILED, None), FixState.REFUSED),
        ((PatchStatus.PROPOSED, None), FixState.UNCHECKED),
        ((PatchStatus.PROPOSED, PatchValidationStatus.QUEUED), FixState.CHECKING),
        ((PatchStatus.PROPOSED, PatchValidationStatus.RUNNING), FixState.CHECKING),
        ((PatchStatus.PROPOSED, PatchValidationStatus.PASSED), FixState.PASSED),
        ((PatchStatus.PROPOSED, PatchValidationStatus.REJECTED), FixState.REJECTED),
        ((PatchStatus.PROPOSED, PatchValidationStatus.FAILED), FixState.NOT_JUDGED),
    ],
)
def test_a_findings_fix_state_follows_its_latest_patch(patch, expected) -> None:  # noqa: ANN001
    assert fix_state(finding(), patch) is expected


def test_a_passed_fix_is_never_described_as_applied() -> None:
    built = report(patches={1: (PatchStatus.PROPOSED, PatchValidationStatus.PASSED)})

    assert built.findings[0].fix_state is FixState.PASSED
    assert "not been applied" in built.findings[0].fix_label
    assert "fixed" not in built.findings[0].fix_label.lower()


def test_a_check_that_could_not_run_is_not_reported_as_a_rejection() -> None:
    built = report(patches={1: (PatchStatus.PROPOSED, PatchValidationStatus.FAILED)})

    assert built.findings[0].fix_label == FIX_LABELS[FixState.NOT_JUDGED]
    assert "rejected" not in built.findings[0].fix_label


def test_a_credential_is_told_to_rotate_whatever_patches_exist() -> None:
    secret = finding(rule_id="SEC005", cwe_id="CWE-798", snippet="JWT_SECRET=[REDACTED]")
    built = report([secret], patches={1: (PatchStatus.PROPOSED, PatchValidationStatus.PASSED)})

    assert built.findings[0].fix_state is FixState.ROTATE
    assert built.findings[0].fix_label.startswith("Rotate this credential")


def test_a_fixed_finding_carries_no_advice_about_fixing_it() -> None:
    built = report(
        [finding(status=FindingStatus.FIXED)],
        patches={1: (PatchStatus.PROPOSED, PatchValidationStatus.REJECTED)},
    )

    assert built.fixed[0].fix_state is FixState.NONE
    assert built.fixed[0].fix_label == ""


def test_times_are_written_in_utc_wherever_the_database_was() -> None:
    india = timezone(timedelta(hours=5, minutes=30))

    assert format_when(datetime(2026, 3, 1, 17, 30, tzinfo=india)) == "01 March 2026, 12:00 UTC"
    assert format_when(datetime(2026, 3, 1, 12, 0, tzinfo=UTC)) == "01 March 2026, 12:00 UTC"


# --- markdown ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("[click](http://example.test)", r"\[click\](http://example.test)"),
        ("<b>bold</b> & more", "&lt;b&gt;bold&lt;/b&gt; &amp; more"),
        ("*a* _b_ `c`", r"\*a\* \_b\_ \`c\`"),
        ("# heading", r"\# heading"),
        ("a | b", r"a \| b"),
        ("two\nlines\r\n  here", "two lines here"),
        ("back\\slash", "back\\\\slash"),
        ("~~struck~~", r"\~\~struck\~\~"),
        (None, ""),
    ],
)
def test_markdown_prose_is_made_inert(raw, expected) -> None:  # noqa: ANN001
    assert markdown_report.text(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("- item", r"\- item"),
        ("+ item", r"\+ item"),
        ("1. item", r"1\. item"),
        ("12) item", r"12\) item"),
        ("=====", r"\====="),
        ("3 files changed", "3 files changed"),
        ("plain", "plain"),
        ("# heading", r"\# heading"),
    ],
)
def test_prose_that_starts_a_line_cannot_start_a_list_or_a_heading(raw: str, expected: str) -> None:
    assert markdown_report.paragraph(raw) == expected


def test_a_version_number_inside_a_line_is_left_alone() -> None:
    assert markdown_report.text("0.1.0") == "0.1.0"


def test_a_code_span_cannot_be_closed_by_its_own_content() -> None:
    assert markdown_report.code_span("a.py") == "`a.py`"
    assert markdown_report.code_span("a`b") == "``a`b``"
    assert markdown_report.code_span("a``b`c") == "```a``b`c```"
    # Leading or trailing backticks need padding to be parsed as code at all.
    assert markdown_report.code_span("`x`") == "`` `x` ``"
    assert markdown_report.code_span("a\nb") == "`a b`"
    assert markdown_report.code_span("a|b") == r"`a\|b`"
    assert markdown_report.code_span("") == ""


def test_a_code_block_cannot_be_closed_by_its_own_content() -> None:
    assert markdown_report.code_block("x = 1") == "```\nx = 1\n```"
    assert markdown_report.code_block("```\nrm -rf\n```") == "````\n```\nrm -rf\n```\n````"
    assert markdown_report.code_block("a ````` b").startswith("``````\n")
    assert markdown_report.code_block("a\r\nb\r") == "```\na\nb\n```"


def prose(document: str) -> str:
    """The document with its code removed: what a renderer would interpret."""
    kept, fence = [], None
    for line in document.splitlines():
        marker = re.match(r"^(`{3,})", line)
        if marker and fence is None:
            fence = marker.group(1)
        elif fence is not None:
            fence = None if line.strip() == fence else fence
        else:
            kept.append(re.sub(r"(?<!`)(`+)(?!`).+?(?<!`)\1(?!`)", "", line))
    return "\n".join(kept)


def headings(document: str) -> list[str]:
    """Headings outside code fences — the document's actual structure."""
    found, fence = [], None
    for line in document.splitlines():
        marker = re.match(r"^(`{3,})", line)
        if marker and fence is None:
            fence = marker.group(1)
        elif fence is not None and line.strip() == fence:
            fence = None
        elif fence is None and re.match(r"^#{1,6} ", line):
            found.append(re.sub(r"[^#].*", "", line))
    return found


@pytest.mark.parametrize(
    "payload",
    [
        "```\n# Injected heading\n\n| a | b |\n```",
        "\n\n## Injected\n\n[link](http://example.test)",
        "` | `` | ``` | ````",
        SCRIPT,
        "](http://example.test) ![x](http://example.test/x.png)",
    ],
)
def test_hostile_text_does_not_change_the_markdown_documents_structure(payload: str) -> None:
    benign = report(
        [
            finding(rule_id="ZZ999", cwe_id="CWE-1", owasp_category="A00"),
            finding(id=2, fingerprint="f2", status=FindingStatus.FIXED),
        ],
        branch="main",
        commit_hash="abc",
    )

    document = markdown_report.render(hostile(payload))

    assert headings(document) == headings(markdown_report.render(benign))
    # Outside code, nothing is left that a renderer would act on.
    interpreted = prose(document)
    assert "<" not in interpreted
    assert not re.search(r"(?<!\\)\[", interpreted)
    assert not re.search(r"(?<!\\)`", interpreted)


def test_the_markdown_report_says_what_it_found_and_what_it_does_not_claim() -> None:
    document = markdown_report.render(
        report(
            [finding(), finding(id=2, fingerprint="f2", status=FindingStatus.FIXED, line_start=40)],
            patches={1: (PatchStatus.PROPOSED, PatchValidationStatus.REJECTED)},
            branch="main",
            commit_hash="abc123",
        )
    )

    assert document.startswith("# Security report: Payments\n")
    assert "Generated 27 September 2026, 12:00 UTC by SentinelForge 0.1.0." in document
    assert "| Repository | `payments.zip` |" in document
    assert "| Branch | `main` |" in document
    assert "| Commit | `abc123` |" in document
    assert "**Risk grade C** (40 out of 100, scoring policy v1)" in document
    assert "- Open findings: **1** (0 first seen in the last scan)" in document
    assert "| CRITICAL | 1 |" in document and "| INFO | 0 |" in document
    assert "### PY010: SQL query built by string formatting" in document
    assert "**Fix.** " in document and "**Risk.** " in document
    assert "### 1. CRITICAL: SQL query built by string formatting" in document
    assert "- Location: `app/users.py:24`" in document
    assert "- Fix: A proposed fix was rejected by the re-scan." in document
    assert "```\ncursor.execute(f'...')\n```" in document
    assert "## Fixed findings" in document
    assert "`app/users.py:40`" in document
    assert "## What this report does not claim" in document
    assert "It is not CVSS" in document
    assert "Incomplete" not in document


def test_a_message_cannot_start_a_list_in_the_markdown_report() -> None:
    document = markdown_report.render(report([finding(message="1. Drop the table\n- then leave")]))

    assert "\n1\\. Drop the table - then leave\n" in document


def test_an_incomplete_scan_is_announced_before_the_numbers() -> None:
    document = markdown_report.render(report(truncated=True))

    assert "**Incomplete.**" in document
    assert document.index("**Incomplete.**") < document.index("| Severity |")


def test_a_clean_report_says_these_rules_matched_nothing_not_that_the_code_is_safe() -> None:
    document = markdown_report.render(report([]))

    assert "None. These rules matched nothing in the last scan." in document
    assert "## Fixed findings" not in document
    assert "It is not a statement that the code is secure." in document
    assert "secure." in document and "is secure\n" not in document


# --- html -------------------------------------------------------------------


class Tags(HTMLParser):
    """Collects what a browser would actually build from the page."""

    VOID = {"meta", "br", "hr", "img", "input", "link"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.seen: list[str] = []
        self.stack: list[str] = []
        self.attributes: list[tuple[str, str, str | None]] = []
        self.unbalanced = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.seen.append(tag)
        self.attributes += [(tag, name, value) for name, value in attrs]
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag: str) -> None:
        if not self.stack or self.stack.pop() != tag:
            self.unbalanced = True


def parse(document: str) -> Tags:
    parser = Tags()
    parser.feed(document)
    parser.close()
    return parser


ALLOWED_TAGS = {
    "html", "head", "meta", "title", "style", "body", "main", "h1", "h2", "h3", "p", "dl", "dt",
    "dd", "div", "strong", "code", "pre", "table", "thead", "tbody", "tr", "th", "td", "span",
    "section", "article", "ul", "li", "footer",
}  # fmt: skip


@pytest.mark.parametrize(
    "payload",
    [
        SCRIPT,
        BREAKOUT,
        "</style><script>alert(1)</script>",
        "</title></head><body onload=alert(1)>",
        "' onmouseover='alert(1)",
        "</pre></code></article><iframe src=//example.test>",
        "&lt;script&gt; &amp; <!-- -->",
    ],
)
def test_hostile_text_never_becomes_markup_in_the_html_report(payload: str) -> None:
    document = html_report.render(hostile(payload))
    parsed = parse(document)

    assert set(parsed.seen) <= ALLOWED_TAGS, set(parsed.seen) - ALLOWED_TAGS
    assert not parsed.unbalanced and not parsed.stack
    assert sorted({name for _tag, name, _value in parsed.attributes}) == [
        "charset", "class", "content", "http-equiv", "lang", "name", "scope", "style",
    ]  # fmt: skip
    # The same tags as a report with nothing hostile in it: nothing was added.
    benign = parse(html_report.render(hostile("plain")))
    assert parsed.seen == benign.seen


def test_escaping_covers_attributes_as_well_as_text() -> None:
    """Nothing untrusted is written into an attribute today. The escape still
    has to be safe there, so that the day something is, it already is."""
    assert html_report.esc('" onload="x') == "&quot; onload=&quot;x"
    assert html_report.esc("' onload='x") == "&#x27; onload=&#x27;x"
    assert html_report.esc("<a & b>") == "&lt;a &amp; b&gt;"
    assert html_report.esc(None) == ""
    assert html_report.esc(3) == "3"


def test_the_html_report_loads_nothing_and_runs_nothing() -> None:
    document = html_report.render(report())
    parsed = parse(document)

    assert "<script" not in document.lower()
    assert not [item for item in parsed.attributes if item[1] in {"src", "href", "action"}]
    assert not [item for item in parsed.attributes if item[1].startswith("on")]
    assert "http://" not in document and "https://" not in document
    assert "@import" not in document and "url(" not in document
    policy = next(value for tag, name, value in parsed.attributes if name == "content"
                  and value and "default-src" in value)  # fmt: skip
    assert "default-src 'none'" in policy
    assert "script-src" not in policy  # nothing re-enables what default-src forbids
    assert "form-action 'none'" in policy and "base-uri 'none'" in policy


def test_the_only_inline_styles_are_bar_widths_the_renderer_computed() -> None:
    document = html_report.render(hostile("width:100%;background:url(http://example.test)"))
    styles = [value for _tag, name, value in parse(document).attributes if name == "style"]

    assert styles
    assert all(re.fullmatch(r"width:\d{1,3}%", value) for value in styles), styles


def test_the_html_report_carries_the_same_facts_as_the_markdown() -> None:
    built = report(
        [
            finding(),
            finding(id=2, fingerprint="b", severity=Severity.MEDIUM, line_start=3),
            finding(id=3, fingerprint="c", severity=Severity.MEDIUM, line_start=4),
            finding(id=4, fingerprint="d", status=FindingStatus.FIXED, line_start=40),
        ],
        patches={1: (PatchStatus.PROPOSED, PatchValidationStatus.PASSED)},
        truncated=True,
    )
    document = html_report.render(built)

    assert "<title>Security report: Payments</title>" in document
    assert "Generated 27 September 2026, 12:00 UTC by SentinelForge 0.1.0." in document
    assert "<code>app/users.py:24</code>" in document
    assert "40 base × 1 confidence × 1 application path × 1 age = 40" in document
    assert "It has not been applied to the code." in document
    assert "<strong>Incomplete.</strong>" in document
    assert "<h2>Fixed findings</h2>" in document
    assert "It is not CVSS" in document
    # MEDIUM is the largest group, so it is the full-width bar; CRITICAL is half.
    assert document.count('style="width:100%"') == 1
    assert document.count('style="width:50%"') == 1
    assert document.count('class="bar"') == 2  # severities with nothing draw no bar


# --- sarif ------------------------------------------------------------------


def test_sarif_has_the_shape_a_code_scanning_consumer_reads() -> None:
    built = report(
        [
            finding(),
            finding(id=2, fingerprint="f2", line_start=30, line_end=32),
            finding(id=3, fingerprint="f3", rule_id="JV003", title="Weak hash",
                    severity=Severity.MEDIUM, cwe_id="CWE-327"),
            finding(id=4, fingerprint="f4", status=FindingStatus.FIXED),
        ],
        commit_hash="abc123",
        branch="main",
        origin="https://example.test/acme/payments.git",
    )  # fmt: skip
    document = sarif_report.render(built)

    assert document["version"] == "2.1.0"
    assert document["$schema"].endswith("sarif-2.1.0.json")
    assert len(document["runs"]) == 1
    run = document["runs"][0]
    driver = run["tool"]["driver"]
    assert (driver["name"], driver["version"]) == ("SentinelForge", "0.1.0")

    assert [rule["id"] for rule in driver["rules"]] == ["PY010", "JV003"]
    sql = driver["rules"][0]
    assert sql["shortDescription"]["text"] == "SQL query built by string formatting"
    assert sql["defaultConfiguration"]["level"] == "error"
    assert sql["properties"]["tags"] == ["security", "external/cwe/cwe-89"]
    assert sql["properties"]["security-severity"] == "9.5"
    assert sql["help"]["text"] and sql["fullDescription"]["text"]

    # Open findings only: a fixed one is not a result of the current code.
    assert len(run["results"]) == 3
    for result in run["results"]:
        assert driver["rules"][result["ruleIndex"]]["id"] == result["ruleId"]
        location = result["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
        assert location["region"]["startLine"] >= 1
        assert location["region"]["endLine"] >= location["region"]["startLine"]
        assert result["message"]["text"]
    by_fingerprint = {
        result["partialFingerprints"]["sentinelforge/v1"]: result for result in run["results"]
    }
    assert set(by_fingerprint) == {"f1", "f2", "f3"}
    assert by_fingerprint["f3"]["level"] == "warning"
    assert by_fingerprint["f2"]["locations"][0]["physicalLocation"]["region"] == {
        "startLine": 30,
        "endLine": 32,
        "snippet": {"text": "cursor.execute(f'...')"},
    }
    assert by_fingerprint["f1"]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "app/users.py"
    )
    assert run["versionControlProvenance"] == [
        {
            "repositoryUri": "https://example.test/acme/payments.git",
            "revisionId": "abc123",
            "branch": "main",
        }
    ]
    assert run["properties"]["riskGrade"] == built.grade


@pytest.mark.parametrize(
    ("severity", "level", "number"),
    [
        (Severity.CRITICAL, "error", "9.5"),
        (Severity.HIGH, "error", "8.0"),
        (Severity.MEDIUM, "warning", "5.5"),
        (Severity.LOW, "note", "3.0"),
        (Severity.INFO, "note", "1.0"),
    ],
)
def test_each_severity_lands_in_its_own_band(severity, level, number) -> None:  # noqa: ANN001
    run = sarif_report.render(report([finding(severity=severity)]))["runs"][0]

    assert run["results"][0]["level"] == level
    assert run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == number


def test_sarif_never_emits_a_line_number_a_consumer_would_reject() -> None:
    run = sarif_report.render(report([finding(line_start=0, line_end=0)]))["runs"][0]
    region = run["results"][0]["locations"][0]["physicalLocation"]["region"]

    assert (region["startLine"], region["endLine"]) == (1, 1)


def test_sarif_leaves_out_what_it_does_not_know() -> None:
    run = sarif_report.render(report([finding(rule_id="ZZ999", cwe_id=None, snippet="  ")]))[
        "runs"
    ][0]
    rule = run["tool"]["driver"]["rules"][0]

    assert "versionControlProvenance" not in run
    assert rule["properties"]["tags"] == ["security"]
    assert "help" not in rule and "fullDescription" not in rule
    assert "snippet" not in run["results"][0]["locations"][0]["physicalLocation"]["region"]


def test_a_clean_repository_is_a_valid_empty_run() -> None:
    run = sarif_report.render(report([]))["runs"][0]

    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []


# --- the export -------------------------------------------------------------


def test_every_format_is_rendered_from_the_same_report() -> None:
    built = report()

    assert render(built, ReportFormat.MARKDOWN) == markdown_report.render(built)
    assert render(built, ReportFormat.HTML) == html_report.render(built)
    assert json.loads(render(built, ReportFormat.SARIF)) == sarif_report.render(built)
    as_json = json.loads(render(built, ReportFormat.JSON))
    assert as_json["findings"][0]["fingerprint"] == "f1"
    assert as_json["findings"][0]["fix_state"] == "none"
    assert as_json["counts_by_severity"]["CRITICAL"] == 1


@pytest.mark.parametrize(
    ("origin", "expected"),
    [
        ("payments.zip", "sentinelforge-payments-20260927.md"),
        ("https://example.test/acme/Web_Goat.git", "sentinelforge-web-goat-20260927.md"),
        ("https://example.test/acme/site/", "sentinelforge-site-20260927.md"),
        (
            '../../etc/passwd"\r\nX-Injected: yes.zip',
            "sentinelforge-passwd-x-injected-yes-20260927.md",
        ),
        ("C:\\Users\\me\\My Project (1).ZIP", "sentinelforge-my-project-1-20260927.md"),
        ("???", "sentinelforge-repository-20260927.md"),
        ("", "sentinelforge-repository-20260927.md"),
        ("a" * 80 + ".zip", f"sentinelforge-{'a' * 40}-20260927.md"),
    ],
)
def test_the_download_name_is_built_only_from_safe_characters(origin: str, expected: str) -> None:
    name = filename_for(origin, NOW, ReportFormat.MARKDOWN)

    assert name == expected
    assert re.fullmatch(r"sentinelforge-[a-z0-9]+(-[a-z0-9]+)*-\d{8}\.md", name)


def test_each_format_gets_its_own_extension_and_the_date_is_utc() -> None:
    late = datetime(2026, 9, 28, 2, 0, tzinfo=timezone(timedelta(hours=5, minutes=30)))

    assert filename_for("a.zip", late, ReportFormat.HTML) == "sentinelforge-a-20260927.html"
    assert filename_for("a.zip", NOW, ReportFormat.SARIF).endswith(".sarif")
    assert filename_for("a.zip", NOW, ReportFormat.JSON).endswith(".json")
