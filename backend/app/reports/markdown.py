"""The report as Markdown.

Markdown is a format where text and markup share one alphabet, so anything
copied out of a repository has to be made inert before it is written: a file
called ``](http://example.test)`` or a snippet containing three backticks would
otherwise restructure the document around itself.

Two rules cover it:

* prose (a project name, a finding's message) goes through :func:`text`, which
  neutralises every character Markdown or inline HTML gives meaning to;
* code (a path, a snippet) goes inside a code span or fence whose delimiter is
  longer than any run of backticks in the content, which is the one way the
  CommonMark specification guarantees the content cannot end it early.
"""

import re

from app.reports.model import Report, ReportFinding, format_when

_BACKTICKS = re.compile(r"`+")
_SPECIAL = re.compile(r"([\\`*_\[\]|#~])")
_LIST_MARKER = re.compile(r"^([-+=]|\d+(?=[.)]))")


def text(value: str | None) -> str:
    """Untrusted prose for use **inside** a line. Always a single line."""
    if not value:
        return ""
    flat = " ".join(value.split())
    flat = flat.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return _SPECIAL.sub(r"\\\1", flat)


def paragraph(value: str | None) -> str:
    """Untrusted prose that **starts** a line.

    At the start of a line a few more characters mean something: "-" and "+"
    begin a list, "1." begins a numbered one, and a row of "=" turns the line
    above into a heading.
    """
    flat = text(value)
    match = _LIST_MARKER.match(flat)
    if match is None:
        return flat
    marker = match.group(1)
    if marker.isdigit():
        return f"{marker}\\{flat[len(marker) :]}"
    return f"\\{flat}"


def code_span(value: str | None) -> str:
    """Untrusted text as inline code that cannot close its own span."""
    flat = " ".join((value or "").split())
    if not flat:
        return ""
    longest = max((len(run) for run in _BACKTICKS.findall(flat)), default=0)
    fence = "`" * (longest + 1)
    # A span that starts or ends with a backtick needs padding to be parsed.
    padding = " " if flat.startswith("`") or flat.endswith("`") else ""
    # A pipe would end a table cell even inside code.
    return f"{fence}{padding}{flat}{padding}{fence}".replace("|", "\\|")


def code_block(value: str) -> str:
    """Untrusted text as a fenced block that cannot close its own fence."""
    body = value.replace("\r\n", "\n").replace("\r", "\n").strip("\n")
    longest = max((len(run) for run in _BACKTICKS.findall(body)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}\n{body}\n{fence}"


def render(report: Report) -> str:
    lines: list[str] = []
    add = lines.append

    add(f"# Security report: {text(report.project_name)}")
    add("")
    add(
        f"Generated {format_when(report.generated_at)} by {report.tool_name} "
        f"{text(report.tool_version)}."
    )
    add("")
    add("| | |")
    add("| --- | --- |")
    add(f"| Repository | {code_span(report.origin)} |")
    if report.branch:
        add(f"| Branch | {code_span(report.branch)} |")
    if report.commit_hash:
        add(f"| Commit | {code_span(report.commit_hash)} |")
    if report.primary_language:
        add(f"| Main language | {text(report.primary_language)} |")
    add(f"| Last scan | {format_when(report.scan.finished_at)} (scan {report.scan.id}) |")
    add(f"| Files analysed | {report.scan.files_scanned} |")
    if report.scan.unparsable_files:
        add(f"| Files that could not be parsed | {report.scan.unparsable_files} |")
    add("")

    add("## Summary")
    add("")
    add(
        f"**Risk grade {report.grade}** ({report.score:g} out of 100, scoring policy "
        f"v{report.policy_version}): {report.grade_label}."
    )
    add("")
    add(
        f"- Open findings: **{report.open_count}** ({report.new_count} first seen in the last scan)"
    )
    add(f"- Fixed findings: **{report.fixed_count}**")
    add("")
    if report.scan.truncated:
        add(
            "> **Incomplete.** The analyser reached its limit on findings and stopped, so the "
            "numbers in this report are a lower bound."
        )
        add("")
    add("| Severity | Open findings |")
    add("| --- | ---: |")
    for severity, count in report.counts_by_severity.items():
        add(f"| {severity} | {count} |")
    add("")

    add("## What to fix, by rule")
    add("")
    if not report.rules:
        add("No open findings.")
        add("")
    for rule in report.rules:
        add(f"### {text(rule.rule_id)}: {text(rule.title)}")
        add("")
        facts = [
            f"{rule.count} open finding{'' if rule.count == 1 else 's'}",
            f"worst severity {rule.worst_severity}",
        ]
        if rule.cwe_id:
            facts.append(text(rule.cwe_id))
        if rule.owasp_category:
            facts.append(text(rule.owasp_category))
        add(" · ".join(facts))
        add("")
        if rule.risk_note:
            add(f"**Risk.** {text(rule.risk_note)}")
            add("")
        if rule.fix_note:
            add(f"**Fix.** {text(rule.fix_note)}")
            add("")

    add("## Open findings")
    add("")
    if not report.findings:
        add("None. These rules matched nothing in the last scan.")
        add("")
    for number, finding in enumerate(report.findings, start=1):
        lines.extend(_finding(number, finding))

    if report.fixed:
        add("## Fixed findings")
        add("")
        add("Present in an earlier scan and gone from the last one.")
        add("")
        add("| Severity | Rule | Finding | Location |")
        add("| --- | --- | --- | --- |")
        for finding in report.fixed:
            add(
                f"| {finding.severity} | {text(finding.rule_id)} | {text(finding.title)} | "
                f"{code_span(f'{finding.file_path}:{finding.line_start}')} |"
            )
        add("")

    add("## What this report does not claim")
    add("")
    for limitation in report.limitations:
        add(f"- {limitation}")
    add("")
    return "\n".join(lines)


def _finding(number: int, finding: ReportFinding) -> list[str]:
    classification = [text(finding.rule_id)]
    if finding.cwe_id:
        classification.append(text(finding.cwe_id))
    if finding.owasp_category:
        classification.append(text(finding.owasp_category))
    lines = [
        f"### {number}. {finding.severity}: {text(finding.title)}",
        "",
        f"- Location: {code_span(f'{finding.file_path}:{finding.line_start}')}",
        f"- Rule: {' · '.join(classification)}",
        f"- Confidence: {finding.confidence} · State: {finding.status}",
        f"- Risk: {finding.score:g} ({code_span(finding.score_explanation)})",
        f"- Fix: {finding.fix_label}",
        "",
        paragraph(finding.message),
        "",
    ]
    if finding.snippet.strip():
        lines += [code_block(finding.snippet), ""]
    return lines


__all__ = ["code_block", "code_span", "paragraph", "render", "text"]
