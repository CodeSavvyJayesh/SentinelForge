"""Java: the line patterns, corrected and extended by the flow walk.

For a Java file, :func:`analyze_java` runs the same line patterns as every
other language, then reads the file with :mod:`app.analysis.java_flow` and
does two things with what the walk found:

* **Withdraws a SQL report** whose every joined value the walk showed to be a
  constant. Only on lines the walk read inside a method it finished; a line it
  did not reach keeps its report.
* **Adds reports** for request data reaching a command, a file path, an LDAP
  search, an XPath expression, the response page or the session, and for a
  query that reaches the database without passing a line the pattern reported
  — `"{call " + name + "}"`, or a query built with `String.format`.

If the file cannot be read as Java, the patterns' findings stand unchanged.
"""

from __future__ import annotations

from collections.abc import Iterable

from app.analysis import java_flow
from app.analysis.findings import Finding, clean_snippet
from app.analysis.patterns import SQL_STATEMENT, analyze_with_patterns
from app.analysis.rules import (
    JAVA_COMMAND_FROM_REQUEST,
    JAVA_LDAP_FROM_REQUEST,
    JAVA_PATH_FROM_REQUEST,
    JAVA_TRUST_BOUNDARY,
    JAVA_XPATH_FROM_REQUEST,
    JAVA_XSS_FROM_REQUEST,
    SQL_CONCATENATION,
    Rule,
)

JAVA_SUFFIXES = frozenset({".java"})
ANALYZER = "java-flow"

RULE_FOR_KIND: dict[str, Rule] = {
    java_flow.COMMAND: JAVA_COMMAND_FROM_REQUEST,
    java_flow.PATH: JAVA_PATH_FROM_REQUEST,
    java_flow.LDAP: JAVA_LDAP_FROM_REQUEST,
    java_flow.XPATH: JAVA_XPATH_FROM_REQUEST,
    java_flow.HTML: JAVA_XSS_FROM_REQUEST,
    java_flow.TRUST: JAVA_TRUST_BOUNDARY,
    java_flow.SQL: SQL_CONCATENATION,
}


def build_project(files: Iterable[tuple[str, str]]) -> java_flow.Project:
    """Every Java file of an analysis, so calls between them can be followed.

    Nothing is parsed here: a file is read when the walk first needs one of
    its classes. A file that cannot be read is then treated as a library.
    """
    project = java_flow.Project()
    for path, source in files:
        project.add_source(path, source)
    return project


# Request data enters a method through a request object or a parameter Spring
# fills from the request. A file that names neither has no request data of its
# own, and its methods are walked only to check a SQL report it already has.
REQUEST_MARKERS = (
    "ServletRequest",
    "RequestParam",
    "PathVariable",
    "RequestHeader",
    "CookieValue",
    "RequestBody",
    "MatrixVariable",
)


def may_read_request(source: str) -> bool:
    return any(marker in source for marker in REQUEST_MARKERS)


def analyze_java(
    source: str, file_path: str, suffix: str = ".java", project: java_flow.Project | None = None
) -> list[Finding]:
    findings = analyze_with_patterns(source, file_path, suffix)
    reads_request = may_read_request(source)
    sql_lines = [
        finding.line_start for finding in findings if finding.rule_id == SQL_CONCATENATION.id
    ]
    if not reads_request and not sql_lines:
        return findings  # nothing for the walk to add or to withdraw
    if project is None or file_path not in project.sources:
        project = project if project is not None else java_flow.Project()
        project.add_source(file_path, source)
    unit = project.unit(file_path)
    if unit is None:
        return findings  # not readable as Java: the patterns' findings stand
    report = java_flow.analyse(
        unit, file_path, project, SQL_STATEMENT, only_lines=None if reads_request else sql_lines
    )
    lines = source.splitlines()

    kept = [finding for finding in findings if not _withdrawn(finding, report)]
    reported_sql = [
        finding.line_start for finding in kept if finding.rule_id == SQL_CONCATENATION.id
    ]
    for hit in report.hits:
        if hit.kind == java_flow.SQL and _same_method(hit.line, reported_sql, report):
            continue  # the query is already reported where it was built
        kept.append(_finding(RULE_FOR_KIND[hit.kind], file_path, hit.line, lines))
    return kept


def _withdrawn(finding: Finding, report: java_flow.FileReport) -> bool:
    if finding.rule_id != SQL_CONCATENATION.id:
        return False
    line = finding.line_start
    if _inside(line, report.unreadable) or not _inside(line, report.methods):
        return False
    return report.sql_joins.get(line) is True


def _inside(line: int, ranges: list[tuple[int, int]]) -> bool:
    return any(first <= line <= last for first, last in ranges)


def _same_method(line: int, others: list[int], report: java_flow.FileReport) -> bool:
    for first, last in report.methods:
        if first <= line <= last:
            return any(first <= other <= last for other in others)
    return False


def _finding(rule: Rule, file_path: str, line: int, lines: list[str]) -> Finding:
    raw = lines[line - 1] if 0 < line <= len(lines) else ""
    return Finding(
        rule_id=rule.id,
        title=rule.title,
        message=rule.message,
        severity=rule.severity,
        confidence=rule.confidence,
        cwe_id=rule.cwe_id,
        owasp_category=rule.owasp_category,
        file_path=file_path,
        line_start=line,
        line_end=line,
        snippet=clean_snippet(raw),
        analyzer=ANALYZER,
    )
