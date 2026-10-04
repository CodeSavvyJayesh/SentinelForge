"""The report as one self-contained HTML page.

Meant to be saved, opened and printed (a browser's "Save as PDF" is the PDF
export). So it carries its own styles, loads nothing from anywhere, and runs no
script.

**Every value is escaped, including the ones that look safe.** A report is the
one place in this project where text from an uploaded repository — file paths,
code, a project name — ends up in a document somebody else opens in a browser.
There is no "trusted" branch here to get wrong: :func:`esc` is applied to every
interpolated value, numbers included.

The page also declares a Content-Security-Policy that forbids scripts,
frames, forms and any network request. That is the second lock, not the first:
if an escaping mistake is ever made, the injected markup still cannot run or
call home.
"""

import html

from app.reports.model import Report, ReportFinding, format_when

CONTENT_SECURITY_POLICY = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
    "base-uri 'none'; form-action 'none'"
)

STYLES = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0; padding: 32px 16px; background: #f6f8fa; color: #1f2328;
  font: 15px/1.5 system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif; }
main { max-width: 900px; margin: 0 auto; background: #fff; border: 1px solid #d0d7de;
  border-radius: 10px; padding: 32px 36px; }
h1 { margin: 0 0 4px; font-size: 26px; }
h2 { margin: 32px 0 12px; padding-bottom: 6px; border-bottom: 1px solid #d0d7de; font-size: 19px; }
h3 { margin: 0 0 6px; font-size: 15px; }
p { margin: 0 0 10px; }
code, pre { font-family: ui-monospace, 'Cascadia Code', Consolas, monospace; font-size: 13px; }
code { background: #f0f3f6; border-radius: 4px; padding: 1px 5px; overflow-wrap: anywhere; }
pre { margin: 8px 0 0; padding: 10px 12px; background: #f6f8fa; border: 1px solid #d0d7de;
  border-radius: 6px; overflow-x: auto; white-space: pre-wrap; overflow-wrap: anywhere; }
pre code { background: none; padding: 0; }
.muted { color: #59636e; }
.small { font-size: 13px; }
.facts { display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; margin: 16px 0 0; }
.facts dt { color: #59636e; }
.facts dd { margin: 0; overflow-wrap: anywhere; }
.summary { display: flex; flex-wrap: wrap; gap: 12px; }
.tile { flex: 1 1 150px; border: 1px solid #d0d7de; border-radius: 8px; padding: 10px 14px; }
.tile .label { color: #59636e; font-size: 13px; }
.tile .value { font-size: 26px; font-weight: 650; line-height: 1.2; }
.warning { margin: 16px 0 0; padding: 10px 14px; border: 1px solid #9a6700;
  border-left-width: 4px; border-radius: 6px; background: #fff8c5; }
table { width: 100%; border-collapse: collapse; margin: 0; }
th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #d0d7de;
  vertical-align: top; }
thead th { color: #59636e; font-size: 12px; text-transform: uppercase; letter-spacing: .05em; }
td.number, th.number { text-align: right; font-variant-numeric: tabular-nums; }
.bar { display: block; height: 8px; min-width: 1px; background: #0f766e;
  border-radius: 0 4px 4px 0; }
.bar-cell { width: 55%; border-left: 1px solid #d0d7de; padding-left: 0; vertical-align: middle; }
.item { margin: 0 0 14px; padding: 12px 14px; border: 1px solid #d0d7de; border-radius: 8px;
  break-inside: avoid; }
.tag { display: inline-block; margin-right: 6px; padding: 0 6px; border: 1px solid #59636e;
  border-radius: 4px; font-size: 11px; font-weight: 700; letter-spacing: .04em; }
.meta { margin: 0 0 6px; color: #59636e; font-size: 13px; }
.fix { margin: 6px 0 0; font-size: 13px; }
ul { margin: 0; padding-left: 20px; }
li { margin-bottom: 6px; }
footer { margin-top: 28px; color: #59636e; font-size: 12px; }
@page { margin: 16mm; }
@media print {
  body { padding: 0; background: #fff; }
  main { border: 0; border-radius: 0; padding: 0; max-width: none; }
  h2 { break-after: avoid; }
}
"""


def esc(value: object) -> str:
    """Escape for both element content and a quoted attribute."""
    return html.escape("" if value is None else str(value), quote=True)


def render(report: Report) -> str:
    parts: list[str] = []
    add = parts.append

    add("<!doctype html>")
    add('<html lang="en">')
    add("<head>")
    add('<meta charset="utf-8">')
    add(f'<meta http-equiv="Content-Security-Policy" content="{esc(CONTENT_SECURITY_POLICY)}">')
    add('<meta name="viewport" content="width=device-width, initial-scale=1">')
    add('<meta name="referrer" content="no-referrer">')
    add(f"<title>Security report: {esc(report.project_name)}</title>")
    add(f"<style>{STYLES}</style>")
    add("</head>")
    add("<body>")
    add("<main>")

    add(f"<h1>Security report: {esc(report.project_name)}</h1>")
    add(
        f'<p class="muted">Generated {esc(format_when(report.generated_at))} by '
        f"{esc(report.tool_name)} {esc(report.tool_version)}.</p>"
    )
    add('<dl class="facts">')
    add(_fact("Repository", f"<code>{esc(report.origin)}</code>"))
    if report.branch:
        add(_fact("Branch", f"<code>{esc(report.branch)}</code>"))
    if report.commit_hash:
        add(_fact("Commit", f"<code>{esc(report.commit_hash)}</code>"))
    if report.primary_language:
        add(_fact("Main language", esc(report.primary_language)))
    add(
        _fact(
            "Last scan",
            f"{esc(format_when(report.scan.finished_at))} (scan {esc(report.scan.id)})",
        )
    )
    add(_fact("Files analysed", esc(report.scan.files_scanned)))
    if report.scan.unparsable_files:
        add(_fact("Files that could not be parsed", esc(report.scan.unparsable_files)))
    add("</dl>")

    add("<h2>Summary</h2>")
    add('<div class="summary">')
    add(_tile("Risk grade", report.grade, report.grade_label))
    add(_tile("Risk score", f"{report.score:g}", f"out of 100, policy v{report.policy_version}"))
    add(
        _tile("Open findings", report.open_count, f"{report.new_count} first seen in the last scan")
    )
    add(_tile("Fixed findings", report.fixed_count, "gone from the last scan"))
    add("</div>")
    if report.scan.truncated:
        add(
            '<p class="warning"><strong>Incomplete.</strong> The analyser reached its limit on '
            "findings and stopped, so the numbers in this report are a lower bound.</p>"
        )

    add("<h2>Open findings by severity</h2>")
    largest = max(report.counts_by_severity.values(), default=0)
    add("<table>")
    add(
        '<thead><tr><th scope="col">Severity</th><th scope="col" class="number">Open</th>'
        '<th scope="col"><span class="muted">Share of the largest</span></th></tr></thead>'
    )
    add("<tbody>")
    for severity, count in report.counts_by_severity.items():
        width = 0 if largest <= 0 or count <= 0 else max(2, round(count / largest * 100))
        bar = f'<span class="bar" style="width:{esc(width)}%"></span>' if width else ""
        add(
            f'<tr><th scope="row">{esc(severity)}</th><td class="number">{esc(count)}</td>'
            f'<td class="bar-cell">{bar}</td></tr>'
        )
    add("</tbody></table>")

    add("<h2>What to fix, by rule</h2>")
    if not report.rules:
        add('<p class="muted">No open findings.</p>')
    for rule in report.rules:
        facts = [
            f"{rule.count} open finding{'' if rule.count == 1 else 's'}",
            f"worst severity {rule.worst_severity}",
        ]
        facts += [value for value in (rule.cwe_id, rule.owasp_category) if value]
        add('<section class="item">')
        add(f"<h3><code>{esc(rule.rule_id)}</code> {esc(rule.title)}</h3>")
        add(f'<p class="meta">{esc(" · ".join(facts))}</p>')
        if rule.risk_note:
            add(f"<p><strong>Risk.</strong> {esc(rule.risk_note)}</p>")
        if rule.fix_note:
            add(f"<p><strong>Fix.</strong> {esc(rule.fix_note)}</p>")
        add("</section>")

    add("<h2>Open findings</h2>")
    if not report.findings:
        add('<p class="muted">None. These rules matched nothing in the last scan.</p>')
    for number, finding in enumerate(report.findings, start=1):
        add(_finding(number, finding))

    if report.fixed:
        add("<h2>Fixed findings</h2>")
        add('<p class="muted">Present in an earlier scan and gone from the last one.</p>')
        add("<table>")
        add(
            '<thead><tr><th scope="col">Severity</th><th scope="col">Rule</th>'
            '<th scope="col">Finding</th><th scope="col">Location</th></tr></thead>'
        )
        add("<tbody>")
        for finding in report.fixed:
            add(
                f"<tr><td>{esc(finding.severity)}</td><td><code>{esc(finding.rule_id)}</code></td>"
                f"<td>{esc(finding.title)}</td>"
                f"<td><code>{esc(finding.file_path)}:{esc(finding.line_start)}</code></td></tr>"
            )
        add("</tbody></table>")

    add("<h2>What this report does not claim</h2>")
    add("<ul>")
    for limitation in report.limitations:
        add(f"<li>{esc(limitation)}</li>")
    add("</ul>")

    add(
        f"<footer>{esc(report.tool_name)} {esc(report.tool_version)} · repository "
        f"{esc(report.repository_id)} · scan {esc(report.scan.id)}</footer>"
    )
    add("</main>")
    add("</body>")
    add("</html>")
    return "\n".join(parts) + "\n"


def _fact(label: str, value_html: str) -> str:
    return f"<dt>{esc(label)}</dt><dd>{value_html}</dd>"


def _tile(label: str, value: object, note: str) -> str:
    return (
        f'<div class="tile"><div class="label">{esc(label)}</div>'
        f'<div class="value">{esc(value)}</div>'
        f'<div class="small muted">{esc(note)}</div></div>'
    )


def _finding(number: int, finding: ReportFinding) -> str:
    classification = [
        value for value in (finding.rule_id, finding.cwe_id, finding.owasp_category) if value
    ]
    parts = [
        '<article class="item">',
        f'<h3><span class="tag">{esc(finding.severity)}</span>{esc(number)}. '
        f"{esc(finding.title)}</h3>",
        f'<p class="meta"><code>{esc(finding.file_path)}:{esc(finding.line_start)}</code> · '
        f"{esc(' · '.join(classification))} · confidence {esc(finding.confidence)} · "
        f"{esc(finding.status)}</p>",
        f"<p>{esc(finding.message)}</p>",
    ]
    if finding.snippet.strip():
        parts.append(f"<pre><code>{esc(finding.snippet)}</code></pre>")
    parts.append(
        f'<p class="fix"><strong>Risk {esc(f"{finding.score:g}")}.</strong> '
        f"<code>{esc(finding.score_explanation)}</code></p>"
    )
    parts.append(f'<p class="fix"><strong>Fix.</strong> {esc(finding.fix_label)}</p>')
    parts.append("</article>")
    return "\n".join(parts)


__all__ = ["CONTENT_SECURITY_POLICY", "esc", "render"]
