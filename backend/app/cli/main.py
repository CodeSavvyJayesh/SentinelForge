"""Arguments in, an exit code out.

Exit codes are the interface, so there are exactly three and they never mean
two things:

* ``0`` — the scan ran and the gate passed.
* ``1`` — the scan ran and the gate failed. The code under test is the problem.
* ``2`` — the scan could not be run as asked. The invocation is the problem.

A pipeline that cannot tell 1 from 2 either blocks a merge because of a typo in
its own configuration, or lets one through because the scanner crashed.
"""

import argparse
import json
import os
import sys
import unicodedata
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from app.cli import baseline as baseline_file
from app.cli.gate import DEFAULT_FAIL_ON, FAIL_ON_CHOICES, MAX_LISTED, Gate, GateResult, evaluate
from app.cli.scan import ScanOptions, ScanOutcome, scan
from app.reports import html as html_report
from app.reports import markdown as markdown_report
from app.reports import sarif as sarif_report
from app.reports.model import Report
from app.schemas.report import ReportRead

EXIT_PASSED = 0
EXIT_GATE_FAILED = 1
EXIT_ERROR = 2


def plain(value: object) -> str:
    """Text from a scanned repository, made safe to print.

    A file can be *named* with an escape sequence in it, and a terminal will
    obey one: move the cursor, recolour the screen, rewrite the line above. A
    build log has a second problem — a line that begins with ``::`` is a
    command to the GitHub Actions runner. So every control and formatting
    character, including the line breaks that would let text start a line of
    its own, is replaced before anything is written.
    """
    return "".join(
        "?" if unicodedata.category(character) in {"Cc", "Cf", "Zl", "Zp"} else character
        for character in str(value)
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.cli",
        description="Scan a folder with SentinelForge and fail the build on what it finds.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    scan_command = commands.add_parser(
        "scan",
        help="analyse a folder; nothing in it is executed",
        description=(
            "Analyse a folder and judge the result. Exit code 0: passed. "
            "1: the gate failed. 2: the scan could not be run."
        ),
    )
    scan_command.add_argument("path", type=Path, help="the folder to scan")
    scan_command.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        default=DEFAULT_FAIL_ON,
        help=(
            f"fail when a finding of this severity or worse is present (default: {DEFAULT_FAIL_ON})"
        ),
    )
    scan_command.add_argument(
        "--max-score",
        type=float,
        default=None,
        metavar="N",
        help="also fail when the repository's risk score (0-100) is above N",
    )
    scan_command.add_argument(
        "--baseline",
        type=Path,
        default=None,
        metavar="SARIF",
        help="SARIF from an earlier run; only findings that are not in it can fail the build",
    )
    scan_command.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help=(
            "leave out findings under this path or glob (repeatable); "
            "the number left out is printed"
        ),
    )
    for name, description in (
        ("sarif", "SARIF 2.1.0, for GitHub code scanning"),
        ("markdown", "Markdown, for a job summary or an issue"),
        ("html", "a self-contained HTML page"),
        ("json", "the report as data"),
    ):
        scan_command.add_argument(
            f"--{name}", type=Path, default=None, metavar="FILE", help=f"write {description}"
        )
    scan_command.add_argument("--name", default=None, help="what to call the project in reports")
    scan_command.add_argument("--max-findings", type=int, default=None, metavar="N")
    scan_command.add_argument("--max-file-bytes", type=int, default=None, metavar="N")
    scan_command.add_argument(
        "--quiet", action="store_true", help="print the verdict only, not each finding"
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    environ: dict[str, str] | None = None,
) -> int:
    out = stdout or sys.stdout
    err = stderr or sys.stderr
    # A Windows console may not be able to encode a character from a file name.
    # That must cost a "?" in the log, not a traceback and the wrong exit code.
    for stream in (out, err):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="replace")
    env = os.environ if environ is None else environ
    try:
        arguments = build_parser().parse_args(argv)
    except SystemExit as exit_:
        # argparse exits 2 for a bad argument and 0 for --help; both are kept.
        return int(exit_.code or 0)

    root = arguments.path
    if not root.is_dir():
        print(f"error: not a folder: {plain(root)}", file=err)
        return EXIT_ERROR
    for label, limit in (("--max-findings", arguments.max_findings),
                         ("--max-file-bytes", arguments.max_file_bytes)):  # fmt: skip
        if limit is not None and limit < 1:
            print(f"error: {label} must be at least 1", file=err)
            return EXIT_ERROR
    if arguments.max_score is not None and not 0 <= arguments.max_score <= 100:
        print("error: --max-score must be between 0 and 100", file=err)
        return EXIT_ERROR

    known: frozenset[str] | None = None
    if arguments.baseline is not None:
        try:
            known = baseline_file.load(arguments.baseline)
        except baseline_file.BaselineError as exc:
            print(f"error: {plain(exc)}", file=err)
            return EXIT_ERROR

    root = root.resolve()
    outcome = scan(root, _options(arguments, root, env))
    gate = Gate(fail_on=arguments.fail_on, max_score=arguments.max_score)
    result = evaluate(outcome.report, gate, baseline=known)

    try:
        _write_files(arguments, outcome.report, known)
    except OSError as exc:
        print(f"error: could not write a report: {plain(exc)}", file=err)
        return EXIT_ERROR

    _print_summary(out, outcome, result, gate, known, quiet=arguments.quiet)
    return EXIT_PASSED if result.passed else EXIT_GATE_FAILED


def _options(arguments: argparse.Namespace, root: Path, env: dict[str, str]) -> ScanOptions:
    """Where the code came from, taken from the pipeline when it says.

    GitHub Actions describes the checkout in environment variables. They are
    read rather than asking git, because asking git means running a program
    inside a folder this tool was told not to trust.
    """
    repository = env.get("GITHUB_REPOSITORY", "")
    server = env.get("GITHUB_SERVER_URL", "")
    origin = f"{server}/{repository}" if server and repository else root.name
    return ScanOptions(
        name=arguments.name or repository or root.name or "repository",
        origin=origin or "repository",
        branch=env.get("GITHUB_REF_NAME") or None,
        commit=env.get("GITHUB_SHA") or None,
        excludes=tuple(arguments.exclude),
        max_file_bytes=arguments.max_file_bytes,
        max_findings=arguments.max_findings,
    )


def _write_files(
    arguments: argparse.Namespace, report: Report, known: frozenset[str] | None
) -> None:
    documents = {
        arguments.sarif: lambda: (
            json.dumps(sarif_report.render(report, baseline=known), indent=2, ensure_ascii=False)
            + "\n"
        ),
        arguments.markdown: lambda: markdown_report.render(report),
        arguments.html: lambda: html_report.render(report),
        arguments.json: lambda: ReportRead.from_report(report).model_dump_json(indent=2) + "\n",
    }
    for path, render in documents.items():
        if path is None:
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        # newline="" so the file has the same bytes on every platform: a SARIF
        # uploaded from Windows should not differ from one built on Linux.
        with path.open("w", encoding="utf-8", newline="") as handle:
            handle.write(render())


def _print_summary(  # noqa: PLR0913 - one argument per thing the summary states
    out: TextIO,
    outcome: ScanOutcome,
    result: GateResult,
    gate: Gate,
    known: frozenset[str] | None,
    *,
    quiet: bool,
) -> None:
    report = outcome.report
    write = lambda line="": print(line, file=out)  # noqa: E731

    write(f"SentinelForge {report.tool_version}: {plain(report.project_name)}")
    write(
        f"  {report.scan.files_scanned} files analysed, {report.open_count} "
        f"finding{'' if report.open_count == 1 else 's'}, risk {report.score:g}/100 "
        f"(grade {report.grade})"
    )
    counts = ", ".join(
        f"{count} {severity.lower()}" for severity, count in report.counts_by_severity.items()
    )
    write(f"  {counts}")
    if known is not None:
        fresh = sum(1 for finding in report.findings if finding.fingerprint not in known)
        write(f"  {fresh} new since the baseline, {report.open_count - fresh} already known")
    if outcome.excluded:
        write(f"  {outcome.excluded} left out by --exclude")
    if report.scan.truncated:
        write(
            "  INCOMPLETE: the analyser stopped at its limit on findings; these are a lower bound"
        )

    if not quiet and report.findings:
        write()
        for finding in report.findings:
            marker = ""
            if known is not None:
                marker = " [known]" if finding.fingerprint in known else " [new]"
            write(
                f"  {finding.severity:<8} {plain(finding.rule_id):<7} "
                f"{plain(finding.file_path)}:{finding.line_start}  "
                f"{plain(finding.title)}{marker}"
            )

    write()
    if result.passed:
        scope = "no new findings" if known is not None else "nothing"
        threshold = (
            "the severity check is off"
            if gate.fail_on == "none"
            else f"{scope} at {gate.fail_on.upper()} or above"
        )
        write(f"PASSED: {threshold}.")
        return
    write("FAILED")
    for reason in result.reasons:
        write(f"  {reason}")
    for finding in result.blocking[:MAX_LISTED]:
        write(
            f"    {finding.severity} {plain(finding.rule_id)} "
            f"{plain(finding.file_path)}:{finding.line_start}"
        )
    if len(result.blocking) > MAX_LISTED:
        write(f"    … and {len(result.blocking) - MAX_LISTED} more")


__all__ = ["EXIT_ERROR", "EXIT_GATE_FAILED", "EXIT_PASSED", "build_parser", "main", "plain"]
