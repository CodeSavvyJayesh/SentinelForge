"""``python -m app.cli fix`` — propose a fix for one finding, and check it.

The scan says what is wrong. This says what to change, and it does not ask to
be believed: the change is applied to a throwaway copy of the folder and the
copy is scanned again before anything is reported as a fix.

Exit codes follow the scanner's rule that a number never means two things:

* ``0`` — a change was found and the re-scan supports it.
* ``1`` — the command ran and there is no change to offer: no built-in fix
  for this rule, or the proposal was refused, or the re-scan rejected it.
* ``2`` — the command could not be run as asked.

By default nothing is written. ``--apply`` writes a change that passed the
re-scan, and only that.
"""

import argparse
import json
import os
import shutil
from dataclasses import asdict
from pathlib import Path
from typing import Any, TextIO

from app.analysis.engine import analyze_workspace
from app.analysis.findings import Finding
from app.cli.scan import ScanOptions, analysis_settings
from app.cli.text import plain
from app.core.config import Settings
from app.fixing import local
from app.fixing.local import BUILTIN, MODEL, MODES, FixError, FixResult
from app.llm.client import LlmError, OllamaClient

EXIT_VERIFIED = 0
EXIT_NO_FIX = 1
EXIT_ERROR = 2

SCHEMA = 1
# A fix is one generation; the scanner's own limit is for a whole scan.
DEFAULT_TIMEOUT_SECONDS = 300
TEMPORARY_SUFFIX = ".sentinelforge-tmp"


def _default(name: str) -> Any:  # noqa: ANN401 - whatever type the setting has
    return Settings.model_fields[name].default


def add_parser(commands: argparse._SubParsersAction) -> None:
    command = commands.add_parser(
        "fix",
        help="propose a fix for one finding and check it by scanning again",
        description=(
            "Propose a change for one finding, apply it to a throwaway copy and scan the "
            "copy. Exit code 0: the re-scan supports the change. 1: there is no change to "
            "offer. 2: the command could not be run. Nothing is written unless --apply."
        ),
    )
    command.add_argument("path", type=Path, help="the folder the finding is in")
    which = command.add_mutually_exclusive_group(required=True)
    which.add_argument(
        "--fingerprint", metavar="HEX", help="the finding's fingerprint, from a report"
    )
    which.add_argument("--at", metavar="FILE:LINE", help="the finding's file and line")
    command.add_argument("--rule", metavar="ID", help="with --at, when a line has several")
    command.add_argument(
        "--mode",
        choices=MODES,
        default=BUILTIN,
        help=(
            f"{BUILTIN}: a mechanical rewrite, no model needed (default). "
            f"{MODEL}: ask the local model"
        ),
    )
    command.add_argument("--json", type=Path, default=None, metavar="FILE", help="write the result")
    command.add_argument(
        "--apply", action="store_true", help="write the change to the file, if it passed"
    )
    command.add_argument(
        "--ollama-url", default=_default("OLLAMA_BASE_URL"), metavar="URL", help="the local model"
    )
    command.add_argument("--model", default=_default("OLLAMA_MODEL"), metavar="NAME")
    command.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS, metavar="SECONDS")
    command.add_argument(
        "--allow-remote-model",
        action="store_true",
        help="allow --ollama-url to be another machine; the code is then sent to it",
    )
    command.add_argument(
        "--retry",
        action="store_true",
        help="ask the model a slightly different question than the first time",
    )


def run(arguments: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    root = arguments.path
    if not root.is_dir():
        print(f"error: not a folder: {plain(root)}", file=err)
        return EXIT_ERROR
    root = root.resolve()
    settings = analysis_settings(ScanOptions(name=root.name, origin=root.name))

    try:
        fingerprint = arguments.fingerprint or _fingerprint_at(root, arguments, settings)
        llm = _model(arguments) if arguments.mode == MODEL else None
        result = local.fix(
            root,
            fingerprint,
            mode=arguments.mode,
            settings=settings,
            llm=llm,
            retry=arguments.retry,
        )
        applied = arguments.apply and result.verified
        if applied:
            _write_change(root, result)
    except FixError as error:
        print(f"error: {plain(error)}", file=err)
        return EXIT_ERROR

    if arguments.json is not None:
        try:
            arguments.json.parent.mkdir(parents=True, exist_ok=True)
            with arguments.json.open("w", encoding="utf-8", newline="") as handle:
                handle.write(json.dumps(as_data(result, applied=applied), indent=2) + "\n")
        except OSError as exc:
            print(f"error: could not write the result: {plain(exc)}", file=err)
            return EXIT_ERROR

    _print(out, result, applied=applied)
    return EXIT_VERIFIED if result.verified else EXIT_NO_FIX


def _model(arguments: argparse.Namespace) -> OllamaClient:
    if arguments.timeout < 1:
        raise FixError("--timeout must be at least 1")
    if not arguments.allow_remote_model and not local.is_loopback(arguments.ollama_url):
        # The prompt contains the code around the finding. Sending that to
        # another machine is a decision, so it takes a flag and never a default.
        raise FixError(
            "The model URL is not on this machine, and asking it for a fix would send it "
            "your code. Use a local Ollama, or pass --allow-remote-model."
        )
    try:
        return OllamaClient(
            arguments.ollama_url,
            model=arguments.model,
            timeout_seconds=arguments.timeout,
            temperature=_default("OLLAMA_TEMPERATURE"),
            max_tokens=_default("OLLAMA_MAX_TOKENS"),
            context_tokens=_default("OLLAMA_CONTEXT_TOKENS"),
        )
    except LlmError as error:
        raise FixError(error.message) from error


def _fingerprint_at(root: Path, arguments: argparse.Namespace, settings: Settings) -> str:
    """The finding on a given line, when the caller has no fingerprint."""
    file_path, separator, line_text = arguments.at.rpartition(":")
    if not separator or not line_text.isdigit():
        raise FixError("--at takes FILE:LINE, for example app/main.py:12")
    file_path = file_path.replace("\\", "/").removeprefix("./")
    line = int(line_text)
    matches: list[Finding] = [
        item
        for item in analyze_workspace(root, settings).findings
        if item.file_path == file_path
        and item.line_start <= line <= max(item.line_end, item.line_start)
        and arguments.rule in (None, item.rule_id)
    ]
    if not matches:
        raise FixError(f"No finding at {file_path}:{line}. Run a scan to see where they are.")
    if len(matches) > 1:
        rules = ", ".join(sorted({item.rule_id for item in matches}))
        raise FixError(f"Several findings are on that line ({rules}). Choose one with --rule.")
    return matches[0].fingerprint


def _write_change(root: Path, result: FixResult) -> None:
    """Write a change that passed, unless the file has moved on since.

    Written beside the file and moved into place, so a failure half way leaves
    the original untouched rather than half a file.
    """
    target = root / result.finding.file_path
    try:
        with target.open(encoding="utf-8", newline="") as handle:
            current = handle.read()
        if current != "".join(result.before):
            raise FixError(
                "The file changed while the fix was being checked, so nothing was written. "
                "Run the command again."
            )
        temporary = target.with_name(target.name + TEMPORARY_SUFFIX)
        try:
            with temporary.open("w", encoding="utf-8", newline="") as handle:
                handle.write("".join(result.after))
            shutil.copymode(target, temporary)
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
    except (OSError, UnicodeError) as exc:
        raise FixError(f"The change could not be written: {exc}") from exc


def as_data(result: FixResult, *, applied: bool) -> dict[str, Any]:
    finding = result.finding
    outcome = result.outcome
    return {
        "schema": SCHEMA,
        "status": result.status,
        "source": result.source,
        "finding": {
            "rule_id": finding.rule_id,
            "title": finding.title,
            "file_path": finding.file_path,
            "line_start": finding.line_start,
            "line_end": finding.line_end,
            "fingerprint": finding.fingerprint,
        },
        "title": result.title,
        "rationale": result.rationale,
        "caution": result.caution,
        "reason": result.reason,
        "diff": result.diff,
        "lines_added": result.lines_added,
        "lines_removed": result.lines_removed,
        "edits": [
            {
                "first_line": edit.first_line,
                "last_line": edit.last_line,
                "old": list(edit.old),
                "new": list(edit.new),
            }
            for edit in result.edits
        ],
        "validation": None
        if outcome is None
        else {
            "passed": outcome.passed,
            "checks": [check.as_dict() for check in outcome.checks],
            "findings_before": outcome.findings_before,
            "findings_after": outcome.findings_after,
            "also_resolved": outcome.also_resolved,
            "new_findings": outcome.new_findings,
        },
        "model": None if result.model is None else asdict(result.model),
        "applied": applied,
    }


def _print(out: TextIO, result: FixResult, *, applied: bool) -> None:
    write = lambda line="": print(line, file=out)  # noqa: E731
    finding = result.finding
    write(
        f"SentinelForge fix: {plain(finding.rule_id)} "
        f"{plain(finding.file_path)}:{finding.line_start}  {plain(finding.title)}"
    )
    source = "built-in" if result.source == BUILTIN else "local model"
    if result.model is not None:
        source = f"{source} ({plain(result.model.model)})"
    write(f"  {source}: {plain(result.title)}")
    if result.rationale:
        write(f"  {plain(result.rationale)}")

    if result.diff:
        write()
        for line in result.diff.splitlines():
            write(f"  {plain(line)}")
    if result.outcome is not None:
        write()
        write("  Checked by scanning a copy with the change applied:")
        for check in result.outcome.checks:
            write(f"    [{check.outcome}] {plain(check.detail)}")

    write()
    if result.verified:
        if result.caution:
            write(f"  Before you accept it: {plain(result.caution)}")
        write(
            "VERIFIED: the finding is gone and the re-scan found nothing new. "
            + ("The file was changed." if applied else "Nothing was written.")
        )
        write(
            "  This says the scanner no longer detects it. It does not say the program "
            "behaves the same: nothing in the folder was run."
        )
        return
    label = "REJECTED" if result.status == local.REJECTED else "NO FIX"
    write(f"{label}: {plain(result.reason or 'There is no change to offer.')}")


__all__ = ["EXIT_ERROR", "EXIT_NO_FIX", "EXIT_VERIFIED", "add_parser", "as_data", "run"]
