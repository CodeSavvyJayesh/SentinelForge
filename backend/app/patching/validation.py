"""Deciding whether a proposed change did what it claims — by scanning it.

Phase 10 ends with a diff and the word PROPOSED. This module is what can say
more than that, and the only way it is allowed to is the one this project has
promised since its first page: **apply the change to a throwaway copy and run
the analyser again.**

The procedure:

1. Copy every file the analyser would read into a temporary directory.
2. Scan the copy. That is the *before*.
3. Apply the diff there — strictly, see :mod:`app.patching.apply`.
4. Scan it again. That is the *after*.
5. Compare, and record every check with its outcome.

The stored workspace is only ever read. Nothing is executed at any point: the
analyser parses and pattern-matches, exactly as in Phase 5, and no build, test
or script from the repository is run. That rules out the most convincing kind
of validation — running the project's own tests — and it is ruled out on
purpose, because those tests are code somebody uploaded.

So the claim a PASSED verdict makes is narrow, and it is worth stating exactly:
*the finding is no longer detected, nothing new is detected, and the change is
not a deletion.* It does **not** say the program still behaves the same.

**Why "the finding disappeared" is not the verdict.** It is necessary and
nowhere near sufficient, because there are at least three ways to make a finding
disappear without fixing anything:

* delete the code, or swap it for ``pass`` or a comment;
* break the file's syntax — a Python file that does not parse yields no AST
  findings at all, so a typo "resolves" every one of them;
* change the line so the *same rule* fires on different text — MD5 becomes
  SHA-1, the old finding is gone and a new one has taken its place.

Each has a check below. The comparison is also made on what a finding *is* —
rule, file and code — rather than on its stored fingerprint, because the
fingerprint includes an occurrence number: fix the first of two identical
vulnerable lines and the second is renumbered into the first's fingerprint,
which would look exactly like the fix having done nothing.
"""

import ast
import shutil
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from app.analysis.engine import analysable_files, analyze_workspace
from app.analysis.findings import Finding
from app.core.config import Settings
from app.patching import apply as patch_apply
from app.patching import diffing

PASSED = "passed"
FAILED = "failed"
SKIPPED = "skipped"

MAX_LISTED_FINDINGS = 5
TRUNCATED_MESSAGE = (
    "This repository has more findings than one analysis records, so a before-and-after "
    "comparison would be incomplete."
)


class CannotValidate(RuntimeError):
    """The change could not be judged at all. Not a verdict on the change.

    Kept distinct from a rejection on purpose. "This patch is bad" and "this
    patch could not be tested because the code has moved" are different facts,
    and only the first one says anything about the model that wrote it.
    """


@dataclass(frozen=True)
class Check:
    key: str
    outcome: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {"key": self.key, "outcome": self.outcome, "detail": self.detail}


@dataclass
class Outcome:
    checks: list[Check] = field(default_factory=list)
    findings_before: int = 0
    findings_after: int = 0
    # Other findings the change happened to remove. Reported, not rewarded: a
    # fix for one line that makes four findings vanish deserves a second look.
    also_resolved: int = 0
    new_findings: list[dict[str, object]] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(check.outcome != FAILED for check in self.checks)


Identity = tuple[str, str, str]


def identity(finding: Finding) -> Identity:
    """What a finding is, independent of where in the file it sits."""
    return (finding.rule_id, finding.file_path, " ".join(finding.snippet.split()))


def validate(
    workspace: Path,
    file_path: str,
    diff_text: str,
    target_fingerprint: str,
    settings: Settings,
) -> Outcome:
    """Apply ``diff_text`` to a copy of ``workspace`` and compare two scans."""
    try:
        parsed = patch_apply.parse(diff_text)
    except patch_apply.PatchDoesNotApply as exc:
        raise CannotValidate(str(exc)) from exc
    if parsed.old_path != file_path or parsed.new_path != file_path:
        # The diff may only touch the file its own row says it touches.
        raise CannotValidate("The stored change names a different file from the one it is for.")

    root = workspace.resolve()
    if not root.is_dir():
        raise CannotValidate(
            "The stored copy of this repository is missing. Connect the code again."
        )
    if not (root / file_path).resolve().is_relative_to(root):
        raise CannotValidate("That change points outside its repository workspace.")

    with tempfile.TemporaryDirectory(
        prefix="sentinelforge-validate-", ignore_cleanup_errors=True
    ) as scratch:
        copy = Path(scratch)
        _copy_analysable(root, copy, settings)
        patched_file = copy / file_path
        if not patched_file.is_file():
            raise CannotValidate(
                "The file this change is for is not one the analyser reads, so a re-scan "
                "cannot say anything about it."
            )

        before = analyze_workspace(copy, settings)
        if before.truncated:
            raise CannotValidate(TRUNCATED_MESSAGE)
        target = next(
            (item for item in before.findings if item.fingerprint == target_fingerprint), None
        )
        if target is None:
            raise CannotValidate(
                "The finding is no longer in the stored code as it was recorded. Scan again, "
                "then ask for a new change."
            )

        after_lines = _apply_in_place(patched_file, parsed)
        after = analyze_workspace(copy, settings)

    if after.truncated:
        raise CannotValidate(TRUNCATED_MESSAGE)

    return _judge(target, before.findings, after.findings, parsed, file_path, after_lines)


def _copy_analysable(root: Path, destination: Path, settings: Settings) -> None:
    """Copy exactly the files an analysis would read. Never follows a link."""
    for source in analysable_files(root, settings):
        target = destination / source.relative_to(root)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target, follow_symlinks=False)


def _apply_in_place(path: Path, parsed: patch_apply.ParsedDiff) -> list[str]:
    """Patch one file inside the throwaway copy and return its new lines."""
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            original = handle.read().splitlines(keepends=True)
    except UnicodeDecodeError as exc:
        # Rewriting a file in an encoding we guessed at would change bytes the
        # patch never touched, and those would show up as findings appearing
        # and disappearing for no reason.
        raise CannotValidate(
            "That file is not UTF-8, so the change cannot be applied without altering "
            "lines it does not touch."
        ) from exc
    try:
        patched = patch_apply.apply(original, parsed)
    except patch_apply.PatchDoesNotApply as exc:
        raise CannotValidate(str(exc)) from exc
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write("".join(patched))
    return patched


def _judge(
    target: Finding,
    before: list[Finding],
    after: list[Finding],
    parsed: patch_apply.ParsedDiff,
    file_path: str,
    after_lines: list[str],
) -> Outcome:
    outcome = Outcome(findings_before=len(before), findings_after=len(after))
    before_counts = Counter(identity(item) for item in before)
    after_counts = Counter(identity(item) for item in after)
    target_key = identity(target)

    # 1. The finding this change was written for is no longer detected.
    if after_counts[target_key] < before_counts[target_key]:
        outcome.checks.append(
            Check("target_resolved", PASSED, f"The original {target.rule_id} finding is gone.")
        )
    else:
        outcome.checks.append(
            Check(
                "target_resolved",
                FAILED,
                f"{target.rule_id} is still detected on the same code after the change.",
            )
        )

    # 2. Nothing is detected that was not there before.
    appeared = [
        item for item in after if after_counts[identity(item)] > before_counts[identity(item)]
    ]
    seen: set[Identity] = set()
    for item in appeared:
        if identity(item) in seen:
            continue
        seen.add(identity(item))
        if len(outcome.new_findings) < MAX_LISTED_FINDINGS:
            outcome.new_findings.append(
                {
                    "rule_id": item.rule_id,
                    "title": item.title,
                    "severity": str(item.severity),
                    "file_path": item.file_path,
                    "line": item.line_start,
                }
            )
    if not seen:
        outcome.checks.append(
            Check(
                "no_new_findings", PASSED, "The re-scan detects nothing that was not there before."
            )
        )
    elif any(key[0] == target.rule_id and key[1] == target.file_path for key in seen):
        outcome.checks.append(
            Check(
                "no_new_findings",
                FAILED,
                f"{target.rule_id} still fires on the changed code, so the weakness was "
                "reworded rather than removed.",
            )
        )
    else:
        outcome.checks.append(
            Check(
                "no_new_findings",
                FAILED,
                f"The change introduces {len(seen)} finding{'s' if len(seen) != 1 else ''} "
                "that the original code did not have.",
            )
        )

    outcome.also_resolved = sum(
        count - after_counts[key]
        for key, count in before_counts.items()
        if key != target_key and after_counts[key] < count
    )

    # 3. The change replaces code with code. Recounted from the diff itself
    #    rather than read from the row: the row was written by the phase whose
    #    work is being checked.
    outcome.checks.append(_deletion_check(parsed, file_path))

    # 4. The patched file still parses, where that can be known.
    outcome.checks.append(_syntax_check(file_path, after_lines))
    return outcome


def _deletion_check(parsed: patch_apply.ParsedDiff, file_path: str) -> Check:
    net_removed = len(parsed.removed) - len(parsed.added)
    if net_removed > diffing.MAX_NET_REMOVED_LINES:
        return Check(
            "not_a_deletion",
            FAILED,
            f"The change removes {len(parsed.removed)} lines and adds {len(parsed.added)}. "
            "Deleting vulnerable code makes a finding disappear without fixing it.",
        )
    if all(diffing.is_inert(line, file_path) for line in parsed.added):
        return Check(
            "not_a_deletion",
            FAILED,
            "The change replaces the code with nothing that runs — only blank lines, "
            "comments or a no-op.",
        )
    return Check("not_a_deletion", PASSED, "The change replaces code with code.")


def _syntax_check(file_path: str, after_lines: list[str]) -> Check:
    if PurePosixPath(file_path).suffix.lower() not in {".py", ".pyi"}:
        return Check(
            "still_parses",
            SKIPPED,
            "Only Python is parsed here. For this language the re-scan is the only check.",
        )
    try:
        ast.parse("".join(after_lines))
    except (SyntaxError, ValueError, RecursionError) as exc:
        line = getattr(exc, "lineno", None)
        where = f" (line {line})" if line else ""
        # Not a formality: an unparsable Python file produces no AST findings,
        # so a syntax error makes every one of them "disappear".
        return Check("still_parses", FAILED, f"The patched file does not parse as Python{where}.")
    return Check("still_parses", PASSED, "The patched file still parses as Python.")


__all__ = [
    "FAILED",
    "PASSED",
    "SKIPPED",
    "CannotValidate",
    "Check",
    "Outcome",
    "identity",
    "validate",
]
