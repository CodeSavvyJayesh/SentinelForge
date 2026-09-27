"""Building the diff, and refusing the ones that should not be shown.

The diff itself is `difflib.unified_diff` over the file before and after, so it
is correct by construction — there is no way for a hunk header to be wrong,
because nothing wrote one by hand.

What needs judgement is which proposals are worth showing a person at all. A
model asked to fix SQL injection will sometimes delete the function, sometimes
rewrite the file's indentation, and sometimes return the code unchanged with a
comment saying it fixed it. None of those are patches, and all three look
plausible in a JSON field. The checks below are the ones that can be made
before Phase 11 has re-scanned anything:

* it has to **change something** — an empty diff is a model saying "done";
* it has to stay within a **size budget** relative to what it replaced, because
  a fix for one line that rewrites forty is not a fix anyone will review;
* it must not be a **deletion in disguise** — removing the vulnerable code and
  nothing else makes the finding disappear without solving the problem, which
  is precisely the outcome Phase 11 would otherwise certify as a success;
* for languages where it is possible, the patched file has to **still parse**.

None of this establishes that the patch is *correct*. That is Phase 11's job,
and until it runs the status stays `PROPOSED`.
"""

import ast
import difflib
from dataclasses import dataclass
from pathlib import PurePosixPath

# A one-line fix may legitimately become several — a parameterised query is
# often two statements. Forty is not a fix, it is a rewrite.
MAX_ADDED_LINES = 25
# A patch that removes far more than it adds is usually the model deleting the
# problem. Allowed when the removal is small (a `shell=True` argument, a debug
# flag); refused when it is wholesale.
MAX_NET_REMOVED_LINES = 6


class PatchRejected(ValueError):
    """The proposal was not fit to show. The message is written for a person."""


@dataclass(frozen=True)
class Diff:
    text: str
    added: int
    removed: int


def build(file_path: str, before: list[str], after: list[str], *, context: int = 3) -> Diff:
    """Unified diff of one file, in the conventional a/ b/ form."""
    lines = list(
        difflib.unified_diff(
            before,
            after,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            n=context,
        )
    )
    text = "".join(line if line.endswith("\n") else line + "\n" for line in lines)
    added = sum(1 for line in lines if line.startswith("+") and not line.startswith("+++"))
    removed = sum(1 for line in lines if line.startswith("-") and not line.startswith("---"))
    return Diff(text=text, added=added, removed=removed)


def check(diff: Diff, *, replaced_lines: int) -> None:
    """Refuse proposals that are not worth a reviewer's time."""
    if not diff.text.strip():
        # The model returned the code it was given. Storing this would mean
        # showing somebody a "fix" that fixes nothing.
        raise PatchRejected("The model returned the same code, so there is nothing to apply.")

    if diff.added > replaced_lines + MAX_ADDED_LINES:
        raise PatchRejected(
            f"The proposed change adds {diff.added} lines where it replaced {replaced_lines}. "
            "That is a rewrite rather than a fix, so it is not being shown."
        )

    if diff.removed - diff.added > MAX_NET_REMOVED_LINES:
        raise PatchRejected(
            "The proposed change mostly deletes code. Removing the vulnerable lines makes the "
            "finding disappear without fixing anything, so it is not being shown."
        )


def check_syntax(file_path: str, after: list[str]) -> None:
    """Parse the patched file, where the language allows it cheaply.

    Only Python, and that is stated rather than hidden: this project has a
    parser for Python because Phase 5 needed one, and pulling in a parser for
    every other language to check a patch would be a larger undertaking than the
    patching itself. For everything else this check simply does not run, and
    Phase 11's re-scan is what catches a broken file.

    ``ast.parse`` builds a tree and evaluates nothing, so parsing code from an
    uploaded repository is safe — the same property Phase 5 relies on.
    """
    if PurePosixPath(file_path).suffix.lower() != ".py":
        return
    try:
        ast.parse("".join(after))
    except SyntaxError as exc:
        raise PatchRejected(
            f"The proposed change does not parse as Python (line {exc.lineno}: {exc.msg})."
        ) from exc
    except ValueError as exc:  # pragma: no cover - null bytes and similar
        raise PatchRejected("The proposed change could not be parsed.") from exc


__all__ = [
    "MAX_ADDED_LINES",
    "MAX_NET_REMOVED_LINES",
    "Diff",
    "PatchRejected",
    "build",
    "check",
    "check_syntax",
]
