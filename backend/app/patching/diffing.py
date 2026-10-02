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
    # The added lines themselves, without their "+" or their line ending. Kept
    # so the substance check below reads what was added rather than re-parsing
    # the text and guessing which "+" lines are code.
    added_lines: tuple[str, ...] = ()


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
    # The first two lines are the file headers and are skipped by position, not
    # by prefix: an added `++i;` is the line `+++i;`, and a removed SQL comment
    # `-- x` is `--- x`. Telling those from headers by how they start miscounts.
    body = lines[2:]
    added_lines = tuple(line[1:].rstrip("\r\n") for line in body if line.startswith("+"))
    removed = sum(1 for line in body if line.startswith("-"))
    return Diff(text=text, added=len(added_lines), removed=removed, added_lines=added_lines)


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


# Comment openers by language family. Deliberately per-suffix: `#` starts a
# comment in Python and a preprocessor directive in C, and `*p = 0;` is code.
HASH_COMMENT_SUFFIXES = frozenset(
    {".py", ".pyi", ".rb", ".sh", ".bash", ".yml", ".yaml", ".toml", ".tf", ".pl", ".r", ".ps1",
     ".properties", ".env", ".cfg", ".ini", ".conf", ".php"}
)  # fmt: skip
SLASH_COMMENT_SUFFIXES = frozenset(
    {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java", ".c", ".h", ".cpp", ".cc", ".hpp",
     ".cs", ".go", ".php", ".kt", ".swift", ".rs", ".scala"}
)  # fmt: skip
DASH_COMMENT_SUFFIXES = frozenset({".sql", ".lua", ".hs"})
NO_OP_STATEMENTS = frozenset({"pass", "...", ";", "{}", "{", "}", "pass;"})


def is_inert(line: str, file_path: str) -> bool:
    """Whether a line does nothing: blank, a comment, or a bare no-op."""
    stripped = line.strip()
    if not stripped or stripped in NO_OP_STATEMENTS:
        return True
    suffix = PurePosixPath(file_path).suffix.lower()
    if suffix in HASH_COMMENT_SUFFIXES and stripped.startswith("#"):
        return True
    if suffix in SLASH_COMMENT_SUFFIXES and (
        stripped.startswith(("//", "/*", "*/")) or stripped == "*" or stripped.startswith("* ")
    ):
        return True
    return suffix in DASH_COMMENT_SUFFIXES and stripped.startswith("--")


def check_substance(file_path: str, added_lines: tuple[str, ...] | list[str]) -> None:
    """Refuse a change that replaces code with nothing that runs.

    The size check above catches a model deleting twelve lines. It does not
    catch the tidier version of the same move: swapping the one vulnerable line
    for ``pass`` or for ``# removed for security``. One line out, one line in,
    net zero — and the finding is gone, so a re-scan would call it fixed.

    This is a heuristic and is stated as one. It recognises blank lines,
    comments and bare no-ops; it does not recognise ``return None`` in place of
    a function body. What it buys is that the cheapest way to make a finding
    disappear is no longer available.
    """
    if all(is_inert(line, file_path) for line in added_lines):
        raise PatchRejected(
            "The proposed change replaces the vulnerable code with nothing that runs "
            "(only blank lines, comments or a no-op). That hides the finding instead of "
            "fixing it, so it is not being shown."
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
    "check_substance",
    "check_syntax",
    "is_inert",
]
