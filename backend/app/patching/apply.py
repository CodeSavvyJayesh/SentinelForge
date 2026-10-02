"""Applying a stored unified diff, strictly.

Phase 10 generates diffs with ``difflib`` and never applies one. Phase 11 has to
apply one — to a throwaway copy — and this module is how.

It is written here rather than delegated to ``git apply`` for two reasons. The
first is practical: validation should not depend on a git binary being on the
PATH of whichever machine runs the worker. The second is the point: ``git
apply`` and ``patch`` are *helpful*. They will slide a hunk a few lines to find
somewhere it fits, and a hunk that has been slid is a patch applied to code
nobody reviewed. This applier has **no fuzz and no offset**. Every context line
and every removed line must be exactly where the hunk header says it is, or the
whole patch is refused.

A diff is also only accepted if it touches **one file, the one the patch row
names**. The text came out of our own database, but so did the file path in
Phase 10, and that one gets a containment check too.

Hunks are read by *count*, not by sniffing prefixes. A removed SQL comment
``-- drop it`` appears in a diff as ``--- drop it``, which looks exactly like a
file header to anything that pattern-matches line starts. The hunk header says
how many lines belong to it, so that is what is believed.
"""

import re
from dataclasses import dataclass, field

HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class PatchDoesNotApply(ValueError):
    """The diff could not be applied exactly. The message is safe to show."""


@dataclass(frozen=True)
class Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    # (kind, text) pairs in order; kind is " ", "-" or "+". Text has no line
    # ending: endings come from the file being patched, never from the diff.
    lines: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class ParsedDiff:
    old_path: str
    new_path: str
    hunks: tuple[Hunk, ...]
    added: tuple[str, ...] = field(default=())
    removed: tuple[str, ...] = field(default=())


def _strip_ending(line: str) -> str:
    return line.rstrip("\r\n")


def _header_path(line: str, marker: str, prefix: str) -> str:
    if not line.startswith(marker):
        raise PatchDoesNotApply("The stored change is not a unified diff.")
    path = line[len(marker) :].split("\t")[0].strip()
    if not path.startswith(prefix):
        raise PatchDoesNotApply("The stored change has an unexpected file header.")
    return path[len(prefix) :]


def parse(diff_text: str) -> ParsedDiff:
    """Read a single-file unified diff into hunks."""
    lines = [_strip_ending(line) for line in diff_text.split("\n")]
    while lines and lines[-1] == "":
        lines.pop()
    if len(lines) < 3:
        raise PatchDoesNotApply("The stored change is empty.")

    old_path = _header_path(lines[0], "--- ", "a/")
    new_path = _header_path(lines[1], "+++ ", "b/")

    hunks: list[Hunk] = []
    added: list[str] = []
    removed: list[str] = []
    index = 2
    while index < len(lines):
        match = HUNK_HEADER.match(lines[index])
        if match is None:
            # Anything that is not a hunk header here is a second file, or
            # noise. Either way it is not the one-file diff this project makes.
            raise PatchDoesNotApply("The stored change touches more than one place it should.")
        old_start = int(match.group(1))
        old_count = int(match.group(2) or 1)
        new_start = int(match.group(3))
        new_count = int(match.group(4) or 1)
        index += 1

        body: list[tuple[str, str]] = []
        old_seen = new_seen = 0
        while old_seen < old_count or new_seen < new_count:
            if index >= len(lines):
                raise PatchDoesNotApply("The stored change is cut short.")
            line = lines[index]
            index += 1
            if line.startswith("\\"):
                continue  # "\ No newline at end of file": about endings, not content
            kind, text = (line[0], line[1:]) if line else (" ", "")
            if kind == " ":
                old_seen += 1
                new_seen += 1
            elif kind == "-":
                old_seen += 1
                removed.append(text)
            elif kind == "+":
                new_seen += 1
                added.append(text)
            else:
                raise PatchDoesNotApply("The stored change has a line that is not part of a diff.")
            body.append((kind, text))
        if old_seen != old_count or new_seen != new_count:
            raise PatchDoesNotApply("The stored change does not match its own line counts.")
        # A trailing "\ No newline" marker belongs to the hunk just read.
        while index < len(lines) and lines[index].startswith("\\"):
            index += 1
        hunks.append(Hunk(old_start, old_count, new_start, new_count, tuple(body)))

    if not hunks:
        raise PatchDoesNotApply("The stored change contains no changes.")
    return ParsedDiff(old_path, new_path, tuple(hunks), tuple(added), tuple(removed))


def apply(original: list[str], diff: ParsedDiff) -> list[str]:
    """Return the patched file's lines, or refuse.

    ``original`` is the file split with its line endings kept. Context and
    removed lines are compared without their endings, so a diff stored with
    ``\\n`` still applies to a CRLF checkout — and the endings written back are
    the file's own, for the same reason ``region.splice`` does it: a patch must
    not convert a file it was asked to fix one line of.
    """
    ending = _dominant_ending(original)
    result: list[str] = []
    cursor = 0  # index into `original` of the next line not yet copied

    for hunk in diff.hunks:
        # A hunk with no old lines ("-12,0") names the line *after* which to add.
        start = hunk.old_start if hunk.old_count == 0 else hunk.old_start - 1
        if start < cursor or start > len(original):
            raise PatchDoesNotApply(
                "The code has changed since this change was proposed, so it no longer fits."
            )
        result.extend(original[cursor:start])
        cursor = start

        for kind, text in hunk.lines:
            if kind == "+":
                result.append(text + ending)
                continue
            if cursor >= len(original) or _strip_ending(original[cursor]) != text:
                raise PatchDoesNotApply(
                    "The code has changed since this change was proposed, so it no longer fits."
                )
            if kind == " ":
                result.append(original[cursor])
            cursor += 1

    result.extend(original[cursor:])

    # Keep the file's final-newline convention, whichever it was.
    if result:
        had_final_newline = bool(original) and original[-1].endswith(("\n", "\r"))
        if had_final_newline and not result[-1].endswith(("\n", "\r")):
            result[-1] += ending
        elif not had_final_newline and original:
            result[-1] = _strip_ending(result[-1])
    return result


def _dominant_ending(lines: list[str]) -> str:
    crlf = sum(1 for line in lines if line.endswith("\r\n"))
    return "\r\n" if lines and crlf > len(lines) / 2 else "\n"


__all__ = ["Hunk", "ParsedDiff", "PatchDoesNotApply", "apply", "parse"]
