"""Reading a benchmark's answer key.

A benchmark is a folder of small programs, each written to contain exactly one
weakness — or to look as though it does — and a file saying which is which.
The answer key format read here is the OWASP Benchmark's: one line per test
case, ``name,category,real vulnerability,cwe``.

The file comes from somebody else's repository, so it is read as untrusted
input like everything else that does: bounded, validated line by line, and
refused with the line number when it is not what it claims to be. A name is
never used to build a path, only to be compared with the names of files that
were found by walking the folder.
"""

import csv
import hashlib
import io
import re
from dataclasses import dataclass
from pathlib import Path

MAX_ANSWER_KEY_BYTES = 5 * 1024 * 1024
MAX_TEST_CASES = 100_000

NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,99}")
CATEGORY = re.compile(r"[a-z][a-z0-9_-]{0,39}")
VERSION = re.compile(r"Benchmark version:\s*([0-9][0-9A-Za-z.]{0,19})")
TRUTH = {"true": True, "false": False}

# The two halves of a benchmark. Rules may be changed while looking at the
# development half; the held-out half exists to be measured and not looked at.
DEVELOPMENT = "development"
HELD_OUT = "held-out"
ALL = "all"
SPLITS = (ALL, DEVELOPMENT, HELD_OUT)
# Changing this string changes which half every test case is in, which would
# quietly turn cases a rule was tuned on into "unseen" ones. It is never changed.
SPLIT_SALT = "sentinelforge-evaluation-split-v1"


class BenchmarkError(Exception):
    """The answer key could not be used. The message is safe to show."""


@dataclass(frozen=True)
class TestCase:
    name: str
    category: str
    vulnerable: bool
    cwe: int

    # pytest collects classes named Test*; this is data, not a test.
    __test__ = False


@dataclass(frozen=True)
class Benchmark:
    cases: tuple[TestCase, ...]
    version: str | None
    # Of the answer key exactly as it was read: two runs that disagree can
    # first be asked whether they were marked against the same answers.
    answer_key_sha256: str

    @property
    def categories(self) -> tuple[str, ...]:
        return tuple(sorted({case.category for case in self.cases}))

    def half(self, split: str) -> "Benchmark":
        """The same benchmark restricted to one half (or all of it)."""
        if split not in SPLITS:
            raise BenchmarkError(f"Unknown split: choose one of {', '.join(SPLITS)}.")
        if split == ALL:
            return self
        kept = tuple(case for case in self.cases if split_of(case.name) == split)
        return Benchmark(kept, self.version, self.answer_key_sha256)


def split_of(name: str) -> str:
    """Which half a test case belongs to. Depends on its name and nothing else.

    Not on its position in the file, its category or its answer — so the split
    is the same on every machine, survives the answer key being reordered, and
    cannot have been chosen by looking at what the analyser got right.
    """
    digest = hashlib.sha256(f"{SPLIT_SALT}:{name}".encode()).digest()
    return DEVELOPMENT if digest[0] % 2 == 0 else HELD_OUT


def find_answer_key(root: Path) -> Path:
    """The one ``expectedresults-*.csv`` at the top of a benchmark folder."""
    try:
        candidates = sorted(
            path
            for path in root.iterdir()
            if path.is_file()
            and not path.is_symlink()
            and path.name.startswith("expectedresults-")
            and path.suffix.lower() == ".csv"
        )
    except OSError as error:
        raise BenchmarkError("The benchmark folder could not be read.") from error
    if len(candidates) != 1:
        found = "none" if not candidates else f"{len(candidates)} of them"
        raise BenchmarkError(
            "Expected exactly one expectedresults-*.csv in the benchmark folder "
            f"and found {found}. Name the file with --expected."
        )
    return candidates[0]


def load(path: Path) -> Benchmark:
    try:
        if path.is_symlink() or not path.is_file():
            raise BenchmarkError("The answer key is not a regular file.")
        if path.stat().st_size > MAX_ANSWER_KEY_BYTES:
            raise BenchmarkError("The answer key is larger than an answer key should be.")
        raw = path.read_bytes()
    except OSError as error:
        raise BenchmarkError("The answer key could not be read.") from error
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise BenchmarkError("The answer key is not UTF-8 text.") from error
    return parse(text, hashlib.sha256(raw).hexdigest())


def parse(text: str, answer_key_sha256: str = "") -> Benchmark:
    cases: list[TestCase] = []
    seen: set[str] = set()
    version: str | None = None

    for number, row in enumerate(csv.reader(io.StringIO(text, newline="")), start=1):
        fields = [field.strip() for field in row]
        if not any(fields):
            continue
        if fields[0].startswith("#"):
            # The header is a comment; the benchmark's version is written in it.
            match = VERSION.search(",".join(fields))
            if match and version is None:
                version = match.group(1)
            continue
        if len(fields) < 4:
            raise BenchmarkError(f"Line {number} of the answer key has fewer than four fields.")
        name, category, truth, cwe = fields[:4]
        if not NAME.fullmatch(name):
            raise BenchmarkError(f"Line {number} of the answer key has an unusable test name.")
        if not CATEGORY.fullmatch(category):
            raise BenchmarkError(f"Line {number} of the answer key has an unusable category.")
        if truth.lower() not in TRUTH:
            raise BenchmarkError(
                f"Line {number} of the answer key does not say true or false for the answer."
            )
        if not cwe.isascii() or not cwe.isdigit() or len(cwe) > 6:
            raise BenchmarkError(f"Line {number} of the answer key has an unusable CWE number.")
        if name in seen:
            # Two answers for one test would let the second silently replace
            # the first; neither can be trusted, so neither is used.
            raise BenchmarkError(f"Line {number} of the answer key repeats an earlier test name.")
        seen.add(name)
        cases.append(TestCase(name, category, TRUTH[truth.lower()], int(cwe)))
        if len(cases) > MAX_TEST_CASES:
            raise BenchmarkError("The answer key has more test cases than can be evaluated.")

    if not cases:
        raise BenchmarkError("The answer key contains no test cases.")
    return Benchmark(tuple(cases), version, answer_key_sha256)


__all__ = [
    "ALL",
    "DEVELOPMENT",
    "HELD_OUT",
    "SPLITS",
    "Benchmark",
    "BenchmarkError",
    "TestCase",
    "find_answer_key",
    "load",
    "parse",
    "split_of",
]
