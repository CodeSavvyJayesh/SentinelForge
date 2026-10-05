"""Run the analyser over a benchmark and mark it against the answer key.

The analyser is called exactly as a scan calls it — same engine, same rules,
no evaluation-only switch — so the numbers describe the scanner people use and
not a variant of it tuned for the occasion. Nothing in the benchmark is built
or executed: the test cases are web applications, and they are read as text.

How one test case is marked, which is the benchmark's own convention:

* Its question is its category. It is **reported** when the analyser produced
  at least one finding, in that test case's own source file, from a rule
  assigned to that category (:mod:`app.evaluation.mapping`).
* Vulnerable and reported is a true positive; vulnerable and not reported is a
  miss; safe and reported is a false alarm; safe and not reported is correct.
* A finding of some *other* kind in the file is not an answer to the question
  and is not scored either way. Those findings are counted and published next
  to the results, because leaving them out would hide how much the analyser
  says that the benchmark has no opinion about.

Four things make the run refuse rather than produce a number:

* a test case whose file was not read — marking it "not reported" would record
  a miss, or a correct silence, for code nobody looked at;
* a test case whose file could not be parsed. Python source is parsed by the
  interpreter running the analyser, so a benchmark written for a newer Python
  than that interpreter is, to it, a folder of syntax errors. The first
  measurement in this project was taken that way — 470 of 1,230 files silently
  unread — and looked like a result;
* two source files claiming to be the same test case;
* the analyser stopping at its findings limit, which would make every test
  after that point look clean.
"""

import hashlib
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

import app.analysis as analysis_package
from app.analysis.engine import PYTHON_SUFFIXES, analysable_files, analyze_workspace
from app.analysis.patterns import SQL_HOST_SUFFIXES
from app.core.config import Settings
from app.evaluation.benchmark import ALL, Benchmark, BenchmarkError, TestCase
from app.evaluation.mapping import RULE_CATEGORY, rules_for
from app.evaluation.metrics import Confusion, mean

# Files that are a test case's code. A benchmark also ships an HTML page per
# test with the same name; that page is the form that calls the code, not the
# code being judged.
SOURCE_SUFFIXES: frozenset[str] = PYTHON_SUFFIXES | SQL_HOST_SUFFIXES

# High enough never to be reached by a benchmark; reaching it is an error.
EVALUATION_MAX_FINDINGS = 1_000_000

TRUE_POSITIVE = "TP"
FALSE_POSITIVE = "FP"
TRUE_NEGATIVE = "TN"
FALSE_NEGATIVE = "FN"


@dataclass(frozen=True)
class CaseOutcome:
    case: TestCase
    # Rules of the case's own category that fired in its file, sorted.
    rules: tuple[str, ...]

    @property
    def reported(self) -> bool:
        return bool(self.rules)

    @property
    def verdict(self) -> str:
        if self.case.vulnerable:
            return TRUE_POSITIVE if self.reported else FALSE_NEGATIVE
        return FALSE_POSITIVE if self.reported else TRUE_NEGATIVE

    @property
    def correct(self) -> bool:
        return self.reported == self.case.vulnerable


@dataclass(frozen=True)
class CategoryResult:
    category: str
    cwe: int
    confusion: Confusion
    # Rules that look for this weakness in the benchmark's language. Empty: the
    # analyser has no such rule and every vulnerable case is missed by design.
    rules: tuple[str, ...]

    @property
    def has_rule(self) -> bool:
        return bool(self.rules)


@dataclass(frozen=True)
class Evaluation:
    name: str
    version: str | None
    commit: str | None
    answer_key_sha256: str
    split: str
    tool_version: str
    analyser_sha256: str
    # The interpreter that parsed the Python test cases, as "3.13".
    python_version: str
    files_scanned: int
    duration_ms: int
    categories: tuple[CategoryResult, ...]
    outcomes: tuple[CaseOutcome, ...]
    # Findings the answer key has no opinion about, by rule.
    unscored_in_cases: dict[str, int] = field(default_factory=dict)
    findings_outside_cases: int = 0

    @property
    def pooled(self) -> Confusion:
        """Every test case counted once, whatever its category."""
        total = Confusion()
        for item in self.categories:
            total = total + item.confusion
        return total

    @property
    def with_rule(self) -> tuple[CategoryResult, ...]:
        return tuple(item for item in self.categories if item.has_rule)

    @property
    def pooled_with_rule(self) -> Confusion:
        total = Confusion()
        for item in self.with_rule:
            total = total + item.confusion
        return total

    def average(self, attribute: str, *, only_with_rule: bool = False) -> float | None:
        """A rate averaged over categories, each category counting once.

        This is how the benchmark states its headline: a category with thirty
        test cases weighs the same as one with five hundred, so a tool cannot
        look good by being good only at the commonest weakness.
        """
        chosen = self.with_rule if only_with_rule else self.categories
        return mean([getattr(item.confusion, attribute) for item in chosen])

    @property
    def outcomes_sha256(self) -> str:
        """One hash that changes if any single test case is judged differently."""
        lines = sorted(f"{item.case.name},{int(item.reported)}" for item in self.outcomes)
        return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def evaluate(root: Path, benchmark: Benchmark, *, name: str, split: str = ALL) -> Evaluation:
    chosen = benchmark.half(split)
    if not chosen.cases:
        raise BenchmarkError("No test cases fall in that half of the benchmark.")

    settings = Settings.model_construct(ANALYSIS_MAX_FINDINGS=EVALUATION_MAX_FINDINGS)
    # The whole benchmark is always analysed, whichever half is being marked:
    # the analyser's output for a file does not depend on which files are
    # asked about afterwards.
    files = _case_files(root, benchmark, settings)
    result = analyze_workspace(root, settings)
    if result.truncated:
        raise BenchmarkError(
            "The analyser stopped at its findings limit, so later test cases were not judged."
        )

    unparsable = sorted(path for path in result.unparsable_paths if path in files)
    if unparsable:
        raise BenchmarkError(
            f"{len(unparsable)} test case file(s) could not be parsed by Python "
            f"{python_version()} (the first is {unparsable[0]}). A benchmark written for a "
            "newer Python has to be marked with that Python. Nothing was marked."
        )

    cases = {case.name: case for case in chosen.cases}
    every_case = {case.name for case in benchmark.cases}
    answering: dict[str, set[str]] = {case_name: set() for case_name in cases}
    unscored: Counter[str] = Counter()
    outside = 0

    for finding in result.findings:
        case_name = files.get(finding.file_path)
        if case_name is None:
            outside += 1
            continue
        if case_name not in cases:
            continue  # a test case in the other half; not this run's business
        if RULE_CATEGORY.get(finding.rule_id) == cases[case_name].category:
            answering[case_name].add(finding.rule_id)
        else:
            unscored[finding.rule_id] += 1

    missing = sorted(set(cases) - set(files.values()))
    if missing:
        raise BenchmarkError(
            f"{len(missing)} test case(s) in the answer key have no source file that was read "
            f"(the first is {missing[0]}). Nothing was marked."
        )

    outcomes = tuple(
        CaseOutcome(case, tuple(sorted(answering[case.name]))) for case in chosen.cases
    )
    suffixes = frozenset(
        PurePosixPath(path).suffix.lower()
        for path, case_name in files.items()
        if case_name in every_case
    )
    return Evaluation(
        name=name,
        version=benchmark.version,
        commit=commit_of(root),
        answer_key_sha256=benchmark.answer_key_sha256,
        split=split,
        tool_version=Settings.model_fields["APP_VERSION"].default,
        analyser_sha256=analyser_sha256(),
        python_version=python_version(),
        files_scanned=result.files_scanned,
        duration_ms=result.duration_ms,
        categories=_by_category(outcomes, suffixes),
        outcomes=outcomes,
        unscored_in_cases=dict(sorted(unscored.items())),
        findings_outside_cases=outside,
    )


def _case_files(root: Path, benchmark: Benchmark, settings: Settings) -> dict[str, str]:
    """Repository-relative path of each test case's source file -> its name.

    Found by walking the folder with the analyser's own file list, so a file
    counts here exactly when the analyser would open it.
    """
    names = {case.name for case in benchmark.cases}
    found: dict[str, str] = {}
    owner: dict[str, str] = {}
    for path in analysable_files(root, settings):
        if path.suffix.lower() not in SOURCE_SUFFIXES or path.stem not in names:
            continue
        relative = path.relative_to(root).as_posix()
        if path.stem in owner:
            raise BenchmarkError(
                f"Two source files are named after the test case {path.stem}; "
                "it is not clear which one the answer key is about."
            )
        owner[path.stem] = relative
        found[relative] = path.stem
    return found


def _by_category(
    outcomes: tuple[CaseOutcome, ...], suffixes: frozenset[str]
) -> tuple[CategoryResult, ...]:
    counts: dict[str, Counter[str]] = {}
    cwes: dict[str, int] = {}
    for outcome in outcomes:
        counts.setdefault(outcome.case.category, Counter())[outcome.verdict] += 1
        cwes.setdefault(outcome.case.category, outcome.case.cwe)
    return tuple(
        CategoryResult(
            category=category,
            cwe=cwes[category],
            confusion=Confusion(
                tp=tally[TRUE_POSITIVE],
                fp=tally[FALSE_POSITIVE],
                tn=tally[TRUE_NEGATIVE],
                fn=tally[FALSE_NEGATIVE],
            ),
            rules=rules_for(category, suffixes),
        )
        for category, tally in sorted(counts.items())
    )


def python_version() -> str:
    return f"{sys.version_info.major}.{sys.version_info.minor}"


def analyser_sha256() -> str:
    """A hash of the analyser's own source: which scanner produced these numbers.

    A version number changes when somebody remembers to change it. This changes
    when a rule does. Line endings are normalised so a Windows checkout and a
    Linux one of the same commit agree.
    """
    digest = hashlib.sha256()
    folder = Path(analysis_package.__file__).resolve().parent
    for path in sorted(folder.glob("*.py")):
        digest.update(path.name.encode())
        digest.update(b"\0")
        digest.update(path.read_bytes().replace(b"\r\n", b"\n"))
        digest.update(b"\0")
    return digest.hexdigest()


def commit_of(root: Path) -> str | None:
    """The commit a benchmark folder is checked out at, read from its files.

    Git is not run: the folder is somebody else's repository, and its
    configuration can name programs for git to execute. Two small files say
    the same thing without that.
    """
    git = root / ".git"
    try:
        head = (git / "HEAD").read_text(encoding="utf-8", errors="replace").strip()
        if _is_commit(head):
            return head
        if not head.startswith("ref: "):
            return None
        reference = head[5:].strip()
        if ".." in reference or not reference.startswith("refs/"):
            return None
        loose = git / reference
        if loose.is_file() and not loose.is_symlink():
            value = loose.read_text(encoding="utf-8", errors="replace").strip()
            return value if _is_commit(value) else None
        packed = git / "packed-refs"
        if packed.is_file() and not packed.is_symlink():
            for line in packed.read_text(encoding="utf-8", errors="replace").splitlines():
                value, _, name = line.partition(" ")
                if name.strip() == reference and _is_commit(value):
                    return value
    except OSError:
        return None
    return None


def _is_commit(value: str) -> bool:
    return len(value) == 40 and all(character in "0123456789abcdef" for character in value)


__all__ = [
    "CaseOutcome",
    "CategoryResult",
    "Evaluation",
    "SOURCE_SUFFIXES",
    "analyser_sha256",
    "commit_of",
    "evaluate",
    "python_version",
]
