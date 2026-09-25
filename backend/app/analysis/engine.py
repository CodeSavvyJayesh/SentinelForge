"""The engine: walk an ingested workspace and produce findings.

The contract, in four points:

1. **Nothing is executed.** Files are opened and read. Python is parsed with
   ``ast.parse``, which builds a tree and imports nothing. No build, no install,
   no test run, no plugin loaded from the repository.
2. **It is bounded.** A file bigger than the limit is skipped, binary files are
   skipped, and the whole run stops adding findings at ``ANALYSIS_MAX_FINDINGS``
   and says so. An analysis that never finishes is an outage.
3. **It is deterministic.** Same workspace, same findings, in the same order,
   with the same fingerprints — so "what changed since last time" is a real
   question with a real answer.
4. **Broken code is reported, not guessed at.** A Python file that does not
   parse is counted as unparsable; the pattern and secret analysers still see
   it, because a hardcoded key is a hardcoded key whether or not the file
   compiles.
"""

import time
from dataclasses import dataclass, field, replace
from pathlib import Path

from app.analysis.findings import SEVERITY_ORDER, Finding
from app.analysis.patterns import analyze_with_patterns
from app.analysis.python_ast import analyze_python_source
from app.analysis.secrets import analyze_secrets
from app.core.config import Settings
from app.core.logging import get_logger
from app.ingestion.archive import IGNORED_DIRECTORIES

logger = get_logger("sentinelforge.analysis")

PYTHON_SUFFIXES = frozenset({".py", ".pyi"})

# Files that are data, not code. Scanning a 3 MB lockfile finds nothing and
# costs a second; scanning a PNG finds nothing and costs the whole budget.
SKIPPED_SUFFIXES = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".ico",
        ".svg",
        ".webp",
        ".bmp",
        ".pdf",
        ".zip",
        ".gz",
        ".tar",
        ".bz2",
        ".xz",
        ".7z",
        ".rar",
        ".jar",
        ".war",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".otf",
        ".mp3",
        ".mp4",
        ".mov",
        ".avi",
        ".pyc",
        ".pyo",
        ".so",
        ".dll",
        ".dylib",
        ".exe",
        ".bin",
        ".class",
        ".lock",
        ".map",
        ".min.js",
        ".sqlite",
        ".db",
    }
)
SKIPPED_FILENAMES = frozenset(
    {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Cargo.lock"}
)

BINARY_SNIFF_BYTES = 4096


@dataclass
class AnalysisResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    unparsable_files: int = 0
    truncated: bool = False
    duration_ms: int = 0

    @property
    def counts_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[str(finding.severity)] = counts.get(str(finding.severity), 0) + 1
        return counts


def analyze_workspace(root: Path, settings: Settings) -> AnalysisResult:
    """Analyse every source file under ``root``."""
    started = time.monotonic()
    result = AnalysisResult()
    seen: set[str] = set()

    for path in _source_files(root):
        if result.truncated:
            break
        relative = path.relative_to(root).as_posix()
        text = _read_text(path, settings)
        if text is None:
            result.files_skipped += 1
            continue

        result.files_scanned += 1
        file_findings = _number_repeats(
            _collapse_overlapping(_analyze_file(text, relative, path.suffix.lower(), result))
        )
        for finding in file_findings:
            if finding.fingerprint in seen:
                continue  # the same issue found by two analysers is one issue
            seen.add(finding.fingerprint)
            result.findings.append(finding)
            if len(result.findings) >= settings.ANALYSIS_MAX_FINDINGS:
                result.truncated = True
                break

    result.findings.sort(key=lambda finding: finding.sort_key())
    result.duration_ms = int((time.monotonic() - started) * 1000)
    logger.info(
        "analysis_completed",
        extra={
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "unparsable_files": result.unparsable_files,
            "findings": len(result.findings),
            "truncated": result.truncated,
            "duration_ms": result.duration_ms,
        },
    )
    return result


def _collapse_overlapping(findings: list[Finding]) -> list[Finding]:
    """One issue per place, even when two analysers noticed it.

    A hardcoded credential is found by the Python AST rule *and* by the generic
    secret rule: same file, same line, same CWE, one problem. The stronger
    claim wins — higher severity, then higher confidence — so the report says
    "credential in source (HIGH)" once instead of twice with different ids.

    Findings with different CWEs on the same line are left alone: a line can be
    both an injection and a weak hash, and merging those would hide one.
    """
    best: dict[tuple[str, int, str], Finding] = {}
    unkeyed: list[Finding] = []
    for finding in findings:
        if not finding.cwe_id:
            unkeyed.append(finding)
            continue
        key = (finding.file_path, finding.line_start, finding.cwe_id)
        current = best.get(key)
        if current is None or _strength(finding) < _strength(current):
            best[key] = finding
    return [*best.values(), *unkeyed]


def _strength(finding: Finding) -> tuple[int, int]:
    """Lower is stronger: severity first, then confidence."""
    confidence_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    return (
        SEVERITY_ORDER[finding.severity],
        confidence_rank.get(str(finding.confidence), 3),
    )


def _number_repeats(findings: list[Finding]) -> list[Finding]:
    """Give each repeat of an identical line its own occurrence number."""
    seen: dict[tuple[str, str], int] = {}
    numbered: list[Finding] = []
    for finding in sorted(findings, key=lambda item: (item.line_start, item.rule_id)):
        key = (finding.rule_id, " ".join(finding.snippet.split()))
        index = seen.get(key, 0)
        seen[key] = index + 1
        numbered.append(replace(finding, occurrence=index))
    return numbered


def _analyze_file(text: str, relative: str, suffix: str, result: AnalysisResult) -> list[Finding]:
    findings: list[Finding] = []

    if suffix in PYTHON_SUFFIXES:
        try:
            findings.extend(analyze_python_source(text, relative))
        except (SyntaxError, ValueError, RecursionError):
            # Unparsable: counted, never guessed at. Deeply nested literals can
            # also exhaust the recursion limit, which is not a finding either.
            result.unparsable_files += 1
    else:
        findings.extend(analyze_with_patterns(text, relative, suffix))

    # Secrets are looked for everywhere, including files that do not parse and
    # files in languages we have no rules for: .env, .yml, .tf, .properties.
    findings.extend(analyze_secrets(text, relative))
    return findings


def _source_files(root: Path) -> list[Path]:
    """Every candidate file, in a stable order."""
    import os

    collected: list[Path] = []
    for directory, subdirectories, filenames in os.walk(root, followlinks=False):
        subdirectories[:] = sorted(
            name for name in subdirectories if name not in IGNORED_DIRECTORIES
        )
        for filename in sorted(filenames):
            path = Path(directory) / filename
            if path.is_symlink() or not path.is_file():
                continue
            if filename in SKIPPED_FILENAMES or path.suffix.lower() in SKIPPED_SUFFIXES:
                continue
            collected.append(path)
    return collected


def _read_text(path: Path, settings: Settings) -> str | None:
    """Read a source file, or ``None`` if it should not be analysed."""
    try:
        if path.stat().st_size > settings.ANALYSIS_MAX_FILE_BYTES:
            return None
        with open(path, "rb") as handle:
            head = handle.read(BINARY_SNIFF_BYTES)
            if b"\x00" in head:  # a null byte means binary, whatever the name
                return None
            rest = handle.read()
    except OSError:
        return None

    try:
        return (head + rest).decode("utf-8")
    except UnicodeDecodeError:
        try:
            return (head + rest).decode("latin-1")
        except UnicodeDecodeError:  # pragma: no cover - latin-1 decodes anything
            return None
