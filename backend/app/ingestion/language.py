"""Language detection from an extracted file tree.

Detection is deliberately simple and honest: files are mapped to a language by
extension (with a few exact filename matches), and the breakdown is reported in
**bytes**, not file counts, because one 4 000-line Python file says more about a
project than forty tiny JSON fixtures.

Nothing is guessed. A file whose extension is unknown is counted as "other" and
never attributed to a language, and a project with no recognised source files
reports ``None`` rather than inventing a default.

Later phases pick analysers by this value, so a wrong answer here is worse than
no answer.
"""

import os
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from app.ingestion.archive import IGNORED_DIRECTORIES

EXTENSION_LANGUAGES: dict[str, str] = {
    ".py": "Python",
    ".pyi": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".java": "Java",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".go": "Go",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".hpp": "C++",
    ".rs": "Rust",
    ".swift": "Swift",
    ".scala": "Scala",
    ".sh": "Shell",
    ".bash": "Shell",
    ".zsh": "Shell",
    ".ps1": "PowerShell",
    ".sql": "SQL",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".scss": "CSS",
    ".sass": "CSS",
    ".less": "CSS",
    ".vue": "Vue",
    ".svelte": "Svelte",
    ".dart": "Dart",
    ".ex": "Elixir",
    ".exs": "Elixir",
    ".pl": "Perl",
    ".pm": "Perl",
    ".lua": "Lua",
    ".r": "R",
    ".m": "Objective-C",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".json": "JSON",
    ".tf": "Terraform",
    ".md": "Markdown",
}

FILENAME_LANGUAGES: dict[str, str] = {
    "dockerfile": "Dockerfile",
    "makefile": "Make",
    "jenkinsfile": "Groovy",
    "gemfile": "Ruby",
    "rakefile": "Ruby",
}

# Languages that describe configuration or prose rather than program logic.
# They are reported in the breakdown but never chosen as the primary language:
# a repository is not "a YAML project" because its CI config is verbose.
NON_PRIMARY_LANGUAGES: frozenset[str] = frozenset(
    {"YAML", "JSON", "Markdown", "HTML", "CSS", "Other"}
)

OTHER = "Other"


@dataclass
class TreeSummary:
    file_count: int = 0
    total_bytes: int = 0
    primary_language: str | None = None
    breakdown: dict[str, int] | None = None


def classify(path: Path) -> str:
    name = path.name.lower()
    if name in FILENAME_LANGUAGES:
        return FILENAME_LANGUAGES[name]
    if name.startswith("dockerfile"):  # Dockerfile.prod, Dockerfile.dev
        return "Dockerfile"
    return EXTENSION_LANGUAGES.get(path.suffix.lower(), OTHER)


def summarise_tree(root: Path) -> TreeSummary:
    """Walk ``root`` and summarise what is in it.

    Symlinks are never followed: a link left behind by a clone could point at
    ``/etc`` and inflate the totals (or worse, be read by a later phase).
    """
    summary = TreeSummary()
    byte_totals: dict[str, int] = defaultdict(int)

    for directory, subdirectories, filenames in os.walk(root, followlinks=False):
        # Pruning in place stops os.walk descending into them at all.
        subdirectories[:] = [name for name in subdirectories if name not in IGNORED_DIRECTORIES]
        for filename in filenames:
            path = Path(directory) / filename
            if path.is_symlink() or not path.is_file():
                continue
            try:
                size = path.stat().st_size
            except OSError:  # pragma: no cover - a file removed mid-walk
                continue
            summary.file_count += 1
            summary.total_bytes += size
            byte_totals[classify(path)] += size

    if not summary.file_count:
        return summary

    summary.breakdown = dict(sorted(byte_totals.items(), key=lambda item: -item[1]))
    summary.primary_language = _primary(byte_totals)
    return summary


def _primary(byte_totals: dict[str, int]) -> str | None:
    candidates = {
        language: total
        for language, total in byte_totals.items()
        if language not in NON_PRIMARY_LANGUAGES and total > 0
    }
    if not candidates:
        return None
    return max(candidates.items(), key=lambda item: (item[1], item[0]))[0]
