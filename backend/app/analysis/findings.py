"""What an analyser produces, before anything is stored.

A finding is a claim about code. Three things keep that claim honest:

* **Severity is about the bug, confidence is about us.** A hardcoded AWS key is
  CRITICAL, and we are HIGH confidence it really is one. A string concatenated
  into something that *looks* like SQL is also serious, but we are only MEDIUM
  confident it is a query. Collapsing the two into one number is how security
  tools end up crying wolf.
* **The snippet is untrusted text.** It comes from someone else's repository,
  it is stored as data and never interpreted, control characters are stripped,
  and it is bounded — in Phase 8 it will be handed to an LLM, and by then
  "this is data, not instructions" has to already be true.
* **A finding has a fingerprint**, so the same issue found twice is one
  finding, and re-analysing a repository that has not changed produces exactly
  the same set.
"""

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum

SNIPPET_MAX_CHARS = 240
CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class Severity(StrEnum):
    """How bad it is if the finding is real."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(StrEnum):
    """How sure the analyser is that it found what it thinks it found."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def clean_snippet(text: str) -> str:
    """Make a line of someone else's code safe to store and show."""
    collapsed = CONTROL_CHARACTERS.sub("", text).strip()
    if len(collapsed) > SNIPPET_MAX_CHARS:
        return collapsed[:SNIPPET_MAX_CHARS] + "…"
    return collapsed


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    message: str
    severity: Severity
    confidence: Confidence
    cwe_id: str | None
    owasp_category: str | None
    file_path: str  # relative to the repository root, always
    line_start: int
    line_end: int
    snippet: str
    analyzer: str
    # Which repeat of an identical line this is, within the same file. Set by
    # the engine. Without it, `os.system(cmd)` on lines 10 and 200 would share
    # a fingerprint and the second one would silently vanish.
    occurrence: int = 0

    @property
    def fingerprint(self) -> str:
        """Stable identity for this finding.

        Built from the rule, the file, the *code* and which repeat it is —
        deliberately not the line number, so adding an import at the top of a
        file does not turn every finding below it into a new one.
        """
        material = f"{self.rule_id}|{self.file_path}|{_normalise(self.snippet)}|{self.occurrence}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def sort_key(self) -> tuple[int, str, int, str]:
        return (SEVERITY_ORDER[self.severity], self.file_path, self.line_start, self.rule_id)


def _normalise(snippet: str) -> str:
    """Whitespace-insensitive form, so reindenting code is not a new finding."""
    return " ".join(snippet.split())
