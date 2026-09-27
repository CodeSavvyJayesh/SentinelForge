"""What a proposed fix is allowed to come back as.

Narrower than the explanation contract, because there is less to say: the
replacement text and one sentence about it. The interesting work is cleaning up
what models reliably get wrong about returning code.

Three habits show up in every small model and all three produce text that looks
like code and is not:

* **Markdown fences.** `````python`` … ``` `` wrapped round the answer, despite
  the request for JSON. Left in, they become part of the file and it stops
  compiling.
* **Line numbers echoed back.** The prompt shows ``   24 | cursor.execute(...)``
  and the model helpfully returns the same format. Left in, every line gains a
  gutter.
* **Prose before the code.** "Here is the fixed version:" on line one.

Stripping these is not papering over a bad model — it is the boundary between
"what a model emits" and "what a file may contain", and it belongs here rather
than scattered through the service.
"""

import json
import re
import unicodedata
from dataclasses import dataclass

from pydantic import BaseModel, Field, ValidationError, field_validator

from app.llm.contract import LlmContractError

PATCH_PROMPT_VERSION = 1

MAX_REPLACEMENT_CHARS = 8_000
MAX_RATIONALE_CHARS = 600

# ```python … ``` or ``` … ```, possibly with whitespace around it.
FENCE = re.compile(r"^\s*```[a-zA-Z0-9_+-]*\s*\n(?P<body>.*?)\n?\s*```\s*$", re.DOTALL)
# "   24 | code" — the gutter this project's own prompt puts in front of the
# region it shows.
GUTTER = re.compile(r"^\s*\d+\s*\|\s?")
# The fences the prompt puts around the replaceable lines. A model that echoes
# the whole code block back hands these over as if they were source. They are
# stripped rather than refused, because everything between them is still the
# answer.
MARKER = re.compile(r"^\s*(>{6}\s*REPLACE THESE LINES|<{6}\s*END OF LINES TO REPLACE).*$")
# "Here is the corrected code:" and friends, on their own line before the code.
PREAMBLE = re.compile(
    r"^\s*(here(?:'s| is)[^\n]*|the (?:fixed|corrected|updated)[^\n]*|sure[^\n]*)[:.]\s*\n",
    re.IGNORECASE,
)


class PatchDraft(BaseModel):
    replacement: str = Field(min_length=1, max_length=MAX_REPLACEMENT_CHARS)
    rationale: str = Field(min_length=1, max_length=MAX_RATIONALE_CHARS)

    @field_validator("replacement", "rationale", mode="before")
    @classmethod
    def _coerce(cls, value: object) -> object:
        # Models sometimes answer with a list of lines rather than one string.
        if isinstance(value, list):
            return "\n".join(str(item) for item in value)
        return value


@dataclass(frozen=True)
class ParsedPatch:
    replacement: str
    rationale: str
    # Recorded rather than silently applied: how much tidying the output needed
    # is a measurement of the model, and it goes in the phase report.
    fences_stripped: bool
    gutters_stripped: int


def strip_fences(text: str) -> tuple[str, bool]:
    match = FENCE.match(text)
    if match:
        return match.group("body"), True
    return text, False


def strip_gutters(text: str) -> tuple[str, int]:
    """Remove echoed line numbers — but only if the model used them throughout.

    A single line that happens to start with ``3 |`` is a table or a pipeline,
    not a gutter, and eating it would corrupt working code. The rule is that the
    gutter has to be on every non-blank line before any of them are removed.
    """
    lines = text.split("\n")
    candidates = [line for line in lines if line.strip()]
    if not candidates or not all(GUTTER.match(line) for line in candidates):
        return text, 0
    return "\n".join(GUTTER.sub("", line) if line.strip() else line for line in lines), len(
        candidates
    )


def strip_markers(text: str) -> tuple[str, int]:
    """Drop any prompt markers the model handed back as if they were code."""
    lines = text.split("\n")
    kept = [line for line in lines if not MARKER.match(line)]
    return "\n".join(kept), len(lines) - len(kept)


def sanitise_code(text: str) -> str:
    """Strip control characters, keeping the ones source code is made of."""
    return "".join(
        character
        for character in text
        if character in "\n\t" or unicodedata.category(character)[0] != "C"
    )


def parse(raw: str) -> ParsedPatch:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LlmContractError("The model's answer was not valid JSON.") from exc
    if not isinstance(payload, dict):
        raise LlmContractError("The model's answer was not a JSON object.")

    try:
        draft = PatchDraft.model_validate(payload)
    except ValidationError as exc:
        fields = ", ".join(str(error["loc"][0]) for error in exc.errors() if error.get("loc"))
        raise LlmContractError(
            f"The model's answer did not fit the required format ({fields or 'unknown field'})."
        ) from exc

    replacement = PREAMBLE.sub("", draft.replacement)
    replacement, fenced = strip_fences(replacement)
    replacement, _ = strip_markers(replacement)
    replacement, gutters = strip_gutters(replacement)
    replacement = sanitise_code(replacement).rstrip()

    if not replacement.strip():
        raise LlmContractError("The model returned no code to apply.")

    rationale = " ".join(sanitise_code(draft.rationale).split())
    if not rationale:
        raise LlmContractError("The model gave no reason for the change.")

    return ParsedPatch(
        replacement=replacement,
        rationale=rationale,
        fences_stripped=fenced,
        gutters_stripped=gutters,
    )


__all__ = [
    "MAX_RATIONALE_CHARS",
    "MAX_REPLACEMENT_CHARS",
    "PATCH_PROMPT_VERSION",
    "ParsedPatch",
    "PatchDraft",
    "parse",
    "sanitise_code",
    "strip_fences",
    "strip_gutters",
    "strip_markers",
]
