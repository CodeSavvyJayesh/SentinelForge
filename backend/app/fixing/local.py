"""One finding in, one judged proposal out — with no database.

The steps, and why they are in this order:

1. **Scan the folder as it is now** and look the finding up in the result. A
   finding the caller remembers from an earlier scan may no longer be there —
   the file was edited, or the line moved — and a fix worked out from a
   remembered line number would edit whatever is on that line today.
2. **Refuse a credential.** Editing the line does not un-leak it.
3. **Get a change**, from the built-in rewriter or from the local model. The
   model is asked the same question, through the same prompt and the same
   output contract, as it is by the web application.
4. **Check the change is worth testing** — it changes something, it is not a
   deletion, the file still parses.
5. **Apply it to a throwaway copy and scan again.** Only this can say the
   finding is gone, and it is asked about every proposal, built-in ones
   included.

Nothing is written to the folder. The result carries the change as a diff and
as line edits; whoever asked decides what to do with them.
"""

import difflib
import ipaddress
import urllib.parse
from dataclasses import dataclass, replace
from pathlib import Path

from app.analysis.engine import analyze_workspace
from app.analysis.findings import Finding
from app.core.config import Settings
from app.fixing import builtin
from app.knowledge.rule_notes import NOTES_BY_RULE
from app.llm import patch_prompt
from app.llm.client import LlmError, OllamaClient
from app.llm.contract import LlmContractError
from app.llm.patch_contract import parse as parse_patch
from app.llm.prompt import PromptPassage
from app.models.finding import CREDENTIAL_CWE
from app.patching import CREDENTIAL_MESSAGE, RETRY_TEMPERATURE, diffing, validation
from app.patching.region import RegionError, read_region, reindent, splice, still_holds

VERIFIED = "verified"
REJECTED = "rejected"
NO_FIX = "no_fix"

BUILTIN = "builtin"
MODEL = "model"
MODES = (BUILTIN, MODEL)

NO_BUILTIN_FOR_RULE = (
    "There is no built-in fix for this rule: the right change depends on the code around it. "
    "Ask the local model for a suggestion, or change it by hand."
)
NO_BUILTIN_FOR_LINE = (
    "This line is not written in a way the built-in fix can rewrite safely. "
    "Ask the local model for a suggestion, or change it by hand."
)
STALE_FINDING = "That finding is not in the code as it is now. Scan again, then ask for the fix."
UNPLACEABLE = (
    "The finding could not be matched to the lines of its file, so no change was worked out. "
    "Files containing unusual line-break characters are numbered differently by different tools."
)

# The only places a local model can be. `localhost` is taken at its word: a
# machine whose hosts file points it elsewhere has a problem this tool cannot
# see, let alone fix.
LOOPBACK_NAMES = frozenset({"localhost"})


class FixError(RuntimeError):
    """A fix could not be attempted at all. The message is safe to show."""


@dataclass(frozen=True)
class Edit:
    """One run of lines to replace, as an editor wants it.

    ``first_line`` and ``last_line`` are 1-based and inclusive. An insertion
    replaces nothing: its ``last_line`` is one less than its ``first_line``,
    and the new lines go in before ``first_line``.

    ``old`` is what must be on those lines for the edit to be valid. An editor
    holding a file that has changed since the fix was worked out can see that
    it has, and refuse, rather than replace lines nobody checked.
    """

    first_line: int
    last_line: int
    old: tuple[str, ...]
    new: tuple[str, ...]


@dataclass(frozen=True)
class ModelUse:
    """What the model was and how far its answer was from usable code."""

    model: str
    temperature: float
    prompt_tokens: int
    completion_tokens: int
    duration_ms: int
    fences_stripped: bool
    gutters_stripped: int
    reindented: bool


@dataclass(frozen=True)
class FixResult:
    status: str
    source: str
    finding: Finding
    title: str
    rationale: str
    caution: str | None = None
    # Why there is nothing to apply, whenever ``status`` is not VERIFIED.
    reason: str | None = None
    diff: str = ""
    lines_added: int = 0
    lines_removed: int = 0
    # Empty unless the re-scan passed: a change that failed it is shown, as a
    # diff, and is not something this result offers to apply.
    edits: tuple[Edit, ...] = ()
    before: tuple[str, ...] = ()
    after: tuple[str, ...] = ()
    outcome: validation.Outcome | None = None
    model: ModelUse | None = None

    @property
    def verified(self) -> bool:
        return self.status == VERIFIED


def is_loopback(url: str) -> bool:
    """Whether a model URL points at this machine."""
    host = urllib.parse.urlparse(url).hostname or ""
    if host.lower() in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def find(findings: list[Finding], *, fingerprint: str) -> Finding | None:
    return next((item for item in findings if item.fingerprint == fingerprint), None)


def reference(rule_id: str) -> list[PromptPassage]:
    """This project's own note for the rule, as the model's reference.

    The web application retrieves passages from the knowledge base in its
    database. There is no database here, so the model is given the one source
    that ships with the code: the note written for this rule, in the language
    the rule fires on.
    """
    note = NOTES_BY_RULE.get(rule_id)
    if note is None:
        return []
    return [
        PromptPassage(1, "SENTINELFORGE", rule_id, "Risk", note.risk),
        PromptPassage(2, "SENTINELFORGE", rule_id, "Fix", note.fix),
    ]


def edits_between(before: list[str], after: list[str]) -> tuple[Edit, ...]:
    """The smallest runs of lines that turn one file into the other."""
    # A fix touches a few lines of a file that may have thousands. Trimming
    # what the two have in common first keeps the comparison to the part that
    # differs, and keeps it exact.
    limit = min(len(before), len(after))
    head = 0
    while head < limit and before[head] == after[head]:
        head += 1
    tail = 0
    while tail < limit - head and before[-1 - tail] == after[-1 - tail]:
        tail += 1
    old = before[head : len(before) - tail]
    new = after[head : len(after) - tail]
    matcher = difflib.SequenceMatcher(None, old, new, autojunk=False)
    return tuple(
        Edit(head + i1 + 1, head + i2, tuple(old[i1:i2]), tuple(new[j1:j2]))
        for tag, i1, i2, j1, j2 in matcher.get_opcodes()
        if tag != "equal"
    )


def fix(  # noqa: PLR0911 - one return per way a fix can end
    root: Path,
    fingerprint: str,
    *,
    mode: str,
    settings: Settings,
    llm: OllamaClient | None = None,
    retry: bool = False,
) -> FixResult:
    """Propose a change for one finding and judge it by scanning."""
    if mode not in MODES:
        raise FixError(f"Unknown mode: {mode}")

    before = analyze_workspace(root, settings)
    if before.truncated:
        raise FixError(validation.TRUNCATED_MESSAGE)
    target = find(before.findings, fingerprint=fingerprint)
    if target is None:
        raise FixError(STALE_FINDING)

    fixer = builtin.FIXES.get(target.rule_id)
    title = fixer.title if mode == BUILTIN and fixer else target.title
    nothing = FixResult(NO_FIX, mode, target, title, "")

    if target.cwe_id == CREDENTIAL_CWE:
        return replace(nothing, reason=CREDENTIAL_MESSAGE)

    try:
        region = read_region(root, target.file_path, target.line_start, target.line_end)
    except RegionError as error:
        raise FixError(str(error)) from error
    if not still_holds(region, target.snippet):
        # The finding was made a moment ago from these same bytes, so this is
        # not an edit: it is two ways of counting lines disagreeing. Either
        # way, the lines in hand are not known to be the ones reported.
        raise FixError(UNPLACEABLE)

    model: ModelUse | None = None
    if mode == BUILTIN:
        if fixer is None:
            return replace(nothing, reason=NO_BUILTIN_FOR_RULE)
        after = fixer.rewrite(region.file_lines, target)
        if after is None:
            return replace(nothing, reason=NO_BUILTIN_FOR_LINE)
        rationale, caution = fixer.rationale, fixer.caution
    else:
        if llm is None:
            raise FixError("No model was configured.")
        try:
            llm.check_ready()
            temperature = RETRY_TEMPERATURE if retry else None
            completion = llm.generate(
                patch_prompt.build(target, region, reference(target.rule_id), None),
                system=patch_prompt.SYSTEM_PROMPT,
                temperature=temperature,
            )
        except LlmError as error:
            raise FixError(error.message) from error
        try:
            parsed = parse_patch(completion.text)
        except LlmContractError as error:
            return replace(nothing, status=REJECTED, reason=str(error))
        replacement, reindented = reindent(parsed.replacement, region.lines)
        after = splice(region, replacement)
        rationale, caution = parsed.rationale, None
        model = ModelUse(
            model=completion.model,
            temperature=llm.temperature if temperature is None else temperature,
            prompt_tokens=completion.prompt_tokens,
            completion_tokens=completion.completion_tokens,
            duration_ms=completion.total_duration_ms,
            fences_stripped=parsed.fences_stripped,
            gutters_stripped=parsed.gutters_stripped,
            reindented=reindented,
        )

    proposal = FixResult(
        REJECTED,
        mode,
        target,
        title,
        rationale,
        caution=caution,
        before=tuple(region.file_lines),
        after=tuple(after),
        model=model,
    )
    try:
        diff = diffing.build_checked(
            target.file_path, region.file_lines, after, replaced_lines=len(region.lines)
        )
    except diffing.PatchRejected as rejection:
        return replace(proposal, reason=str(rejection))
    proposal = replace(proposal, diff=diff.text, lines_added=diff.added, lines_removed=diff.removed)

    try:
        outcome = validation.validate(
            root, target.file_path, diff.text, fingerprint, settings, before=before
        )
    except validation.CannotValidate as error:
        raise FixError(str(error)) from error

    if not outcome.passed:
        failed = [check.detail for check in outcome.checks if check.outcome == validation.FAILED]
        return replace(proposal, outcome=outcome, reason=" ".join(failed))
    return replace(
        proposal,
        status=VERIFIED,
        outcome=outcome,
        edits=edits_between(region.file_lines, after),
    )


__all__ = [
    "BUILTIN",
    "MODEL",
    "MODES",
    "NO_FIX",
    "REJECTED",
    "VERIFIED",
    "Edit",
    "FixError",
    "FixResult",
    "ModelUse",
    "edits_between",
    "find",
    "fix",
    "is_loopback",
    "reference",
]
