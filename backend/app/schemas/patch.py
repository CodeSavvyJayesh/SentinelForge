"""Patch response schema.

The shape is built round one claim the API is careful about: whether this code
has been checked, and by what. ``status`` says whether a proposal exists.
``validated`` is true only when the most recent re-scan of a throwaway copy
passed every check — it is derived from that validation row on every read, and
there is no column anybody could set by hand. ``validation`` carries the checks
themselves, so a verdict never travels without its evidence.

Even then ``validated`` means something narrow: the finding is no longer
detected, nothing new is, and the change is not a deletion. It does not mean
the program still behaves the same, and nothing here says so.

The diff is returned as text rather than parsed into hunks. It came from
``difflib``, so it is already in the format every developer tool understands,
and the frontend renders it by colouring lines — not by interpreting them.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.patch import PatchStatus
from app.models.patch_validation import PatchValidationStatus


class ValidationCheck(BaseModel):
    """One thing the re-scan tested, and how it came out."""

    key: str
    # "passed", "failed" or "skipped". Skipped is shown, not hidden: "this was
    # not checked for Java" is information a reviewer needs.
    outcome: str
    detail: str


class NewFinding(BaseModel):
    """Something the patched copy has that the original did not."""

    rule_id: str
    title: str
    severity: str
    file_path: str
    line: int


class PatchValidationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    status: PatchValidationStatus
    attempts: int
    checks: list[ValidationCheck]
    findings_before: int | None
    findings_after: int | None
    also_resolved: int
    new_findings: list[NewFinding]
    duration_ms: int | None
    error_message: str | None
    created_at: datetime
    finished_at: datetime | None


class PatchRead(BaseModel):
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    id: int
    finding_id: int
    status: PatchStatus
    attempts: int

    # What to show.
    diff: str | None
    rationale: str | None
    file_path: str | None
    first_line: int | None
    last_line: int | None
    lines_added: int
    lines_removed: int

    # True only when the latest re-scan of a throwaway copy passed every check.
    # Derived on each read from that validation; never stored on the patch.
    validated: bool
    # The latest validation, whatever state it is in — including "could not be
    # checked", which is not the same as "checked and rejected".
    validation: PatchValidationRead | None

    # Provenance, same reasoning as explanations: a proposal with no origin is
    # one a developer cannot weigh.
    model: str | None
    prompt_version: int | None
    explanation_id: int | None

    # How much tidying the model's answer needed. Surfaced, not hidden: a
    # proposal that arrived wrapped in markdown says something about how
    # closely the model followed the contract.
    fences_stripped: bool
    gutters_stripped: int
    reindented: bool

    # What the model returned when the proposal was refused. Shown behind a
    # disclosure rather than hidden: "the change mostly deletes code" is a
    # verdict, and a developer is entitled to see what it was passed on. Null
    # on success, where the diff is the answer.
    rejected_code: str | None
    # Recorded so two runs of the same prompt are distinguishable.
    temperature: float | None

    duration_ms: int | None
    prompt_tokens: int | None
    completion_tokens: int | None
    error_message: str | None
    created_at: datetime
    finished_at: datetime | None


__all__ = ["NewFinding", "PatchRead", "PatchValidationRead", "ValidationCheck"]
