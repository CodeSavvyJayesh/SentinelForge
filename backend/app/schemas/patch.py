"""Patch response schema.

The shape is built round one claim the API is careful never to make: that this
code is correct. ``status`` never reaches "applied" or "verified" in this phase,
``validated`` is always ``False``, and the counters say how much the model's
output had to be cleaned before it could be treated as code.

The diff is returned as text rather than parsed into hunks. It came from
``difflib``, so it is already in the format every developer tool understands,
and the frontend renders it by colouring lines — not by interpreting them.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.patch import PatchStatus


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

    # Always False in this phase. It is a field rather than an omission so the
    # frontend renders the warning from data, and so Phase 11 has somewhere to
    # put the answer instead of changing the contract.
    validated: bool

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


__all__ = ["PatchRead"]
