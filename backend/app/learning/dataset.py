"""Reading the training examples out of the database.

An example is one proposed fix that was checked and got a verdict. Three kinds
of row are deliberately not examples:

* a fix that is still being generated, or was refused before it became a
  proposal — there is nothing to check;
* a proposal nobody has checked yet;
* a proposal whose check could not be completed (``FAILED``: the code had
  moved). That is no verdict on the fix, and counting it as a rejection would
  teach the model that stale workspaces are the fix's fault.

When a proposal was checked more than once, the latest check is its verdict —
the same rule the dashboard uses, so the model is trained on the outcomes the
application shows.
"""

from collections import Counter
from dataclasses import dataclass
from pathlib import PurePosixPath

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.learning.features import PatchExample
from app.models import (
    ACTIVE_PATCH_STATUSES,
    ACTIVE_VALIDATION_STATUSES,
    Finding,
    Patch,
    PatchStatus,
    PatchValidation,
    PatchValidationStatus,
)

VERDICTS = {PatchValidationStatus.PASSED: True, PatchValidationStatus.REJECTED: False}


@dataclass(frozen=True)
class Collected:
    examples: list[PatchExample]
    # Every fix that was ever requested, by what became of it.
    requested: int
    generating: int
    refused: int
    unchecked: int
    checking: int
    not_judged: int

    @property
    def passed(self) -> int:
        return sum(1 for item in self.examples if item.passed)

    @property
    def rejected(self) -> int:
        return len(self.examples) - self.passed

    def by_rule(self) -> list[tuple[str, int, int]]:
        """(rule, passed, rejected), most examples first."""
        passed: Counter[str] = Counter(item.rule_id for item in self.examples if item.passed)
        total: Counter[str] = Counter(item.rule_id for item in self.examples)
        return [
            (rule, passed[rule], count - passed[rule])
            for rule, count in sorted(total.items(), key=lambda pair: (-pair[1], pair[0]))
        ]


def collect(db: Session) -> Collected:
    """Every fix in the database, sorted into examples and everything else."""
    statement = (
        select(Patch, Finding, PatchValidation.status)
        .join(Finding, Patch.finding_id == Finding.id)
        .outerjoin(PatchValidation, PatchValidation.patch_id == Patch.id)
        .order_by(Patch.id.asc(), PatchValidation.created_at.asc(), PatchValidation.id.asc())
    )
    latest: dict[int, tuple[Patch, Finding, PatchValidationStatus | None]] = {}
    for patch, finding, validation in db.execute(statement):
        latest[patch.id] = (patch, finding, validation)  # later checks overwrite earlier ones

    counts: Counter[str] = Counter()
    examples: list[PatchExample] = []
    for patch, finding, validation in latest.values():
        counts["requested"] += 1
        if patch.status in ACTIVE_PATCH_STATUSES:
            counts["generating"] += 1
        elif patch.status is not PatchStatus.PROPOSED:
            counts["refused"] += 1
        elif validation is None:
            counts["unchecked"] += 1
        elif validation in ACTIVE_VALIDATION_STATUSES:
            counts["checking"] += 1
        elif validation in VERDICTS:
            examples.append(example_from(patch, finding, VERDICTS[validation]))
        else:
            counts["not_judged"] += 1
    return Collected(
        examples=examples,
        requested=counts["requested"],
        generating=counts["generating"],
        refused=counts["refused"],
        unchecked=counts["unchecked"],
        checking=counts["checking"],
        not_judged=counts["not_judged"],
    )


def example_from(patch: Patch, finding: Finding, passed: bool) -> PatchExample:
    first, last = patch.first_line or 0, patch.last_line or 0
    return PatchExample(
        patch_id=patch.id,
        finding_id=finding.id,
        passed=passed,
        rule_id=finding.rule_id,
        severity=str(finding.severity),
        confidence=str(finding.confidence),
        suffix=PurePosixPath(finding.file_path).suffix.lower() or "none",
        lines_added=patch.lines_added or 0,
        lines_removed=patch.lines_removed or 0,
        region_lines=max(0, last - first + 1) if first and last else 0,
        diff_characters=len(patch.diff or ""),
        rationale_characters=len(patch.rationale or ""),
        fences_stripped=bool(patch.fences_stripped),
        gutters_stripped=patch.gutters_stripped or 0,
        reindented=bool(patch.reindented),
        attempts=patch.attempts or 0,
        had_explanation=patch.explanation_id is not None,
        passages=len(patch.passage_chunk_ids or ()),
        prompt_tokens=patch.prompt_tokens,
        completion_tokens=patch.completion_tokens,
        duration_ms=patch.duration_ms,
        temperature=patch.temperature,
    )


__all__ = ["Collected", "collect", "example_from"]
