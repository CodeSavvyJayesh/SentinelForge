"""Asking for more fixes, so there is something to learn from.

The classifier needs fixes that were proposed and then checked. This module
queues the two requests a person would otherwise click one at a time:
"suggest a fix" for findings that have none with a verdict, and "validate" for
proposals nobody has checked.

It only adds rows to the two queues. The fixes are still written by the
language model and judged by the re-scan, through the same workers and the
same checks as a request made in the browser: nothing here decides an outcome,
and nothing here can produce an example that the application itself would not
have produced.
"""

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    ACTIVE_PATCH_STATUSES,
    ACTIVE_VALIDATION_STATUSES,
    AuditAction,
    ExplanationStatus,
    Finding,
    FindingStatus,
    Patch,
    PatchStatus,
    PatchValidation,
    PatchValidationStatus,
    Project,
    Repository,
)
from app.repositories.audit_log_repository import AuditLogRepository
from app.repositories.explanation_repository import ExplanationRepository

SOURCE = "collection script"
VERDICTS = (PatchValidationStatus.PASSED, PatchValidationStatus.REJECTED)


@dataclass(frozen=True)
class Queued:
    added: int
    # Findings or proposals that qualified but were over the limit.
    left: int


def _owned_findings(db: Session) -> list[tuple[Finding, int]]:
    statement = (
        select(Finding, Project.owner_id)
        .join(Repository, Finding.repository_id == Repository.id)
        .join(Project, Repository.project_id == Project.id)
        .where(Finding.status != FindingStatus.FIXED)
        .order_by(Finding.id.asc())
    )
    return [(finding, owner) for finding, owner in db.execute(statement)]


def queue_fixes(db: Session, *, limit: int, again: bool = False) -> Queued:
    """Request a fix for open findings that do not have one with a verdict.

    Credentials are skipped, as they are in the application: the fix for a
    leaked secret is to rotate it. With ``again``, a finding whose latest fix
    was rejected or refused is asked again — a second attempt is a second
    example, kept with the first on the same side of every split.
    """
    audit = AuditLogRepository(db)
    explanations = ExplanationRepository(db)
    patches = _patches_by_finding(db)
    verdicts = _latest_verdicts(db)
    added = left = 0
    for finding, owner in _owned_findings(db):
        if finding.is_credential:
            continue
        existing = patches.get(finding.id, [])
        if any(patch.status in ACTIVE_PATCH_STATUSES for patch in existing):
            continue
        unchecked = [
            patch
            for patch in existing
            if patch.status is PatchStatus.PROPOSED and patch.id not in verdicts
        ]
        if unchecked:
            continue  # it has a proposal waiting for a check; ask for that instead
        judged = [verdicts[patch.id] for patch in existing if patch.id in verdicts]
        if judged and not again:
            continue
        if again and judged and judged[-1] is PatchValidationStatus.PASSED:
            continue
        if added >= limit:
            left += 1
            continue
        # Built on the finding's explanation when it has one, exactly as a
        # request made in the browser is.
        explanation = explanations.latest_for_finding(finding.id)
        patch = Patch(
            finding_id=finding.id,
            requested_by_id=owner,
            status=PatchStatus.QUEUED,
            explanation_id=(
                explanation.id
                if explanation is not None and explanation.status is ExplanationStatus.COMPLETED
                else None
            ),
        )
        db.add(patch)
        db.flush()
        audit.add(
            action=str(AuditAction.PATCH_REQUESTED),
            user_id=owner,
            entity_type="patch",
            entity_id=str(patch.id),
            details={"finding_id": finding.id, "rule_id": finding.rule_id, "source": SOURCE},
        )
        added += 1
    return Queued(added, left)


def queue_checks(db: Session, *, limit: int) -> Queued:
    """Request a check for every proposal that has not been checked."""
    audit = AuditLogRepository(db)
    checked = {patch_id for (patch_id,) in db.execute(select(PatchValidation.patch_id).distinct())}
    statement = (
        select(Patch, Project.owner_id)
        .join(Finding, Patch.finding_id == Finding.id)
        .join(Repository, Finding.repository_id == Repository.id)
        .join(Project, Repository.project_id == Project.id)
        .where(Patch.status == PatchStatus.PROPOSED, Patch.diff.is_not(None))
        .order_by(Patch.id.asc())
    )
    added = left = 0
    for patch, owner in db.execute(statement):
        if patch.id in checked or not patch.diff:
            continue
        if added >= limit:
            left += 1
            continue
        validation = PatchValidation(
            patch_id=patch.id, requested_by_id=owner, status=PatchValidationStatus.QUEUED
        )
        db.add(validation)
        db.flush()
        audit.add(
            action=str(AuditAction.PATCH_VALIDATION_REQUESTED),
            user_id=owner,
            entity_type="patch_validation",
            entity_id=str(validation.id),
            details={"patch_id": patch.id, "finding_id": patch.finding_id, "source": SOURCE},
        )
        added += 1
    return Queued(added, left)


def _patches_by_finding(db: Session) -> dict[int, list[Patch]]:
    grouped: dict[int, list[Patch]] = {}
    for patch in db.scalars(select(Patch).order_by(Patch.id.asc())):
        grouped.setdefault(patch.finding_id, []).append(patch)
    return grouped


def _latest_verdicts(db: Session) -> dict[int, PatchValidationStatus]:
    """Patch -> the verdict of its latest finished check, where there is one."""
    statement = select(PatchValidation.patch_id, PatchValidation.status).order_by(
        PatchValidation.created_at.asc(), PatchValidation.id.asc()
    )
    latest: dict[int, PatchValidationStatus] = {}
    for patch_id, status in db.execute(statement):
        if status in ACTIVE_VALIDATION_STATUSES:
            continue
        latest[patch_id] = status
    return {patch_id: status for patch_id, status in latest.items() if status in VERDICTS}


__all__ = ["Queued", "queue_checks", "queue_fixes"]
