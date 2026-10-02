"""Patch endpoints.

The same 202-and-poll shape as scans and explanations, and for the same reason:
generation takes tens of seconds on a CPU.

What is deliberately **absent** is as important as what is here. There is no
endpoint that applies a patch to the repository, none that writes to the
workspace, and none that marks a finding fixed. A client can ask for a
proposal, ask for it to be checked, and read both.

Checking means what it has meant since the first page of this project: the diff
is applied to a throwaway copy and the analyser is run again. A patch is
reported ``validated`` only while its latest check passed, and even then the
finding stays open — the real code has not changed, and only a scan of the real
code can close a finding.
"""

from fastapi import APIRouter, Response, status

from app.core.deps import (
    Context,
    CurrentUser,
    DbSession,
    PatchServiceDep,
    PatchValidationServiceDep,
)
from app.models import Patch, PatchValidation, PatchValidationStatus
from app.schemas.error import ErrorResponse
from app.schemas.patch import NewFinding, PatchRead, PatchValidationRead, ValidationCheck
from app.services.patch_validation_service import PatchValidationService

router = APIRouter(tags=["patches"])

NOT_FOUND_RESPONSE: dict[int | str, dict[str, object]] = {
    404: {
        "model": ErrorResponse,
        "description": "No such finding or patch, or it belongs to someone else",
    },
}


def validation_to_read(validation: PatchValidation) -> PatchValidationRead:
    return PatchValidationRead(
        id=validation.id,
        status=validation.status,
        attempts=validation.attempts,
        checks=[ValidationCheck(**check) for check in validation.checks or []],
        findings_before=validation.findings_before,
        findings_after=validation.findings_after,
        also_resolved=validation.also_resolved,
        new_findings=[NewFinding(**item) for item in validation.new_findings or []],
        duration_ms=validation.duration_ms,
        error_message=validation.error_message,
        created_at=validation.created_at,
        finished_at=validation.finished_at,
    )


def to_read(patch: Patch, validations: PatchValidationService) -> PatchRead:
    latest = validations.latest_for_patch(patch.id)
    return PatchRead(
        id=patch.id,
        finding_id=patch.finding_id,
        status=patch.status,
        attempts=patch.attempts,
        diff=patch.diff,
        rationale=patch.rationale,
        file_path=patch.file_path,
        first_line=patch.first_line,
        last_line=patch.last_line,
        lines_added=patch.lines_added,
        lines_removed=patch.lines_removed,
        # Derived from the latest validation on every read. There is no column
        # on the patch that says "validated", so there is nothing to set by
        # hand and nothing that can go stale when a later check disagrees.
        validated=latest is not None and latest.status is PatchValidationStatus.PASSED,
        validation=validation_to_read(latest) if latest is not None else None,
        model=patch.model,
        prompt_version=patch.prompt_version,
        explanation_id=patch.explanation_id,
        fences_stripped=patch.fences_stripped,
        gutters_stripped=patch.gutters_stripped,
        reindented=patch.reindented,
        rejected_code=patch.rejected_code,
        temperature=patch.temperature,
        duration_ms=patch.duration_ms,
        prompt_tokens=patch.prompt_tokens,
        completion_tokens=patch.completion_tokens,
        error_message=patch.error_message,
        created_at=patch.created_at,
        finished_at=patch.finished_at,
    )


@router.post(
    "/findings/{finding_id}/patch",
    response_model=PatchRead,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ask the local model to propose a fix for a finding",
    responses={
        **NOT_FOUND_RESPONSE,
        409: {
            "model": ErrorResponse,
            "description": "Already being generated, or this finding cannot be patched",
        },
    },
)
def request_patch(
    finding_id: int,
    user: CurrentUser,
    context: Context,
    service: PatchServiceDep,
    validations: PatchValidationServiceDep,
    db: DbSession,
) -> PatchRead:
    """202 Accepted: queued, not generated. The client polls the returned id.

    The commit is load-bearing — Phase 8 shipped this endpoint without one and
    the symptom was a perfect-looking 202 for a row that had been rolled back.
    A test asserts the commit itself, because the shared-session test fixture
    cannot otherwise tell the difference.
    """
    patch = service.request(finding_id, user, context)
    db.commit()
    db.refresh(patch)
    return to_read(patch, validations)


@router.get(
    "/patches/{patch_id}",
    response_model=PatchRead,
    summary="Poll one proposed change",
    responses=NOT_FOUND_RESPONSE,
)
def get_patch(
    patch_id: int,
    user: CurrentUser,
    service: PatchServiceDep,
    validations: PatchValidationServiceDep,
) -> PatchRead:
    return to_read(service.get(patch_id, user), validations)


@router.get(
    "/findings/{finding_id}/patch",
    response_model=PatchRead | None,
    summary="The most recent proposed change for a finding, if there is one",
    responses=NOT_FOUND_RESPONSE,
)
def latest_patch(
    finding_id: int,
    user: CurrentUser,
    service: PatchServiceDep,
    validations: PatchValidationServiceDep,
    response: Response,
) -> PatchRead | None:
    """Latest attempt whatever its state, including refused ones.

    A refusal is the most useful thing this endpoint returns: "the proposed
    change mostly deletes code" tells a developer something true about the
    model. 204 when nothing was ever requested, so "not asked for" stays
    distinguishable from "asked for and refused".
    """
    patch = service.latest_for_finding(finding_id, user)
    if patch is None:
        response.status_code = status.HTTP_204_NO_CONTENT
        return None
    return to_read(patch, validations)


@router.post(
    "/patches/{patch_id}/validation",
    response_model=PatchRead,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Check a proposed change by applying it to a copy and re-scanning",
    responses={
        **NOT_FOUND_RESPONSE,
        409: {
            "model": ErrorResponse,
            "description": "Already being checked, or there is no proposal to check",
        },
    },
)
def request_validation(
    patch_id: int,
    user: CurrentUser,
    context: Context,
    validations: PatchValidationServiceDep,
    db: DbSession,
) -> PatchRead:
    """202 Accepted: queued, not checked. The client polls the patch.

    Every proposal is checked automatically when it is generated; this endpoint
    is for checking one again — a proposal from before validation existed, or
    one whose check could not run because the stored code had moved.

    Returns the patch, with the queued validation inside it, so a client holds
    one object and polls one URL.
    """
    patch = validations.request(patch_id, user, context)
    db.commit()
    db.refresh(patch)
    return to_read(patch, validations)
