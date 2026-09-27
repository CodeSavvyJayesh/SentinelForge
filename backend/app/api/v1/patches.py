"""Patch endpoints.

The same 202-and-poll shape as scans and explanations, and for the same reason:
generation takes tens of seconds on a CPU.

What is deliberately **absent** is as important as what is here. There is no
endpoint that applies a patch, none that writes to the workspace, and none that
marks a finding fixed. A client can ask for a proposal and read it. Turning a
proposal into a change is Phase 11's problem, and Phase 11 does it by copying
the repository, applying there, and re-scanning — never by trusting this text.
"""

from fastapi import APIRouter, Response, status

from app.core.deps import Context, CurrentUser, DbSession, PatchServiceDep
from app.models import Patch
from app.schemas.error import ErrorResponse
from app.schemas.patch import PatchRead

router = APIRouter(tags=["patches"])

NOT_FOUND_RESPONSE: dict[int | str, dict[str, object]] = {
    404: {
        "model": ErrorResponse,
        "description": "No such finding or patch, or it belongs to someone else",
    },
}


def to_read(patch: Patch) -> PatchRead:
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
        # Hard-coded, not read from the row. Nothing in this phase can set it
        # true, and a column that only ever holds one value would invite
        # somebody to set it by hand.
        validated=False,
        model=patch.model,
        prompt_version=patch.prompt_version,
        explanation_id=patch.explanation_id,
        fences_stripped=patch.fences_stripped,
        gutters_stripped=patch.gutters_stripped,
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
    return to_read(patch)


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
) -> PatchRead:
    return to_read(service.get(patch_id, user))


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
    return to_read(patch)
