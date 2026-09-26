"""Explanation endpoints.

Request one, poll it, read the latest — the same 202-and-poll shape as scans,
for the same reason and more so: a 7B model on a CPU takes tens of seconds, and
no HTTP request should be held open that long.

There is no endpoint that generates synchronously, and none that accepts a
prompt. The prompt is built by the server from a finding and its indexed
passages; letting a client supply one would turn this into a general-purpose
model endpoint with the application's credentials attached to it.
"""

from fastapi import APIRouter, Response, status

from app.core.deps import Context, CurrentUser, ExplanationServiceDep
from app.models import Explanation
from app.schemas.error import ErrorResponse
from app.schemas.explanation import ExplanationCitation, ExplanationRead
from app.services.explanation_service import ExplanationService

router = APIRouter(tags=["explanations"])

NOT_FOUND_RESPONSE: dict[int | str, dict[str, object]] = {
    404: {
        "model": ErrorResponse,
        "description": "No such finding or explanation, or it belongs to someone else",
    },
}


def to_read(explanation: Explanation, service: ExplanationService) -> ExplanationRead:
    return ExplanationRead(
        id=explanation.id,
        finding_id=explanation.finding_id,
        status=explanation.status,
        attempts=explanation.attempts,
        summary=explanation.summary,
        impact=explanation.impact,
        remediation=explanation.remediation,
        model=explanation.model,
        prompt_version=explanation.prompt_version,
        citations=[
            ExplanationCitation(
                number=number,
                chunk_id=chunk.id,
                source=chunk.document.source,
                external_id=chunk.document.external_id,
                document_title=chunk.document.title,
                section=chunk.section,
                url=chunk.document.url,
            )
            for number, chunk in service.citations_for(explanation)
        ],
        grounded=explanation.grounded,
        dropped_citations=explanation.dropped_citations,
        links_removed=explanation.links_removed,
        duration_ms=explanation.duration_ms,
        prompt_tokens=explanation.prompt_tokens,
        completion_tokens=explanation.completion_tokens,
        error_message=explanation.error_message,
        created_at=explanation.created_at,
        finished_at=explanation.finished_at,
    )


@router.post(
    "/findings/{finding_id}/explanation",
    response_model=ExplanationRead,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ask the local model to explain a finding",
    responses={
        **NOT_FOUND_RESPONSE,
        409: {"model": ErrorResponse, "description": "This finding is already being explained"},
    },
)
def request_explanation(
    finding_id: int,
    user: CurrentUser,
    context: Context,
    service: ExplanationServiceDep,
) -> ExplanationRead:
    """202 Accepted: queued, not generated. The client polls the returned id."""
    return to_read(service.request(finding_id, user, context), service)


@router.get(
    "/explanations/{explanation_id}",
    response_model=ExplanationRead,
    summary="Poll one explanation",
    responses=NOT_FOUND_RESPONSE,
)
def get_explanation(
    explanation_id: int,
    user: CurrentUser,
    service: ExplanationServiceDep,
) -> ExplanationRead:
    return to_read(service.get(explanation_id, user), service)


@router.get(
    "/findings/{finding_id}/explanation",
    response_model=ExplanationRead | None,
    summary="The most recent explanation of a finding, if there is one",
    responses=NOT_FOUND_RESPONSE,
)
def latest_explanation(
    finding_id: int,
    user: CurrentUser,
    service: ExplanationServiceDep,
    response: Response,
) -> ExplanationRead | None:
    """Returns the latest attempt whatever its state — including failed ones.

    A failed generation is information: the UI can say the model is not running
    and name the command that starts it, rather than showing an empty panel that
    looks like the feature does not exist.

    204 when nothing has ever been requested, so "not asked for yet" is
    distinguishable from "asked for and produced nothing".
    """
    explanation = service.latest_for_finding(finding_id, user)
    if explanation is None:
        response.status_code = status.HTTP_204_NO_CONTENT
        return None
    return to_read(explanation, service)
