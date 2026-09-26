"""Security knowledge endpoints.

Two reads, no writes. The knowledge base is built by ``scripts/build_knowledge.py``
from files on disk, deliberately not over HTTP: indexing the CWE catalogue takes
minutes of CPU, and an endpoint that could trigger it would be both a denial of
service and a way to put arbitrary text into everybody's knowledge base.
"""

from fastapi import APIRouter

from app.core.deps import CurrentUser, KnowledgeServiceDep
from app.schemas.error import ErrorResponse
from app.schemas.knowledge import (
    FindingKnowledgeResponse,
    KnowledgePassage,
    KnowledgeStatusResponse,
)
from app.services.knowledge_service import query_text

router = APIRouter(tags=["knowledge"])


@router.get(
    "/findings/{finding_id}/knowledge",
    response_model=FindingKnowledgeResponse,
    summary="Reference material explaining one finding",
    responses={
        404: {
            "model": ErrorResponse,
            "description": "No such finding, or it belongs to someone else",
        },
        503: {
            "model": ErrorResponse,
            "description": "The knowledge base has not been built, or was built with another model",
        },
    },
)
def finding_knowledge(
    finding_id: int,
    user: CurrentUser,
    service: KnowledgeServiceDep,
) -> FindingKnowledgeResponse:
    finding, passages = service.for_finding(finding_id, user)
    return FindingKnowledgeResponse(
        finding_id=finding.id,
        rule_id=finding.rule_id,
        cwe_id=finding.cwe_id,
        owasp_category=finding.owasp_category,
        query=query_text(finding),
        passages=[
            KnowledgePassage(
                id=passage.chunk.id,
                source=passage.chunk.document.source,
                external_id=passage.chunk.document.external_id,
                document_title=passage.chunk.document.title,
                section=passage.chunk.section,
                text=passage.chunk.text,
                url=passage.chunk.document.url,
                source_version=passage.chunk.document.source_version,
                score=passage.score,
                matched_by=passage.matched_by,
            )
            for passage in passages
        ],
    )


@router.get(
    "/knowledge/status",
    response_model=KnowledgeStatusResponse,
    summary="Whether the knowledge base has been built, and from what",
)
def knowledge_status(user: CurrentUser, service: KnowledgeServiceDep) -> KnowledgeStatusResponse:
    """Reported rather than inferred.

    The UI needs to tell "this weakness has no reference material" apart from
    "nobody has built the knowledge base on this machine", because the first is
    a statement about a vulnerability and the second is a statement about an
    installation. Only one of them should worry anyone.
    """
    status = service.status()
    return KnowledgeStatusResponse(
        built=status.built,
        documents=status.documents,
        chunks=status.chunks,
        embedded_chunks=status.embedded_chunks,
        by_source=status.counts_by_source,
        embedding_models=status.embedding_models,
        source_versions=status.source_versions,
        built_at=status.built_at,
    )
