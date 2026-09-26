"""Knowledge-base request/response schemas.

Every passage carries its source, its title and its URL. That is not decoration:
security advice a developer cannot trace back to who said it is advice they
cannot check, and this project's own notes must be visibly distinguishable from
MITRE's and OWASP's text.

``matched_by`` is exposed for the same reason. A passage found because it was
written for this exact rule and one found because it scored well against a
vector are both useful, and the reader is entitled to know which is which.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.knowledge import KnowledgeSource


class KnowledgePassage(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source: KnowledgeSource
    external_id: str
    document_title: str
    section: str
    text: str
    url: str | None
    source_version: str | None
    # Cosine similarity against the query, in [-1, 1]. Shown rounded; kept as a
    # float here so a test can assert an ordering rather than a rendering.
    score: float
    matched_by: str = Field(
        description="rule, cwe, owasp or semantic — why this passage was retrieved"
    )


class FindingKnowledgeResponse(BaseModel):
    finding_id: int
    rule_id: str
    cwe_id: str | None
    owasp_category: str | None
    # The text actually embedded to search with. Exposed because a retrieval
    # result nobody can reproduce is a result nobody can argue with.
    query: str
    passages: list[KnowledgePassage]


class KnowledgeStatusResponse(BaseModel):
    built: bool
    documents: int
    chunks: int
    embedded_chunks: int
    by_source: dict[str, int]
    embedding_models: list[str]
    source_versions: dict[str, str]
    built_at: datetime | None


__all__ = ["FindingKnowledgeResponse", "KnowledgePassage", "KnowledgeStatusResponse"]
