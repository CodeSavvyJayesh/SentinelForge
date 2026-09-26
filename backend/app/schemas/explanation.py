"""Explanation request/response schemas.

Every field here exists so a reader can judge the text rather than only read it.
``model``, ``prompt_version`` and the resolved citations say what produced it;
``dropped_citations`` and ``links_removed`` say what had to be taken out of it;
``grounded`` says whether it rests on anything at all.

None of that is decoration. An explanation written by a language model is a
claim, and a claim with no provenance is one a developer cannot check.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.explanation import ExplanationStatus
from app.models.knowledge import KnowledgeSource


class ExplanationCitation(BaseModel):
    """A passage the model cited, resolved back to the real document.

    The number is the one the model saw in its prompt; everything else is read
    from our own knowledge base, never from the model. That is what makes the
    link safe to render — a model-authored URL would point wherever it liked.
    """

    number: int
    chunk_id: int
    source: KnowledgeSource
    external_id: str
    document_title: str
    section: str
    url: str | None


class ExplanationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    id: int
    finding_id: int
    status: ExplanationStatus
    attempts: int

    summary: str | None
    impact: str | None
    remediation: str | None

    # Provenance.
    model: str | None
    prompt_version: int | None
    citations: list[ExplanationCitation]
    # True when at least one citation survived verification.
    grounded: bool

    # What the contract had to remove. Surfaced rather than logged: these are
    # the clearest signal available that the model invented something.
    dropped_citations: int
    links_removed: int

    duration_ms: int | None
    prompt_tokens: int | None
    completion_tokens: int | None
    error_message: str | None
    created_at: datetime
    finished_at: datetime | None


__all__ = ["ExplanationCitation", "ExplanationRead"]
