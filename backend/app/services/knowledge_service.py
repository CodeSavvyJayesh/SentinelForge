"""Retrieval: given a finding, find the passages that are about it.

The algorithm is **filter first, then rank**, and the order is the whole point.

A finding already carries structured facts the analyser was certain about: which
rule fired, and which CWE that rule maps to. Those are not guesses, so they are
used as a filter — every passage tagged with this finding's CWE, or written for
this finding's rule, is a candidate. The embedding model's job is then only to
*order* those candidates: within CWE-89 it decides whether this question is
better answered by the description or by the mitigations.

Only when that filter comes back short — a rule with no CWE, a CWE the
catalogue does not cover — does an unrestricted similarity search run, and
those results have to clear a minimum score to be shown at all. A passage
retrieved purely because it was the least-bad match is noise wearing a citation.

This ordering is also what makes the phase cheap. The common case touches a few
dozen vectors, not the whole corpus.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from http import HTTPStatus
from pathlib import PurePosixPath

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.errors import AppError
from app.core.logging import get_logger
from app.knowledge.embedder import Embedder, EmbeddingBackendUnavailableError
from app.knowledge.sources.owasp import owasp_code
from app.knowledge.vectors import VectorFormatError, decode, similarity
from app.models import Finding, KnowledgeChunk, User
from app.repositories.finding_repository import FindingRepository
from app.repositories.knowledge_repository import KnowledgeRepository

logger = get_logger("sentinelforge.knowledge")

# Which language a finding is in, for the retrieval query. "How do I fix weak
# hashing" and "how do I fix weak hashing in Java" retrieve different passages,
# and the second question is the one the developer is actually asking.
LANGUAGE_BY_SUFFIX: dict[str, str] = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".java": "Java",
    ".php": "PHP",
    ".go": "Go",
    ".rb": "Ruby",
    ".cs": "C#",
    ".sql": "SQL",
}


class FindingNotFoundError(AppError):
    def __init__(self) -> None:
        super().__init__("FINDING_NOT_FOUND", "Finding not found", status_code=HTTPStatus.NOT_FOUND)


class KnowledgeBaseNotBuiltError(AppError):
    """No usable knowledge base. Said plainly rather than returning an empty list.

    An empty list reads as "there is nothing to say about this vulnerability",
    which is a lie about the vulnerability. This reads as "the knowledge base
    has not been built", which is the truth about the installation.
    """

    def __init__(self, detail: str) -> None:
        super().__init__(
            "KNOWLEDGE_BASE_NOT_BUILT", detail, status_code=HTTPStatus.SERVICE_UNAVAILABLE
        )


@dataclass(frozen=True)
class RetrievedPassage:
    chunk: KnowledgeChunk
    score: float
    # "rule", "cwe" or "semantic" — how this passage was found. Surfaced in the
    # API so the reader can tell targeted advice from a similarity match.
    matched_by: str


@dataclass(frozen=True)
class KnowledgeStatus:
    built: bool
    documents: int
    chunks: int
    embedded_chunks: int
    counts_by_source: dict[str, int]
    embedding_models: list[str]
    source_versions: dict[str, str]
    built_at: object | None


def language_for(file_path: str) -> str | None:
    return LANGUAGE_BY_SUFFIX.get(PurePosixPath(file_path).suffix.lower())


def query_text(finding: Finding) -> str:
    """The question put to the embedding model.

    Built from the finding's *metadata* — rule title, message, CWE, language —
    and deliberately **not** from its code snippet. Two reasons, one of them
    non-negotiable: a snippet can contain a credential, and the query has no
    business carrying one anywhere. The weaker reason is that it would not help
    much; a line of code embeds to "some code", while the rule's title embeds to
    the weakness it describes.
    """
    parts = [finding.title, finding.message]
    if finding.cwe_id:
        parts.append(finding.cwe_id)
    if finding.owasp_category:
        parts.append(finding.owasp_category)
    language = language_for(finding.file_path)
    if language:
        parts.append(f"in {language}")
    return " ".join(part for part in parts if part)


class KnowledgeService:
    def __init__(self, db: Session, settings: Settings, embedder: Embedder) -> None:
        self.db = db
        self.settings = settings
        self.embedder = embedder
        self.knowledge = KnowledgeRepository(db)
        self.findings = FindingRepository(db)

    # -- status ------------------------------------------------------------

    def status(self) -> KnowledgeStatus:
        embedded = self.knowledge.chunk_count(embedded_only=True)
        return KnowledgeStatus(
            built=embedded > 0,
            documents=self.knowledge.document_count(),
            chunks=self.knowledge.chunk_count(),
            embedded_chunks=embedded,
            counts_by_source=self.knowledge.counts_by_source(),
            embedding_models=self.knowledge.embedding_models(),
            source_versions=self.knowledge.source_versions(),
            built_at=self.knowledge.built_at(),
        )

    # -- retrieval ---------------------------------------------------------

    def for_finding(self, finding_id: int, user: User) -> tuple[Finding, list[RetrievedPassage]]:
        finding = self.findings.get_for_owner(finding_id, user.id)
        if finding is None:
            raise FindingNotFoundError
        return finding, self.retrieve(finding)

    def retrieve(self, finding: Finding) -> list[RetrievedPassage]:
        self._assert_usable()

        try:
            vector = self.embedder.embed_query(query_text(finding))
        except EmbeddingBackendUnavailableError as exc:
            raise KnowledgeBaseNotBuiltError(str(exc)) from exc

        limit = self.settings.KNOWLEDGE_RETRIEVAL_LIMIT
        candidates = self.knowledge.candidates_for(
            cwe_id=finding.cwe_id,
            rule_id=finding.rule_id,
            owasp_category=owasp_code(finding.owasp_category),
        )
        passages = self._rank(candidates, vector, finding)[:limit]

        if len(passages) < limit:
            passages.extend(self._top_up(vector, finding, limit - len(passages), candidates))

        logger.info(
            "knowledge_retrieved",
            extra={
                "finding_id": finding.id,
                "rule_id": finding.rule_id,
                "cwe_id": finding.cwe_id,
                "candidates": len(candidates),
                "returned": len(passages),
            },
        )
        return passages

    # -- internals ---------------------------------------------------------

    def _assert_usable(self) -> None:
        if self.knowledge.chunk_count(embedded_only=True) == 0:
            raise KnowledgeBaseNotBuiltError(
                "The security knowledge base has not been built yet. "
                "Run scripts/build_knowledge.py to index the CWE and OWASP sources."
            )
        models = self.knowledge.embedding_models()
        # More than one model, or the wrong one, means stored vectors and query
        # vectors live in different spaces. The dot products would still come
        # out as numbers, and every one of them would be meaningless.
        if len(models) > 1:
            raise KnowledgeBaseNotBuiltError(
                "The knowledge base was built with more than one embedding model "
                f"({', '.join(models)}), so its scores cannot be compared. Rebuild it."
            )
        if models and models[0] != self.embedder.model_id:
            raise KnowledgeBaseNotBuiltError(
                f"The knowledge base was built with {models[0]!r} but the application is "
                f"configured for {self.embedder.model_id!r}. Rebuild it, or restore the setting."
            )

    def _rank(
        self, chunks: Iterable[KnowledgeChunk], vector: list[float], finding: Finding
    ) -> list[RetrievedPassage]:
        scored: list[RetrievedPassage] = []
        for chunk in chunks:
            if chunk.embedding is None:
                continue
            try:
                stored = decode(chunk.embedding, dimensions=self.embedder.dimensions)
            except VectorFormatError:
                # One malformed row must not take down the explanation of a
                # vulnerability. It is logged and skipped; the builder is what
                # fixes it.
                logger.warning("knowledge_chunk_unreadable", extra={"chunk_id": chunk.id})
                continue
            scored.append(
                RetrievedPassage(
                    chunk=chunk,
                    score=similarity(vector, stored),
                    matched_by=self._match_reason(chunk, finding),
                )
            )
        scored.sort(key=lambda passage: passage.score, reverse=True)
        return scored

    def _top_up(
        self,
        vector: list[float],
        finding: Finding,
        wanted: int,
        already: list[KnowledgeChunk],
    ) -> list[RetrievedPassage]:
        exclude = {chunk.id for chunk in already}
        scored = self._rank(self.knowledge.iter_embedded(exclude_ids=exclude), vector, finding)
        threshold = self.settings.KNOWLEDGE_MIN_SIMILARITY
        return [passage for passage in scored if passage.score >= threshold][:wanted]

    @staticmethod
    def _match_reason(chunk: KnowledgeChunk, finding: Finding) -> str:
        """Why this passage was considered — most specific reason first.

        A passage written for this exact rule is more precisely about the
        finding than one tagged with its CWE, which is in turn more precise
        than one sharing its OWASP category. The reader is shown this, so
        targeted advice is distinguishable from a category-level match.
        """
        if chunk.rule_id and chunk.rule_id == finding.rule_id:
            return "rule"
        if chunk.cwe_id and chunk.cwe_id == finding.cwe_id:
            return "cwe"
        if chunk.owasp_category and chunk.owasp_category == owasp_code(finding.owasp_category):
            return "owasp"
        return "semantic"


__all__ = [
    "FindingNotFoundError",
    "KnowledgeBaseNotBuiltError",
    "KnowledgeService",
    "KnowledgeStatus",
    "RetrievedPassage",
    "language_for",
    "query_text",
]
