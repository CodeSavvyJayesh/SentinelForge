"""Database queries for the knowledge base.

Unlike every other repository in this project, nothing here is scoped to an
owner — and that is correct. The CWE catalogue is not user data. It is the same
for every account, it contains nothing anybody uploaded, and scoping it to a
user would be security theatre that costs a join.

What *is* scoped is the finding a passage is retrieved for. Ownership is checked
there, in the service, before this file is ever reached.
"""

from collections.abc import Iterator
from datetime import datetime

from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from app.models import KnowledgeChunk, KnowledgeDocument, KnowledgeSource


class KnowledgeRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    # -- documents ---------------------------------------------------------

    def get_document(self, source: KnowledgeSource, external_id: str) -> KnowledgeDocument | None:
        statement = select(KnowledgeDocument).where(
            KnowledgeDocument.source == source,
            KnowledgeDocument.external_id == external_id,
        )
        return self.db.scalars(statement).first()

    def add_document(self, document: KnowledgeDocument) -> KnowledgeDocument:
        self.db.add(document)
        self.db.flush()
        return document

    def delete_chunks(self, document_id: int) -> None:
        """Clear a document's chunks before rewriting them.

        A rebuild replaces a document's passages wholesale rather than trying to
        match them up one by one: the CWE catalogue can gain or lose a section
        between releases, and a partial update would leave passages from the old
        edition mixed in with the new.
        """
        self.db.execute(delete(KnowledgeChunk).where(KnowledgeChunk.document_id == document_id))
        self.db.flush()

    def add_chunk(self, chunk: KnowledgeChunk) -> KnowledgeChunk:
        self.db.add(chunk)
        return chunk

    def chunks_not_embedded_by(self, document_id: int, model_id: str) -> int:
        """How many of a document's passages are missing, or came from another model.

        An unchanged document still has to be re-embedded when the model
        changes, because its old vectors are in a different space. Without this
        check a rebuild after switching models would skip everything — the text
        did not change — and leave a knowledge base whose scores are nonsense.
        """
        statement = (
            select(func.count())
            .select_from(KnowledgeChunk)
            .where(
                KnowledgeChunk.document_id == document_id,
                or_(
                    KnowledgeChunk.embedding.is_(None),
                    KnowledgeChunk.embedding_model.is_distinct_from(model_id),
                ),
            )
        )
        return self.db.scalar(statement) or 0

    # -- retrieval ---------------------------------------------------------

    def candidates_for(
        self, *, cwe_id: str | None, rule_id: str | None, owasp_category: str | None = None
    ) -> list[KnowledgeChunk]:
        """Every embedded passage that is *definitely* about this weakness.

        Matching on identifiers rather than on meaning, because we already know
        the identifiers: the analyser recorded the rule, the CWE and the OWASP
        category when it raised the finding. A vector search would be guessing
        at something the database can answer exactly.

        Returns nothing when no identifier is given — the caller then falls back
        to an unrestricted search rather than being handed the entire corpus by
        accident.
        """
        conditions = []
        if cwe_id:
            conditions.append(KnowledgeChunk.cwe_id == cwe_id)
        if rule_id:
            conditions.append(KnowledgeChunk.rule_id == rule_id)
        if owasp_category:
            conditions.append(KnowledgeChunk.owasp_category == owasp_category)
        if not conditions:
            return []

        statement = select(KnowledgeChunk).where(
            KnowledgeChunk.embedding.is_not(None), or_(*conditions)
        )
        return list(self.db.scalars(statement))

    def iter_embedded(self, *, exclude_ids: set[int] | None = None) -> Iterator[KnowledgeChunk]:
        """Stream the whole embedded corpus, for the unrestricted fallback.

        Streamed rather than listed because each row carries a vector; pulling a
        few thousand of them into memory at once to score them one at a time is
        a cost with no benefit. This path runs only when the identifier filter
        came back short, which for a finding with a known CWE is never.
        """
        statement = select(KnowledgeChunk).where(KnowledgeChunk.embedding.is_not(None))
        if exclude_ids:
            statement = statement.where(KnowledgeChunk.id.not_in(exclude_ids))
        yield from self.db.scalars(statement).yield_per(256)

    # -- status ------------------------------------------------------------

    def document_count(self) -> int:
        return self.db.scalar(select(func.count()).select_from(KnowledgeDocument)) or 0

    def chunk_count(self, *, embedded_only: bool = False) -> int:
        statement = select(func.count()).select_from(KnowledgeChunk)
        if embedded_only:
            statement = statement.where(KnowledgeChunk.embedding.is_not(None))
        return self.db.scalar(statement) or 0

    def counts_by_source(self) -> dict[str, int]:
        statement = select(KnowledgeDocument.source, func.count()).group_by(
            KnowledgeDocument.source
        )
        return {str(source): count for source, count in self.db.execute(statement)}

    def embedding_models(self) -> list[str]:
        """Every model that has written a vector into this knowledge base.

        More than one means the base was built twice with different settings,
        and its scores are no longer comparable. Retrieval checks this.
        """
        statement = (
            select(KnowledgeChunk.embedding_model)
            .where(KnowledgeChunk.embedding_model.is_not(None))
            .distinct()
        )
        return sorted(model for model in self.db.scalars(statement) if model)

    def source_versions(self) -> dict[str, str]:
        statement = (
            select(KnowledgeDocument.source, KnowledgeDocument.source_version)
            .where(KnowledgeDocument.source_version.is_not(None))
            .distinct()
        )
        return {str(source): version for source, version in self.db.execute(statement) if version}

    def built_at(self) -> datetime | None:
        return self.db.scalar(select(func.max(KnowledgeDocument.updated_at)))


__all__ = ["KnowledgeRepository"]
