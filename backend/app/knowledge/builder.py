"""Building the knowledge base: documents in, embedded passages out.

The builder is **idempotent and incremental**, which matters more than it
sounds. Embedding the CWE catalogue takes a couple of minutes on a laptop CPU;
if every run cost that, nobody would re-run it, and a knowledge base that is
never refreshed slowly stops describing the code it is asked about.

So each document carries a hash of its own text, and a rebuild re-embeds a
document only when that hash changed — or when the *model* changed, because
vectors from two different models cannot be compared even if the words are
identical.

Everything is written in one transaction per batch of documents rather than one
for the whole run. A build interrupted half way leaves a partial knowledge base,
which is honest: retrieval reports how many passages are embedded, and running
the builder again finishes the job instead of starting over.
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.knowledge.chunking import SourceDocument, chunk_document
from app.knowledge.embedder import Embedder
from app.knowledge.vectors import encode
from app.models import KnowledgeChunk, KnowledgeDocument
from app.repositories.knowledge_repository import KnowledgeRepository

logger = get_logger("sentinelforge.knowledge")

# How many passages are handed to the model at once. Large enough that the
# per-call overhead disappears, small enough that a batch's vectors and text fit
# comfortably in memory alongside the catalogue.
EMBED_BATCH = 64
# How many documents are written before committing. A crash costs at most this
# much work, and the rows already committed stay usable.
COMMIT_EVERY = 50


@dataclass
class BuildReport:
    documents_seen: int = 0
    documents_written: int = 0
    documents_unchanged: int = 0
    chunks_written: int = 0
    by_source: dict[str, int] = field(default_factory=dict)

    def summary(self) -> str:
        sources = ", ".join(f"{name} {count}" for name, count in sorted(self.by_source.items()))
        return (
            f"{self.documents_written} documents written "
            f"({self.documents_unchanged} unchanged), "
            f"{self.chunks_written} passages embedded [{sources}]"
        )


class KnowledgeBuilder:
    def __init__(
        self,
        db: Session,
        embedder: Embedder,
        *,
        max_chunk_chars: int,
        batch_size: int = EMBED_BATCH,
    ) -> None:
        self.db = db
        self.embedder = embedder
        self.max_chunk_chars = max_chunk_chars
        self.batch_size = batch_size
        self.knowledge = KnowledgeRepository(db)

    def build(
        self,
        documents: Sequence[SourceDocument],
        *,
        force: bool = False,
        progress: Callable[[int, int], None] | None = None,
    ) -> BuildReport:
        report = BuildReport()
        pending: list[tuple[KnowledgeDocument, SourceDocument]] = []

        for index, source_document in enumerate(documents, start=1):
            report.documents_seen += 1
            row = self._upsert(source_document)
            if not force and self._is_current(row, source_document):
                report.documents_unchanged += 1
            else:
                pending.append((row, source_document))

            if len(pending) >= COMMIT_EVERY:
                self._write(pending, report)
                pending.clear()
                self.db.commit()
            if progress is not None:
                progress(index, len(documents))

        if pending:
            self._write(pending, report)
        self.db.commit()

        logger.info(
            "knowledge_base_built",
            extra={
                "documents_written": report.documents_written,
                "documents_unchanged": report.documents_unchanged,
                "chunks_written": report.chunks_written,
                "model": self.embedder.model_id,
            },
        )
        return report

    # -- internals ---------------------------------------------------------

    def _upsert(self, source_document: SourceDocument) -> KnowledgeDocument:
        row = self.knowledge.get_document(source_document.source, source_document.external_id)
        if row is None:
            row = self.knowledge.add_document(
                KnowledgeDocument(
                    source=source_document.source,
                    external_id=source_document.external_id,
                    title=source_document.title,
                    url=source_document.url,
                    source_version=source_document.source_version,
                    cwe_id=source_document.cwe_id,
                    owasp_category=source_document.owasp_category,
                    rule_id=source_document.rule_id,
                    content_hash="",  # set once the chunks are actually written
                )
            )
            return row

        # Metadata is refreshed even when the text is unchanged: a corrected
        # title or a moved URL costs nothing to update and does not invalidate
        # a single vector.
        row.title = source_document.title
        row.url = source_document.url
        row.source_version = source_document.source_version
        row.cwe_id = source_document.cwe_id
        row.owasp_category = source_document.owasp_category
        row.rule_id = source_document.rule_id
        return row

    def _is_current(self, row: KnowledgeDocument, source_document: SourceDocument) -> bool:
        if row.id is None or row.content_hash != source_document.content_hash:
            return False
        return self.knowledge.chunks_not_embedded_by(row.id, self.embedder.model_id) == 0

    def _write(
        self, pending: list[tuple[KnowledgeDocument, SourceDocument]], report: BuildReport
    ) -> None:
        for row, source_document in pending:
            chunks = chunk_document(source_document, max_chars=self.max_chunk_chars)
            self.knowledge.delete_chunks(row.id)

            for start in range(0, len(chunks), self.batch_size):
                batch = chunks[start : start + self.batch_size]
                vectors = self.embedder.embed_documents([chunk.text for chunk in batch])
                if len(vectors) != len(batch):
                    raise RuntimeError(
                        f"The embedder returned {len(vectors)} vectors for {len(batch)} passages."
                    )
                for chunk, vector in zip(batch, vectors, strict=True):
                    self.knowledge.add_chunk(
                        KnowledgeChunk(
                            document_id=row.id,
                            ordinal=chunk.ordinal,
                            section=chunk.section,
                            text=chunk.text,
                            cwe_id=source_document.cwe_id,
                            owasp_category=source_document.owasp_category,
                            rule_id=source_document.rule_id,
                            embedding=encode(vector),
                            embedding_model=self.embedder.model_id,
                            embedding_dimensions=self.embedder.dimensions,
                        )
                    )

            # The hash is written last, and only here. If embedding fails part
            # way through, the document keeps its old hash and the next run
            # redoes it — rather than being marked current on the strength of
            # passages that were never stored.
            row.content_hash = source_document.content_hash
            report.documents_written += 1
            report.chunks_written += len(chunks)
            name = str(source_document.source)
            report.by_source[name] = report.by_source.get(name, 0) + 1
        self.db.flush()


__all__ = ["COMMIT_EVERY", "EMBED_BATCH", "BuildReport", "KnowledgeBuilder"]
