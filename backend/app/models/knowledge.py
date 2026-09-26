"""The security knowledge base: reference material, and how it is indexed.

Two tables, and the split matters.

A **document** is one thing a source says: a single CWE weakness entry, a single
OWASP Top 10 category, or the remediation note this project wrote for one of its
own rules. It carries the citation — where the text came from, and which version
of the catalogue — because advice about a security weakness that cannot be
traced back to its source is advice nobody should act on.

A **chunk** is a passage of that document small enough to embed and precise
enough to be worth retrieving. "CWE-89" as a single blob would embed its
description, its consequences and its mitigations into one average of all three,
and the average is about nothing. Split into sections, a query about *fixing*
SQL injection retrieves the mitigation passage rather than the history of the
weakness.

Chunks carry ``cwe_id``, ``owasp_category`` and ``rule_id`` copied down from
their document. That is deliberate denormalisation: retrieval filters on those
columns before it ranks anything, because a structured identifier we already
know is more reliable than a similarity score.

``owasp_category`` is stored as the bare code — ``A03:2021`` — on both sides of
the comparison. OWASP's own documents title it with an en dash and the analyser
rules spell it with a space, and a filter that depended on which spelling won
would work until someone reformatted a string.
"""

from enum import StrEnum

from sqlalchemy import (
    Enum,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.base import Base
from app.models.mixins import TimestampMixin


class KnowledgeSource(StrEnum):
    """Who is speaking. Shown to the user with every passage.

    ``SENTINELFORGE`` is this project's own writing, and it is labelled as such
    so it is never mistaken for a standards body's text.
    """

    CWE = "CWE"
    OWASP = "OWASP"
    SENTINELFORGE = "SENTINELFORGE"


class KnowledgeDocument(TimestampMixin, Base):
    __tablename__ = "knowledge_documents"
    __table_args__ = (
        # One document per thing a source says. Re-running the builder updates
        # the row in place rather than growing a second copy of the catalogue.
        UniqueConstraint("source", "external_id", name="uq_knowledge_documents_source_external"),
        Index("ix_knowledge_documents_cwe", "cwe_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[KnowledgeSource] = mapped_column(
        Enum(KnowledgeSource, name="knowledge_source", validate_strings=True), nullable=False
    )
    # "CWE-89", "A03:2021", "PY001" — the identifier in its own source's terms.
    external_id: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    # Where a reader can go and check. Null only for text with no public home.
    url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # Which edition said this: the CWE catalogue version, the OWASP year.
    # Advice ages, and a passage with no version cannot be audited later.
    source_version: Mapped[str | None] = mapped_column(String(64), nullable=True)

    cwe_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # The bare code, "A03:2021" — see the module docstring.
    owasp_category: Mapped[str | None] = mapped_column(String(16), nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # SHA-256 of the text this document was built from. The builder re-embeds a
    # document only when this changes, which turns a rebuild after a catalogue
    # update from "embed everything again" into "embed what actually moved".
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    chunks: Mapped[list["KnowledgeChunk"]] = relationship(
        back_populates="document", cascade="all, delete-orphan", passive_deletes=True
    )

    def __repr__(self) -> str:
        return (
            f"KnowledgeDocument(id={self.id!r}, source={self.source!r}, "
            f"external_id={self.external_id!r})"
        )


class KnowledgeChunk(TimestampMixin, Base):
    __tablename__ = "knowledge_chunks"
    __table_args__ = (
        UniqueConstraint("document_id", "ordinal", name="uq_knowledge_chunks_document_ordinal"),
        # Retrieval filters on these before it ranks anything.
        Index("ix_knowledge_chunks_cwe", "cwe_id"),
        Index("ix_knowledge_chunks_rule", "rule_id"),
        Index("ix_knowledge_chunks_owasp", "owasp_category"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    document_id: Mapped[int] = mapped_column(
        ForeignKey("knowledge_documents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    # "Description", "Mitigations", "Consequences" — shown as the passage's
    # heading, and the reason chunking by section beats chunking by length.
    section: Mapped[str] = mapped_column(String(120), nullable=False)
    text: Mapped[str] = mapped_column(Text, nullable=False)

    # Copied down from the document so a filter never needs the join.
    cwe_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    owasp_category: Mapped[str | None] = mapped_column(String(16), nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # The vector: little-endian float32, normalised to unit length at write
    # time so similarity is a plain dot product. Null means "not embedded yet" —
    # a chunk in that state is stored but cannot be retrieved, which is the
    # correct behaviour for a half-built knowledge base.
    embedding: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # Recorded per chunk, not per deployment: a knowledge base half-embedded by
    # one model and half by another would return scores that cannot be compared,
    # and this is what lets retrieval notice and refuse.
    embedding_model: Mapped[str | None] = mapped_column(String(120), nullable=True)
    embedding_dimensions: Mapped[int | None] = mapped_column(Integer, nullable=True)

    document: Mapped[KnowledgeDocument] = relationship(back_populates="chunks")

    def __repr__(self) -> str:
        return (
            f"KnowledgeChunk(id={self.id!r}, document_id={self.document_id!r}, "
            f"section={self.section!r})"
        )


__all__ = ["KnowledgeChunk", "KnowledgeDocument", "KnowledgeSource"]
