"""Building the knowledge base: incremental, idempotent, and honest when it fails.

A build that re-embedded everything every time would take minutes, so nobody
would re-run it, so the knowledge base would go stale. A build that skipped too
much would leave passages that no longer match their text, or vectors from a
model that is no longer configured. Both failures are quiet. These tests are
what make them loud.
"""

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.knowledge.builder import KnowledgeBuilder
from app.knowledge.chunking import Section, SourceDocument
from app.knowledge.vectors import decode
from app.models import KnowledgeChunk, KnowledgeDocument, KnowledgeSource

pytestmark = pytest.mark.integration


def document(text: str = "Use prepared statements with bound parameters.") -> SourceDocument:
    return SourceDocument(
        source=KnowledgeSource.CWE,
        external_id="CWE-89",
        title="CWE-89: SQL Injection",
        sections=[Section(name="Mitigations", text=text)],
        url="https://cwe.mitre.org/data/definitions/89.html",
        source_version="4.99",
        cwe_id="CWE-89",
    )


def builder(db_session: Session, embedder) -> KnowledgeBuilder:  # noqa: ANN001
    return KnowledgeBuilder(db_session, embedder, max_chunk_chars=1200)


def test_a_document_is_stored_with_its_passages_and_vectors(
    db_session: Session, stub_embedder
) -> None:  # noqa: ANN001
    report = builder(db_session, stub_embedder).build([document()])

    assert report.documents_written == 1
    assert report.chunks_written == 1

    row = db_session.scalars(select(KnowledgeDocument)).one()
    assert row.external_id == "CWE-89"
    assert row.source_version == "4.99"
    assert row.content_hash

    chunk = db_session.scalars(select(KnowledgeChunk)).one()
    assert chunk.cwe_id == "CWE-89"
    assert chunk.embedding_model == stub_embedder.model_id
    assert chunk.embedding_dimensions == stub_embedder.dimensions
    decoded = decode(chunk.embedding, dimensions=stub_embedder.dimensions)
    assert len(decoded) == stub_embedder.dimensions


def test_rebuilding_unchanged_documents_embeds_nothing(db_session: Session, stub_embedder) -> None:  # noqa: ANN001
    """The whole reason the build is affordable to re-run."""
    builder(db_session, stub_embedder).build([document()])
    report = builder(db_session, stub_embedder).build([document()])

    assert report.documents_written == 0
    assert report.documents_unchanged == 1


def test_changed_text_is_re_embedded(db_session: Session, stub_embedder) -> None:  # noqa: ANN001
    builder(db_session, stub_embedder).build([document("Old advice.")])
    report = builder(db_session, stub_embedder).build([document("New advice entirely.")])

    assert report.documents_written == 1
    chunk = db_session.scalars(select(KnowledgeChunk)).one()
    assert "New advice entirely." in chunk.text


def test_a_changed_model_re_embeds_even_though_the_text_is_identical(
    db_session: Session, stub_embedder
) -> None:  # noqa: ANN001
    """Vectors from two models cannot be compared. Skipping on the text hash
    alone would leave a knowledge base whose scores mean nothing, and nothing
    would say so."""
    from tests.helpers import HashingEmbedder

    builder(db_session, stub_embedder).build([document()])
    other = HashingEmbedder(dimensions=32, model_id="test-hashing-v2")
    report = builder(db_session, other).build([document()])

    assert report.documents_written == 1
    chunk = db_session.scalars(select(KnowledgeChunk)).one()
    assert chunk.embedding_model == "test-hashing-v2"
    assert chunk.embedding_dimensions == 32


def test_force_re_embeds_an_unchanged_document(db_session: Session, stub_embedder) -> None:  # noqa: ANN001
    builder(db_session, stub_embedder).build([document()])
    report = builder(db_session, stub_embedder).build([document()], force=True)
    assert report.documents_written == 1


def test_passages_are_replaced_not_appended(db_session: Session, stub_embedder) -> None:  # noqa: ANN001
    """A section can disappear between catalogue editions. Matching old passages
    to new ones would leave the removed one in place, still retrievable, still
    citing an edition that no longer says it."""
    long_text = " ".join(f"Sentence {index} of advice." for index in range(200))
    builder(db_session, stub_embedder).build([document(long_text)])
    first = db_session.scalar(select(KnowledgeDocument)).id
    many = db_session.scalars(select(KnowledgeChunk)).all()
    assert len(many) > 1

    builder(db_session, stub_embedder).build([document("Short now.")])
    remaining = db_session.scalars(
        select(KnowledgeChunk).where(KnowledgeChunk.document_id == first)
    ).all()
    assert len(remaining) == 1
    assert "Short now." in remaining[0].text


def test_a_document_is_updated_in_place_rather_than_duplicated(
    db_session: Session, stub_embedder
) -> None:  # noqa: ANN001
    builder(db_session, stub_embedder).build([document("One.")])
    builder(db_session, stub_embedder).build([document("Two.")])
    assert len(db_session.scalars(select(KnowledgeDocument)).all()) == 1


def test_metadata_is_refreshed_without_re_embedding(db_session: Session, stub_embedder) -> None:  # noqa: ANN001
    """A corrected title or a moved URL costs nothing and invalidates no vector."""
    builder(db_session, stub_embedder).build([document()])
    moved = SourceDocument(
        source=KnowledgeSource.CWE,
        external_id="CWE-89",
        title="CWE-89: SQL Injection",
        sections=[
            Section(name="Mitigations", text="Use prepared statements with bound parameters.")
        ],
        url="https://example.invalid/moved",
        source_version="5.00",
        cwe_id="CWE-89",
    )
    report = builder(db_session, stub_embedder).build([moved])

    assert report.documents_written == 0
    row = db_session.scalars(select(KnowledgeDocument)).one()
    assert row.url == "https://example.invalid/moved"
    assert row.source_version == "5.00"


def test_a_failed_embedding_leaves_the_document_marked_for_rebuild(
    db_session: Session, stub_embedder
) -> None:  # noqa: ANN001
    """The hash is written only after the passages are stored.

    Writing it first would mark a document current on the strength of vectors
    that were never saved, and every later build would skip it.
    """

    class Failing:
        model_id = "test-hashing-v1"
        dimensions = 64

        def embed_documents(self, texts):  # noqa: ANN001, ANN202
            raise RuntimeError("model exploded")

        def embed_query(self, text):  # noqa: ANN001, ANN202
            raise RuntimeError("model exploded")

    # Build once so there is a stored hash to compare against.
    builder(db_session, stub_embedder).build([document("Original advice.")])
    original_hash = db_session.scalars(select(KnowledgeDocument)).one().content_hash

    # Now fail part way through re-embedding it. No rollback here on purpose:
    # the question is what the builder *wrote* before it raised, and a rollback
    # would hide a hash it had already set.
    with pytest.raises(RuntimeError, match="model exploded"):
        builder(db_session, Failing()).build([document("Replacement advice.")])

    row = db_session.scalars(select(KnowledgeDocument)).one()
    assert row.content_hash == original_hash

    db_session.rollback()
    report = builder(db_session, stub_embedder).build([document("Replacement advice.")])
    assert report.documents_written == 1


def test_deleting_a_document_takes_its_passages_with_it(db_session: Session, stub_embedder) -> None:  # noqa: ANN001
    """ON DELETE CASCADE in the database, not just in the ORM.

    Deleting through the session would pass either way — SQLAlchemy's own
    cascade would tidy up in Python. This deletes with a Core statement, which
    is what a migration, a psql session or a future bulk delete would do, so it
    is the *database* constraint being asserted. Without it, PostgreSQL refuses
    the delete and the passages would otherwise outlive the document they cite.
    """
    from sqlalchemy import delete

    builder(db_session, stub_embedder).build([document()])
    row = db_session.scalars(select(KnowledgeDocument)).one()

    db_session.execute(delete(KnowledgeDocument).where(KnowledgeDocument.id == row.id))
    db_session.flush()
    db_session.expire_all()
    assert db_session.scalars(select(KnowledgeChunk)).all() == []
