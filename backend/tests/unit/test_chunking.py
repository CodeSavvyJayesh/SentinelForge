"""Splitting documents into passages.

Two claims are being defended here. First, that a passage carries its own
subject — "Use parameterised queries" is useless as a standalone vector.
Second, that the content hash changes when, and only when, the embedded text
changes, because that is what makes a rebuild incremental rather than a lie.
"""

from app.knowledge.chunking import (
    Section,
    SourceDocument,
    chunk_document,
    collapse,
    non_empty_sections,
    split_text,
)
from app.models import KnowledgeSource


def document(*sections: tuple[str, str]) -> SourceDocument:
    return SourceDocument(
        source=KnowledgeSource.CWE,
        external_id="CWE-89",
        title="CWE-89: SQL Injection",
        sections=[Section(name=name, text=text) for name, text in sections],
    )


def test_collapse_removes_indentation_but_keeps_paragraphs() -> None:
    text = "  one    two  \n   three\n\n\n   second   paragraph  "
    assert collapse(text) == "one two three\n\nsecond paragraph"


def test_sections_become_separate_chunks() -> None:
    """The whole reason for chunking: one vector per idea, not one per document."""
    chunks = chunk_document(
        document(("Description", "a" * 50), ("Mitigations", "b" * 50)), max_chars=1200
    )
    assert [chunk.section for chunk in chunks] == ["Description", "Mitigations"]
    assert [chunk.ordinal for chunk in chunks] == [0, 1]


def test_every_chunk_carries_the_document_title() -> None:
    chunks = chunk_document(document(("Mitigations", "Use parameterised queries.")), max_chars=1200)
    assert chunks[0].text.startswith("CWE-89: SQL Injection — Mitigations\n")


def test_a_long_section_is_split_on_sentence_boundaries() -> None:
    sentences = " ".join(f"Sentence number {index} explains something." for index in range(60))
    pieces = split_text(sentences, 200)
    assert len(pieces) > 1
    assert all(len(piece) <= 200 for piece in pieces)
    # Nothing was dropped and nothing was cut mid-word.
    assert " ".join(pieces).split() == sentences.split()


def test_paragraphs_are_packed_rather_than_emitted_one_by_one() -> None:
    """Two short paragraphs belong in one passage; alone, neither has context."""
    text = "First paragraph here.\n\nSecond paragraph here."
    assert split_text(text, 1000) == ["First paragraph here.\n\nSecond paragraph here."]


def test_a_single_word_longer_than_the_limit_is_cut_rather_than_dropped() -> None:
    pieces = split_text("x" * 250, 100)
    assert [len(piece) for piece in pieces] == [100, 100, 50]


def test_sections_are_never_merged_with_each_other() -> None:
    """Merging would put two subjects in one vector — the averaging problem
    chunking exists to avoid — even when both are short."""
    chunks = chunk_document(
        document(("Description", "Short."), ("Mitigations", "Also short.")), max_chars=4000
    )
    assert len(chunks) == 2


def test_empty_sections_are_dropped() -> None:
    """An empty section still embeds, and matches everything weakly."""
    sections = non_empty_sections(
        [("Description", "Real text."), ("Extended", "   "), ("Notes", None)]
    )
    assert [section.name for section in sections] == ["Description"]


def test_content_hash_changes_when_the_text_changes() -> None:
    before = document(("Description", "One.")).content_hash
    after = document(("Description", "Two.")).content_hash
    assert before != after


def test_content_hash_changes_when_a_section_is_renamed() -> None:
    """Section names are prefixed into the embedded text, so they are part of
    what the vector encodes."""
    described = document(("Description", "One.")).content_hash
    summarised = document(("Summary", "One.")).content_hash
    assert described != summarised


def test_content_hash_ignores_the_url() -> None:
    """A moved link does not change what a passage means, and re-embedding the
    whole catalogue because MITRE reorganised its site would be waste."""
    base = document(("Description", "One."))
    moved = SourceDocument(
        source=base.source,
        external_id=base.external_id,
        title=base.title,
        sections=base.sections,
        url="https://example.invalid/moved",
    )
    assert base.content_hash == moved.content_hash


def test_section_boundaries_cannot_be_forged_by_the_text() -> None:
    """Concatenating name and text without a separator would let a document
    whose section is called "AB" and text "C" hash the same as one called "A"
    with text "BC"."""
    first = document(("AB", "C")).content_hash
    second = document(("A", "BC")).content_hash
    assert first != second
