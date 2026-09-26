"""Turning a source document into passages worth embedding.

An embedding is one vector for the whole input, which means it is an *average*
of everything in it. Embed a CWE entry whole and you get a point midway between
"what this weakness is", "what it leads to" and "how to prevent it" — close to
all three questions and a good answer to none. Split it by section and each
vector is about one thing, so a query about fixing the weakness lands on the
mitigation text.

So the unit here is the **section**, not a fixed number of characters. Length is
only a backstop: a section longer than the configured maximum is split on
paragraph boundaries, and a paragraph longer than the maximum is split on
sentence boundaries, so a passage never ends mid-word. Sections are never merged
with each other — that would recreate the averaging problem chunking exists to
avoid.
"""

import hashlib
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from app.models import KnowledgeSource

# A blank line is a paragraph break; whitespace either side of it is ignored.
PARAGRAPH_BREAK = re.compile(r"\n\s*\n")
# A sentence ends at ., ! or ? followed by whitespace and a capital or a digit.
# Deliberately crude: it only has to find a readable place to cut an unusually
# long paragraph, not to be right about every abbreviation.
SENTENCE_BREAK = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9])")


@dataclass(frozen=True)
class Section:
    name: str
    text: str


@dataclass(frozen=True)
class SourceDocument:
    """One thing a source says, before it reaches the database."""

    source: KnowledgeSource
    external_id: str
    title: str
    sections: Sequence[Section]
    url: str | None = None
    source_version: str | None = None
    cwe_id: str | None = None
    owasp_category: str | None = None
    rule_id: str | None = None

    @property
    def content_hash(self) -> str:
        """Fingerprint of everything that would change the embeddings.

        The builder compares this against the stored hash and re-embeds only
        what moved, which turns "the CWE catalogue was updated" from a full
        rebuild into a few dozen documents.

        Title and section names are included because they are part of the text
        that gets embedded. The URL is not: a changed link does not change what
        a passage means.
        """
        digest = hashlib.sha256()
        digest.update(self.title.encode("utf-8"))
        for section in self.sections:
            digest.update(b"\x1e")  # record separator: keeps boundaries unambiguous
            digest.update(section.name.encode("utf-8"))
            digest.update(b"\x1f")
            digest.update(section.text.encode("utf-8"))
        return digest.hexdigest()


@dataclass
class Chunk:
    ordinal: int
    section: str
    text: str
    embedding: list[float] | None = field(default=None)


def collapse(text: str) -> str:
    """Normalise whitespace while keeping paragraph breaks.

    XML and Markdown both arrive full of indentation that carries no meaning;
    left in, it becomes part of what the model sees.
    """
    paragraphs = [" ".join(part.split()) for part in PARAGRAPH_BREAK.split(text)]
    return "\n\n".join(paragraph for paragraph in paragraphs if paragraph)


def split_text(text: str, max_chars: int) -> list[str]:
    """Break text into pieces no longer than ``max_chars``, on natural boundaries.

    Paragraphs are packed together up to the limit rather than emitted one per
    passage: a two-line paragraph on its own is too little context to be useful,
    and the sentences around it are what make it make sense.
    """
    cleaned = collapse(text)
    if not cleaned:
        return []

    pieces: list[str] = []
    current = ""
    for paragraph in cleaned.split("\n\n"):
        for part in _fit(paragraph, max_chars):
            if not current:
                current = part
            elif len(current) + 2 + len(part) <= max_chars:
                current = f"{current}\n\n{part}"
            else:
                pieces.append(current)
                current = part
    if current:
        pieces.append(current)
    return pieces


def _fit(paragraph: str, max_chars: int) -> list[str]:
    """Cut one over-long paragraph into pieces that fit."""
    if len(paragraph) <= max_chars:
        return [paragraph]

    pieces: list[str] = []
    current = ""
    for sentence in SENTENCE_BREAK.split(paragraph):
        for part in _hard_wrap(sentence, max_chars):
            if not current:
                current = part
            elif len(current) + 1 + len(part) <= max_chars:
                current = f"{current} {part}"
            else:
                pieces.append(current)
                current = part
    if current:
        pieces.append(current)
    return pieces


def _hard_wrap(sentence: str, max_chars: int) -> list[str]:
    """Last resort for text with no sentence breaks — wrap on spaces.

    Reached by things like a long list rendered as one line. Cutting on a space
    keeps words intact; cutting mid-word would put a fragment into the vector.
    """
    if len(sentence) <= max_chars:
        return [sentence]
    pieces: list[str] = []
    current = ""
    for word in sentence.split(" "):
        candidate = f"{current} {word}".strip()
        if len(candidate) <= max_chars:
            current = candidate
            continue
        if current:
            pieces.append(current)
        # A single word longer than the limit (a URL, a base64 blob) is cut.
        while len(word) > max_chars:
            pieces.append(word[:max_chars])
            word = word[max_chars:]
        current = word
    if current:
        pieces.append(current)
    return pieces


def chunk_document(document: SourceDocument, *, max_chars: int) -> list[Chunk]:
    """Split a document into ordered, numbered passages.

    The title is prefixed to every passage. On its own, "Use parameterised
    queries" does not say what it is about, and its vector would sit next to
    every other piece of generic advice; with "CWE-89: SQL Injection —
    Mitigations" in front of it, the passage carries its own subject.
    """
    chunks: list[Chunk] = []
    for section in document.sections:
        for text in split_text(section.text, max_chars):
            heading = f"{document.title} — {section.name}"
            chunks.append(
                Chunk(ordinal=len(chunks), section=section.name, text=f"{heading}\n{text}")
            )
    return chunks


def non_empty_sections(pairs: Iterable[tuple[str, str | None]]) -> list[Section]:
    """Build a section list, dropping the ones a source left blank.

    Half the CWE catalogue has no Extended Description. An empty section would
    still be embedded, and would match every query weakly — noise with a
    citation attached.
    """
    sections: list[Section] = []
    for name, text in pairs:
        cleaned = collapse(text or "")
        if cleaned:
            sections.append(Section(name=name, text=cleaned))
    return sections


__all__ = [
    "Chunk",
    "Section",
    "SourceDocument",
    "chunk_document",
    "collapse",
    "non_empty_sections",
    "split_text",
]
