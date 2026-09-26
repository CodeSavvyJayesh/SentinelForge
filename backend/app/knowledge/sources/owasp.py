"""Reading the OWASP Top 10 (2021) documents.

OWASP publishes the Top 10 as Markdown, one file per category. Each file opens
with a level-one heading naming the category and is then divided by level-two
headings — *Description*, *How to Prevent*, *Example Attack Scenarios* and so on.

The parser keys off the heading structure rather than the heading *names*,
because the names differ between categories and between editions. A parser that
looked for a section literally called "How to Prevent" would quietly return
nothing the year OWASP renamed it, and a knowledge base that silently lost its
remediation guidance is worse than one that never had it.

Code fences are preserved as text: a prevention section whose example is a
parameterised query is more useful with the query in it.
"""

import re
from pathlib import Path

from app.knowledge.chunking import SourceDocument, non_empty_sections
from app.models import KnowledgeSource

# "A03:2021" — the stable part of an OWASP category label, and the only part
# worth matching on. The title after it is punctuated differently in different
# places (an en dash here, a hyphen there, a plain space in our rule catalogue).
OWASP_CODE = re.compile(r"\bA(\d{1,2}):(\d{4})\b")

HEADING_1 = re.compile(r"^#\s+(.+?)\s*$", re.MULTILINE)
HEADING_2 = re.compile(r"^##\s+(.+?)\s*$", re.MULTILINE)
OWASP_URL_TEMPLATE = "https://owasp.org/Top10/{slug}/"
SOURCE_VERSION = "2021"
# Sections that are link lists or mapping tables rather than prose. Their text
# embeds to nothing useful and would crowd out real guidance.
SKIPPED_SECTIONS = {"references", "list of mapped cwes"}


class OwaspSourceError(RuntimeError):
    """The Top 10 documents could not be read."""


def owasp_code(value: str | None) -> str | None:
    """Reduce any spelling of a category to its code, or ``None``.

    ``"A03:2021 Injection"``, ``"A03:2021 – Injection"`` and ``"A3:2021"`` all
    become ``"A03:2021"``. Zero-padding is applied so that A3 and A03 are the
    same category, which they are.
    """
    if not value:
        return None
    match = OWASP_CODE.search(value)
    if not match:
        return None
    return f"A{int(match.group(1)):02d}:{match.group(2)}"


def _slug(title: str) -> str:
    """The URL fragment OWASP uses, derived from the document title."""
    cleaned = re.sub(r"[^A-Za-z0-9]+", "_", title.replace("–", "-")).strip("_")
    return cleaned


def parse_document(text: str, *, fallback_title: str) -> SourceDocument | None:
    """Parse one Top 10 Markdown file."""
    heading = HEADING_1.search(text)
    title = heading.group(1).strip() if heading else fallback_title
    code = owasp_code(title) or owasp_code(fallback_title)
    if code is None:
        return None

    body = text[heading.end() :] if heading else text
    sections: list[tuple[str, str]] = []
    matches = list(HEADING_2.finditer(body))
    if not matches:
        sections.append(("Overview", body))
    else:
        preamble = body[: matches[0].start()].strip()
        if preamble:
            sections.append(("Overview", preamble))
        for index, match in enumerate(matches):
            end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
            name = match.group(1).strip()
            if name.lower() in SKIPPED_SECTIONS:
                continue
            sections.append((name, body[match.end() : end]))

    built = non_empty_sections(sections)
    if not built:
        return None

    return SourceDocument(
        source=KnowledgeSource.OWASP,
        external_id=code,
        title=title,
        sections=built,
        url=OWASP_URL_TEMPLATE.format(slug=_slug(title)),
        source_version=SOURCE_VERSION,
        owasp_category=code,
    )


def build_documents(source_dir: Path) -> list[SourceDocument]:
    """Read every Top 10 Markdown file in ``source_dir``."""
    if not source_dir.is_dir():
        raise OwaspSourceError(
            f"No OWASP directory at {source_dir}. Download the Top 10 Markdown files into it."
        )
    documents: list[SourceDocument] = []
    for path in sorted(source_dir.glob("*.md")):
        document = parse_document(
            path.read_text(encoding="utf-8", errors="replace"), fallback_title=path.stem
        )
        if document is not None:
            documents.append(document)
    if not documents:
        raise OwaspSourceError(
            f"No OWASP Top 10 categories were parsed from {source_dir}. "
            "The files should be the A01…A10 Markdown documents from the OWASP/Top10 repository."
        )
    return documents


__all__ = ["OwaspSourceError", "build_documents", "owasp_code", "parse_document"]
