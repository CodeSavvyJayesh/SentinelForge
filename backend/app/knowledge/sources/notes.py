"""This project's own remediation notes, as knowledge-base documents.

The only source that needs no download and no parsing — the text is in
``app.knowledge.rule_notes``. It is still indexed the same way as everything
else so that retrieval has one code path, and it is still labelled with its
source so a reader can see at a glance which advice came from MITRE and which
came from us.
"""

from app.analysis.rules import RULES_BY_ID
from app.knowledge.chunking import SourceDocument, non_empty_sections
from app.knowledge.rule_notes import RULE_NOTES
from app.knowledge.sources.owasp import owasp_code
from app.models import KnowledgeSource

# Every rule note needs the CWE its rule maps to, so that a finding's CWE filter
# picks the note up alongside the catalogue text. The mapping is read from the
# rule catalogue rather than repeated here — one source of truth for which CWE a
# rule means, and no way for the two to drift apart.


def build_documents() -> list[SourceDocument]:
    documents: list[SourceDocument] = []
    for note in RULE_NOTES:
        rule = RULES_BY_ID.get(note.rule_id)
        documents.append(
            SourceDocument(
                source=KnowledgeSource.SENTINELFORGE,
                external_id=note.rule_id,
                title=f"{note.rule_id}: {note.title} ({note.language})",
                sections=non_empty_sections(
                    [("Risk", note.risk), ("Fix", note.fix)],
                ),
                url=None,
                source_version=None,
                cwe_id=rule.cwe_id if rule else None,
                owasp_category=owasp_code(rule.owasp_category) if rule else None,
                rule_id=note.rule_id,
            )
        )
    return documents


__all__ = ["build_documents"]
