"""Reading the three knowledge sources.

The XML fixtures here are written by hand, not copied from MITRE: they are
*inputs* designed to exercise a parser, including the malicious ones a real
catalogue would never contain. The real catalogue is parsed for real by
``scripts/build_knowledge.py``, and the counts it reports are what proves the
parser works on the genuine file.

The security tests in this file matter more than the parsing ones. This project
ships a rule (PY015) that flags XML parsers which resolve entities; a knowledge
builder that parsed a hostile catalogue would be the project failing its own
audit.
"""

import io
import struct
import zipfile

import pytest

from app.analysis.rules import ALL_RULES
from app.knowledge.rule_notes import NOTES_BY_RULE
from app.knowledge.sources import cwe, notes, owasp
from app.models import KnowledgeSource

CATALOGUE = """<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" Name="CWE" Version="4.99">
  <Weaknesses>
    <Weakness ID="89" Name="SQL Injection" Abstraction="Base" Status="Stable">
      <Description>The product builds a command using external input.</Description>
      <Extended_Description>
        <xhtml:p xmlns:xhtml="http://www.w3.org/1999/xhtml">Without neutralisation the
        structure of the query can be altered.</xhtml:p>
      </Extended_Description>
      <Applicable_Platforms>
        <Language Class="Not Language-Specific" Prevalence="Undetermined"/>
      </Applicable_Platforms>
      <Common_Consequences>
        <Consequence>
          <Scope>Confidentiality</Scope>
          <Impact>Read Application Data</Impact>
          <Note>An attacker can read data they are not entitled to.</Note>
        </Consequence>
      </Common_Consequences>
      <Potential_Mitigations>
        <Mitigation>
          <Phase>Implementation</Phase>
          <Strategy>Parameterization</Strategy>
          <Description>Use prepared statements with bound parameters.</Description>
        </Mitigation>
      </Potential_Mitigations>
    </Weakness>
    <Weakness ID="4242" Name="Retired Thing" Abstraction="Base" Status="Deprecated">
      <Description>This entry has been deprecated.</Description>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>
"""

# Same catalogue, older namespace. A parser that matched the URI literally would
# find nothing here and build an empty knowledge base without complaining.
OLD_NAMESPACE = CATALOGUE.replace("cwe-7", "cwe-6")

BILLION_LAUGHS = """<?xml version="1.0"?>
<!DOCTYPE Weakness_Catalog [
  <!ENTITY a "aaaaaaaaaa">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
]>
<Weakness_Catalog Version="4.99"><Weaknesses>
  <Weakness ID="1" Name="&b;"><Description>&b;</Description></Weakness>
</Weaknesses></Weakness_Catalog>
"""

EXTERNAL_ENTITY = """<?xml version="1.0"?>
<!DOCTYPE Weakness_Catalog [ <!ENTITY secret SYSTEM "file:///etc/passwd"> ]>
<Weakness_Catalog Version="4.99"><Weaknesses>
  <Weakness ID="1" Name="x"><Description>&secret;</Description></Weakness>
</Weaknesses></Weakness_Catalog>
"""

OWASP_MARKDOWN = """# A03:2021 – Injection

## Factors

| CWEs Mapped | Max Incidence Rate |
|---|---|
| 33 | 19.09% |

## Overview

Injection slides down to the third position.

## Description

An application is vulnerable when user-supplied data is not validated.

## How to Prevent

Use a safe API which avoids the use of the interpreter entirely, or provides a
parameterized interface.

## Example Attack Scenarios

Scenario #1: An application uses untrusted data in a SQL call.

## References

-   [OWASP Proactive Controls](https://example.invalid)

## List of Mapped CWEs

CWE-20 Improper Input Validation
"""


def zip_with(name: str, content: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, content)
    return buffer.getvalue()


# --- CWE ------------------------------------------------------------------


def test_a_weakness_becomes_a_document_with_separate_sections() -> None:
    version, documents = cwe.parse_catalogue(CATALOGUE.encode())
    assert version == "4.99"
    assert len(documents) == 1
    document = documents[0]
    assert document.external_id == "CWE-89"
    assert document.cwe_id == "CWE-89"
    assert document.source is KnowledgeSource.CWE
    assert document.url == "https://cwe.mitre.org/data/definitions/89.html"
    assert [section.name for section in document.sections] == [
        "Description",
        "Applicable platforms",
        "Consequences",
        "Mitigations",
    ]


def test_nested_xhtml_inside_a_description_is_not_lost() -> None:
    """Reading ``element.text`` alone would stop at the first child tag and drop
    most of an extended description."""
    _, documents = cwe.parse_catalogue(CATALOGUE.encode())
    description = documents[0].sections[0].text
    assert "structure of the query can be altered" in description


def test_mitigation_phase_and_strategy_are_kept_with_the_text() -> None:
    _, documents = cwe.parse_catalogue(CATALOGUE.encode())
    mitigations = next(s for s in documents[0].sections if s.name == "Mitigations")
    assert "Implementation — Parameterization" in mitigations.text
    assert "prepared statements" in mitigations.text


def test_deprecated_weaknesses_are_skipped() -> None:
    """Their text is a redirect notice, useful to nobody searching for advice."""
    _, documents = cwe.parse_catalogue(CATALOGUE.encode())
    assert [document.external_id for document in documents] == ["CWE-89"]


def test_an_older_namespace_still_parses() -> None:
    """The catalogue's namespace changed from cwe-6 to cwe-7. Matching the URI
    literally would silently yield nothing after the next such change."""
    _, documents = cwe.parse_catalogue(OLD_NAMESPACE.encode())
    assert [document.external_id for document in documents] == ["CWE-89"]


def test_an_empty_catalogue_is_an_error_not_an_empty_knowledge_base() -> None:
    """Silently indexing nothing is the worst outcome: every later query answers
    "no information", which reads as a verdict about the code."""
    empty = b'<?xml version="1.0"?><Weakness_Catalog Version="1"><Weaknesses/></Weakness_Catalog>'
    with pytest.raises(cwe.CweSourceError, match="No weaknesses"):
        cwe.parse_catalogue(empty)


def test_an_entity_expansion_bomb_is_refused() -> None:
    """The billion-laughs attack. Refusing the DOCTYPE removes the whole class
    rather than trying to bound the expansion."""
    with pytest.raises(cwe.CweSourceError, match="DOCTYPE"):
        cwe.parse_catalogue(BILLION_LAUGHS.encode())


def test_an_external_entity_reference_is_refused() -> None:
    """Otherwise a tampered catalogue could make the builder read a local file
    or call an internal URL — the XXE this project's own PY015 rule flags."""
    with pytest.raises(cwe.CweSourceError, match="DOCTYPE"):
        cwe.parse_catalogue(EXTERNAL_ENTITY.encode())


def test_malformed_xml_is_reported_clearly(tmp_path) -> None:  # noqa: ANN001
    with pytest.raises(cwe.CweSourceError, match="not valid XML"):
        cwe.parse_catalogue(b"<Weakness_Catalog><Weaknesses>")


def test_a_catalogue_declaring_more_than_the_size_limit_is_refused(tmp_path, monkeypatch) -> None:  # noqa: ANN001
    """The zip header is a claim about size, and this is the cheap check of it."""
    path = tmp_path / "cwec_test.xml.zip"
    path.write_bytes(zip_with("cwec.xml", CATALOGUE))
    monkeypatch.setattr(cwe, "MAX_CATALOGUE_BYTES", 10)
    with pytest.raises(cwe.CweSourceError, match="over the"):
        cwe.read_catalogue_bytes(path)


def test_an_archive_with_several_xml_files_is_refused(tmp_path) -> None:  # noqa: ANN001
    """Which one is the catalogue? Guessing would mean indexing whichever file
    sorted first, which is not a decision a builder should make silently."""
    path = tmp_path / "cwec_test.xml.zip"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("a.xml", CATALOGUE)
        archive.writestr("b.xml", CATALOGUE)
    path.write_bytes(buffer.getvalue())
    with pytest.raises(cwe.CweSourceError, match="expected one"):
        cwe.read_catalogue_bytes(path)


def test_a_file_that_is_not_a_zip_is_reported_as_such(tmp_path) -> None:  # noqa: ANN001
    path = tmp_path / "cwec_test.xml.zip"
    path.write_bytes(b"this is not a zip")
    with pytest.raises(cwe.CweSourceError, match="corrupt or has been tampered"):
        cwe.read_catalogue_bytes(path)


def test_an_archive_whose_header_lies_about_its_size_is_refused(tmp_path) -> None:  # noqa: ANN001
    """A tampered catalogue, and the reason no byte counter is needed here.

    ``zipfile`` stops a member read at its *declared* uncompressed size and then
    checks the CRC, so a header claiming a member is smaller than it is produces
    a short read and a checksum failure — never an over-long one. The declared
    size is therefore the only bound needed, and this is the test that says so.
    """
    payload = b"A" * 200_000
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("cwec.xml", payload)
    raw = bytearray(buffer.getvalue())
    struct.pack_into("<I", raw, 22, 100)  # local header: uncompressed size
    central = raw.rfind(b"PK\x01\x02")
    struct.pack_into("<I", raw, central + 24, 100)  # central directory: the same

    path = tmp_path / "cwec_test.xml.zip"
    path.write_bytes(bytes(raw))
    with pytest.raises(cwe.CweSourceError, match="corrupt or has been tampered"):
        cwe.read_catalogue_bytes(path)


def test_a_missing_catalogue_names_the_download(tmp_path) -> None:  # noqa: ANN001
    with pytest.raises(cwe.CweSourceError, match="cwe.mitre.org"):
        cwe.build_documents(tmp_path)


def test_build_documents_reads_the_zip_end_to_end(tmp_path) -> None:  # noqa: ANN001
    (tmp_path / "cwec_v4.99.xml.zip").write_bytes(zip_with("cwec_v4.99.xml", CATALOGUE))
    version, documents = cwe.build_documents(tmp_path)
    assert version == "4.99"
    assert documents[0].external_id == "CWE-89"


# --- OWASP ----------------------------------------------------------------


def test_owasp_document_is_split_by_its_headings() -> None:
    document = owasp.parse_document(OWASP_MARKDOWN, fallback_title="A03_2021-Injection")
    assert document is not None
    assert document.external_id == "A03:2021"
    assert document.owasp_category == "A03:2021"
    assert "How to Prevent" in [section.name for section in document.sections]


def test_reference_and_mapping_sections_are_dropped() -> None:
    """Link lists and CWE tables embed to nothing useful and crowd out guidance."""
    document = owasp.parse_document(OWASP_MARKDOWN, fallback_title="x")
    names = [section.name for section in document.sections]
    assert "References" not in names
    assert "List of Mapped CWEs" not in names


def test_owasp_code_normalises_every_spelling() -> None:
    """OWASP writes an en dash, our rule catalogue writes a space, and A3 and
    A03 are the same category. A filter that depended on the spelling would
    break the day someone reformatted a string."""
    assert owasp.owasp_code("A03:2021 – Injection") == "A03:2021"
    assert owasp.owasp_code("A03:2021 Injection") == "A03:2021"
    assert owasp.owasp_code("A3:2021") == "A03:2021"
    assert owasp.owasp_code("not a category") is None
    assert owasp.owasp_code(None) is None


def test_a_document_with_no_category_code_is_skipped() -> None:
    assert owasp.parse_document("# Introduction\n\nSome text.", fallback_title="intro") is None


def test_an_empty_owasp_directory_is_an_error(tmp_path) -> None:  # noqa: ANN001
    with pytest.raises(owasp.OwaspSourceError):
        owasp.build_documents(tmp_path)


def test_build_documents_reads_the_markdown_directory(tmp_path) -> None:  # noqa: ANN001
    (tmp_path / "A03_2021-Injection.md").write_text(OWASP_MARKDOWN, encoding="utf-8")
    documents = owasp.build_documents(tmp_path)
    assert [document.external_id for document in documents] == ["A03:2021"]
    assert documents[0].source_version == "2021"


# --- our own notes --------------------------------------------------------


def test_every_analyser_rule_has_a_remediation_note() -> None:
    """A rule with no note is a finding the explanation layer cannot answer."""
    missing = sorted(rule.id for rule in ALL_RULES if rule.id not in NOTES_BY_RULE)
    assert missing == []


def test_no_note_refers_to_a_rule_that_does_not_exist() -> None:
    known = {rule.id for rule in ALL_RULES}
    assert sorted(rule_id for rule_id in NOTES_BY_RULE if rule_id not in known) == []


def test_notes_inherit_the_cwe_from_the_rule_catalogue() -> None:
    """Repeating the mapping here would let the two drift apart, and a note
    tagged with the wrong CWE is retrieved for the wrong findings."""
    documents = {document.rule_id: document for document in notes.build_documents()}
    assert documents["JV003"].cwe_id == "CWE-327"
    assert documents["JV003"].owasp_category == "A02:2021"
    assert documents["PY010"].cwe_id == "CWE-89"


def test_notes_are_attributed_to_this_project_not_a_standards_body() -> None:
    documents = notes.build_documents()
    assert {document.source for document in documents} == {KnowledgeSource.SENTINELFORGE}


def test_each_note_has_both_a_risk_and_a_fix() -> None:
    """A note explaining the danger without saying what to write instead is
    exactly the advice this phase exists to stop producing."""
    for document in notes.build_documents():
        assert [section.name for section in document.sections] == ["Risk", "Fix"], document.rule_id


def test_only_the_ten_categories_are_indexed() -> None:
    """OWASP publishes A00 ("How to start an AppSec program") and A11 ("Next
    Steps") in the same directory, numbered like categories. They are real
    documents and useful ones — and no finding should ever retrieve "how to
    start an AppSec program" as the explanation of a weak hash."""
    assert owasp.owasp_code("A01:2021 – Broken Access Control") == "A01:2021"
    assert owasp.owasp_code("A10:2021 – Server-Side Request Forgery") == "A10:2021"
    assert owasp.owasp_code("A00:2021 – How to start an AppSec program") is None
    assert owasp.owasp_code("A11:2021 – Next Steps") is None


def test_a_non_category_document_is_skipped_entirely(tmp_path) -> None:  # noqa: ANN001
    (tmp_path / "A11_2021-Next_Steps.md").write_text(
        "# A11:2021 – Next Steps\n\n## Overview\n\nWhat to do after the Top 10.\n",
        encoding="utf-8",
    )
    (tmp_path / "A03_2021-Injection.md").write_text(OWASP_MARKDOWN, encoding="utf-8")
    documents = owasp.build_documents(tmp_path)
    assert [document.external_id for document in documents] == ["A03:2021"]
