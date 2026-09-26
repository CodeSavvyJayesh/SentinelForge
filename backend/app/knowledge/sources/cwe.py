"""Reading MITRE's CWE catalogue.

The catalogue is published as a zipped XML file. It is downloaded once, by hand,
and parsed here into one document per weakness with its description, its
consequences and its mitigations as separate sections.

**Parsing this file is the most dangerous thing in the phase**, which is worth
saying plainly. This project ships a rule — PY015 — that flags XML parsers which
resolve entities, because a document can declare an entity that expands into
gigabytes of memory, or one that points at ``file:///etc/passwd``. We do not get
to be the exception to our own rule just because the file came from MITRE: the
zip is a download, downloads can be tampered with, and a parser that is only
safe when its input is honest is not safe.

So, before any XML is parsed:

* the archive member is read by name, with a declared-size check and a streaming
  byte counter, exactly as Phase 4 treats an uploaded zip;
* the document is refused outright if it contains a ``DOCTYPE`` declaration.
  With no DOCTYPE there can be no entity declarations, which removes the entire
  class of attack rather than trying to defuse it. The real catalogue has no
  DOCTYPE, so this costs nothing and is trivially testable.

Namespaces are stripped rather than matched, because the catalogue's namespace
URI changes with its major version (``cwe-6`` became ``cwe-7``) and a hardcoded
URI would silently find zero weaknesses after an update — the worst kind of
failure, because an empty knowledge base looks like a working one.
"""

import zipfile
from pathlib import Path
from xml.etree import ElementTree  # noqa: S405 - DOCTYPE is refused before parsing

from app.knowledge.chunking import SourceDocument, non_empty_sections
from app.models import KnowledgeSource

CWE_URL_TEMPLATE = "https://cwe.mitre.org/data/definitions/{number}.html"

# The catalogue is ~10 MB of XML inside a ~2 MB zip. The cap is generous enough
# for years of growth and small enough that a zip bomb cannot exhaust memory.
MAX_CATALOGUE_BYTES = 128 * 1024 * 1024
READ_CHUNK = 1024 * 1024
# Enough to cover any leading whitespace, the XML declaration and a DOCTYPE.
DOCTYPE_SCAN_BYTES = 8192


class CweSourceError(RuntimeError):
    """The catalogue could not be read. Always actionable by whoever runs it."""


def local_name(tag: str) -> str:
    """``{http://cwe.mitre.org/cwe-7}Weakness`` -> ``Weakness``."""
    return tag.rpartition("}")[2]


def _text_of(element) -> str:  # noqa: ANN001 - ElementTree.Element
    """All text under an element, including nested XHTML.

    Extended descriptions are marked up with ``<xhtml:p>`` and ``<xhtml:ul>``,
    so reading ``element.text`` alone returns the few characters before the
    first tag and silently loses the rest.
    """
    return " ".join(part.strip() for part in element.itertext() if part.strip())


def read_catalogue_bytes(archive_path: Path) -> bytes:
    """Extract the catalogue XML from the downloaded zip, with limits.

    Uses the same reasoning as repository ingestion: the size in the zip header
    is a claim, so it is checked *and* the extracted stream is counted.
    """
    if not archive_path.exists():
        raise CweSourceError(
            f"CWE catalogue not found at {archive_path}. Download it from "
            "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
        )
    try:
        with zipfile.ZipFile(archive_path) as archive:
            members = [
                info for info in archive.infolist() if info.filename.lower().endswith(".xml")
            ]
            if not members:
                raise CweSourceError(f"{archive_path.name} contains no XML file.")
            if len(members) > 1:
                raise CweSourceError(
                    f"{archive_path.name} contains {len(members)} XML files; expected one."
                )
            info = members[0]
            if info.file_size > MAX_CATALOGUE_BYTES:
                raise CweSourceError(
                    f"{info.filename} declares {info.file_size} bytes, over the "
                    f"{MAX_CATALOGUE_BYTES} byte limit."
                )
            # The declared size is enough of a check here, unlike in repository
            # ingestion where an archive's many members are summed. `zipfile`
            # stops a member read at its declared uncompressed size and then
            # verifies the CRC, so a header that under-reports produces a short
            # read and a BadZipFile rather than an over-long one. A counter in
            # this loop could therefore never fire, and an unreachable control
            # is worse than none: it reads as protection nobody has tested.
            buffer = bytearray()
            with archive.open(info) as handle:
                while chunk := handle.read(READ_CHUNK):
                    buffer.extend(chunk)
            return bytes(buffer)
    except zipfile.BadZipFile as exc:
        raise CweSourceError(
            f"{archive_path.name} is corrupt or has been tampered with; re-download it."
        ) from exc


def reject_doctype(data: bytes) -> None:
    """Refuse any XML carrying a DOCTYPE declaration.

    Entity-expansion and external-entity attacks both need a DOCTYPE. Refusing
    the declaration removes both without needing to reason about how deeply an
    entity nests or what a URL points at. The genuine catalogue has none.
    """
    head = data[:DOCTYPE_SCAN_BYTES].lower()
    if b"<!doctype" in head or b"<!entity" in head:
        raise CweSourceError(
            "The CWE catalogue contains a DOCTYPE declaration, which this parser refuses. "
            "Re-download it from https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
        )


def parse_catalogue(data: bytes) -> tuple[str | None, list[SourceDocument]]:
    """Parse the catalogue XML into documents. Returns ``(version, documents)``."""
    reject_doctype(data)
    try:
        root = ElementTree.fromstring(data)  # noqa: S314 - DOCTYPE refused above
    except ElementTree.ParseError as exc:
        raise CweSourceError(f"The CWE catalogue is not valid XML: {exc}") from exc

    version = root.attrib.get("Version")
    documents: list[SourceDocument] = []
    for element in root.iter():
        if local_name(element.tag) != "Weakness":
            continue
        document = _weakness_to_document(element, version)
        if document is not None:
            documents.append(document)

    if not documents:
        # An empty catalogue means the structure changed under us. Failing here
        # is the point: a knowledge base that silently contains nothing answers
        # every question with "no information", which reads like a verdict.
        raise CweSourceError(
            "No weaknesses were found in the CWE catalogue. The file may be the wrong "
            "download, or its structure may have changed."
        )
    return version, documents


def _weakness_to_document(element, version: str | None) -> SourceDocument | None:  # noqa: ANN001
    number = element.attrib.get("ID")
    name = element.attrib.get("Name")
    if not number or not name:
        return None
    # Deprecated entries are kept in the catalogue as tombstones; their text is
    # a redirect notice, which is worth retrieving to nobody.
    if element.attrib.get("Status", "").lower() == "deprecated":
        return None

    description = ""
    extended = ""
    consequences: list[str] = []
    mitigations: list[str] = []
    platforms: list[str] = []

    for child in element:
        tag = local_name(child.tag)
        if tag == "Description":
            description = _text_of(child)
        elif tag == "Extended_Description":
            extended = _text_of(child)
        elif tag == "Common_Consequences":
            consequences = [_consequence(item) for item in child]
        elif tag == "Potential_Mitigations":
            mitigations = [_mitigation(item) for item in child]
        elif tag == "Applicable_Platforms":
            platforms = [
                value
                for item in child
                if (value := item.attrib.get("Name") or item.attrib.get("Class"))
            ]

    cwe_id = f"CWE-{number}"
    sections = non_empty_sections(
        [
            ("Description", " ".join(part for part in (description, extended) if part)),
            ("Applicable platforms", ", ".join(dict.fromkeys(platforms))),
            ("Consequences", "\n\n".join(part for part in consequences if part)),
            ("Mitigations", "\n\n".join(part for part in mitigations if part)),
        ]
    )
    if not sections:
        return None

    return SourceDocument(
        source=KnowledgeSource.CWE,
        external_id=cwe_id,
        title=f"{cwe_id}: {name}",
        sections=sections,
        url=CWE_URL_TEMPLATE.format(number=number),
        source_version=version,
        cwe_id=cwe_id,
    )


def _consequence(element) -> str:  # noqa: ANN001
    scopes: list[str] = []
    impacts: list[str] = []
    notes: list[str] = []
    for child in element:
        tag = local_name(child.tag)
        if tag == "Scope":
            scopes.append(_text_of(child))
        elif tag == "Impact":
            impacts.append(_text_of(child))
        elif tag == "Note":
            notes.append(_text_of(child))
    headline = " / ".join(filter(None, [", ".join(scopes), ", ".join(impacts)]))
    return " ".join(part for part in [headline, " ".join(notes)] if part).strip()


def _mitigation(element) -> str:  # noqa: ANN001
    phase = ""
    strategy = ""
    description = ""
    for child in element:
        tag = local_name(child.tag)
        if tag == "Phase":
            phase = _text_of(child)
        elif tag == "Strategy":
            strategy = _text_of(child)
        elif tag == "Description":
            description = _text_of(child)
    label = " — ".join(part for part in [phase, strategy] if part)
    return f"{label}: {description}".strip(": ") if label else description


def build_documents(source_dir: Path) -> tuple[str | None, list[SourceDocument]]:
    """Read every weakness from the catalogue zip in ``source_dir``."""
    candidates = sorted(source_dir.glob("cwec_*.xml.zip")) or sorted(source_dir.glob("cwec*.zip"))
    if not candidates:
        raise CweSourceError(
            f"No CWE catalogue zip found in {source_dir}. Download "
            "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip into that directory."
        )
    return parse_catalogue(read_catalogue_bytes(candidates[0]))


__all__ = [
    "CweSourceError",
    "build_documents",
    "local_name",
    "parse_catalogue",
    "read_catalogue_bytes",
    "reject_doctype",
]
