"""What question gets asked of the model.

Small file, one important test: the code snippet never reaches the query. A
snippet can contain a credential, and a credential has no business being turned
into a vector, logged as a query, or echoed back through the API.
"""

from app.models import Confidence, Finding, Severity
from app.services.knowledge_service import language_for, query_text

SECRET = "sup3r" + "-s3cret-database-value"


def finding(**overrides) -> Finding:  # noqa: ANN003
    defaults = {
        "rule_id": "JV003",
        "analyzer": "pattern",
        "title": "Weak hash algorithm (MD5 or SHA-1)",
        "message": "MD5 and SHA-1 are collision-broken.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe_id": "CWE-327",
        "owasp_category": "A02:2021 Cryptographic Failures",
        "file_path": "srv/Report.java",
        "line_start": 4,
        "line_end": 4,
        "snippet": f'password = "{SECRET}"',
        "fingerprint": "f",
        "repository_id": 1,
    }
    return Finding(**{**defaults, **overrides})


def test_the_query_never_contains_the_code_snippet() -> None:
    assert SECRET not in query_text(finding())


def test_the_query_carries_the_rule_the_cwe_and_the_language() -> None:
    """ "How do I fix weak hashing" and "...in Java" retrieve different passages,
    and the second is the question the developer is actually asking."""
    text = query_text(finding())
    assert "Weak hash algorithm" in text
    assert "CWE-327" in text
    assert "in Java" in text


def test_an_unknown_file_extension_simply_omits_the_language() -> None:
    assert "in " not in query_text(finding(file_path="notes.unknownext"))


def test_language_is_read_from_the_extension() -> None:
    assert language_for("app/main.py") == "Python"
    assert language_for("web/App.TSX") == "TypeScript"
    assert language_for("srv/Report.java") == "Java"
    assert language_for("Makefile") is None


def test_a_finding_without_a_cwe_still_produces_a_query() -> None:
    """Not every rule maps to a CWE, and a finding with none must still be
    explainable rather than raising."""
    text = query_text(finding(cwe_id=None, owasp_category=None))
    assert "Weak hash algorithm" in text
