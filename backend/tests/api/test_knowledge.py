"""Retrieving the reference material behind a finding.

The claim under test is not "the model is good" — that is checked by
``scripts/check_retrieval.py`` against the real model and a real knowledge base.
The claim here is that the machinery around it behaves: that the filter runs
before the ranking, that a passage from the wrong weakness cannot outrank one
from the right weakness just by scoring well, that ownership is enforced, and
that an unusable knowledge base says so instead of returning an empty list.

That last one matters most. "No passages" and "nobody built the knowledge base"
look identical to a UI, and only one of them is a statement about the code.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.knowledge.builder import KnowledgeBuilder
from app.knowledge.chunking import Section, SourceDocument
from app.knowledge.sources import notes
from app.models import (
    Confidence,
    Finding,
    KnowledgeSource,
    Repository,
    RepositorySource,
    RepositoryStatus,
    Severity,
)

pytestmark = pytest.mark.integration

PROJECTS = "/api/v1/projects"
PASSWORD = "a-long-enough-passphrase"


def sign_up(client: TestClient, name: str) -> str:
    client.post(
        "/api/v1/auth/register",
        json={"email": f"{name}@example.com", "username": name, "password": PASSWORD},
    )
    response = client.post("/api/v1/auth/login", json={"identifier": name, "password": PASSWORD})
    return response.json()["access_token"]


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def make_repository(client: TestClient, db: Session, token: str) -> Repository:
    """A repository row without running ingestion — these tests are about
    retrieval, and a real zip upload would only add a slower way to get an id."""
    project_id = client.post(PROJECTS, json={"name": "kb"}, headers=auth(token)).json()["id"]
    repository = Repository(
        project_id=project_id,
        source=RepositorySource.UPLOAD,
        status=RepositoryStatus.READY,
        origin="kb.zip",
        workspace_path=f"project-{project_id}/repo-kb",
        file_count=1,
        total_bytes=10,
    )
    db.add(repository)
    db.flush()
    return repository


def make_finding(db: Session, repository_id: int, **overrides) -> Finding:  # noqa: ANN003
    defaults = {
        "rule_id": "JV003",
        "analyzer": "pattern",
        "title": "Weak hash algorithm (MD5 or SHA-1)",
        "message": "MD5 and SHA-1 are collision-broken and must not prove integrity.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe_id": "CWE-327",
        "owasp_category": "A02:2021 Cryptographic Failures",
        "file_path": "srv/Report.java",
        "line_start": 4,
        "line_end": 4,
        "snippet": 'MessageDigest.getInstance("MD5")',
        "fingerprint": f"fp-{repository_id}-{overrides.get('rule_id', 'JV003')}",
    }
    finding = Finding(repository_id=repository_id, **{**defaults, **overrides})
    db.add(finding)
    db.flush()
    return finding


def cwe_document(cwe_id: str, title: str, text: str) -> SourceDocument:
    return SourceDocument(
        source=KnowledgeSource.CWE,
        external_id=cwe_id,
        title=f"{cwe_id}: {title}",
        sections=[Section(name="Mitigations", text=text)],
        url=f"https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[1]}.html",
        source_version="4.99",
        cwe_id=cwe_id,
    )


CORPUS = [
    cwe_document(
        "CWE-327",
        "Use of a Broken or Risky Cryptographic Algorithm",
        "Use a strong hash such as SHA-256; MD5 and SHA-1 are collision-broken.",
    ),
    cwe_document(
        "CWE-89",
        "SQL Injection",
        "Use prepared statements with bound parameters rather than concatenation.",
    ),
    cwe_document(
        "CWE-79",
        "Cross-site Scripting",
        "Encode output for the context it is rendered into, and sanitise HTML.",
    ),
]


def build_knowledge(db: Session, embedder, documents=None) -> None:  # noqa: ANN001
    KnowledgeBuilder(db, embedder, max_chunk_chars=1200).build(documents or CORPUS)


# --- status ---------------------------------------------------------------


def test_status_reports_an_empty_knowledge_base(api_client: TestClient) -> None:
    token = sign_up(api_client, "kbstatus")
    body = api_client.get("/api/v1/knowledge/status", headers=auth(token)).json()
    assert body["built"] is False
    assert body["embedded_chunks"] == 0


def test_status_reports_what_was_indexed(
    api_client: TestClient, db_session: Session, stub_embedder
) -> None:  # noqa: ANN001
    build_knowledge(db_session, stub_embedder)
    token = sign_up(api_client, "kbstatus2")
    body = api_client.get("/api/v1/knowledge/status", headers=auth(token)).json()

    assert body["built"] is True
    assert body["documents"] == 3
    assert body["by_source"] == {"CWE": 3}
    assert body["embedding_models"] == [stub_embedder.model_id]
    assert body["source_versions"] == {"CWE": "4.99"}
    assert body["built_at"] is not None


def test_status_requires_authentication(api_client: TestClient) -> None:
    assert api_client.get("/api/v1/knowledge/status").status_code == 401


# --- retrieval ------------------------------------------------------------


def test_a_finding_retrieves_the_material_for_its_own_cwe(
    api_client: TestClient, db_session: Session, stub_embedder
) -> None:  # noqa: ANN001
    token = sign_up(api_client, "kbread")
    repository = make_repository(api_client, db_session, token)
    finding = make_finding(db_session, repository.id)
    build_knowledge(db_session, stub_embedder)

    response = api_client.get(f"/api/v1/findings/{finding.id}/knowledge", headers=auth(token))
    assert response.status_code == 200
    body = response.json()

    assert body["finding_id"] == finding.id
    assert body["cwe_id"] == "CWE-327"
    assert [passage["external_id"] for passage in body["passages"]] == ["CWE-327"]
    assert body["passages"][0]["matched_by"] == "cwe"
    assert body["passages"][0]["source"] == "CWE"


def test_the_identifier_filter_runs_before_the_ranking(
    api_client: TestClient, db_session: Session, stub_embedder
) -> None:  # noqa: ANN001
    """A passage about a different weakness must not be returned ahead of the
    right one merely because it shares vocabulary. The CWE is a fact the
    analyser recorded; the vector is a guess, and the fact wins.
    """
    token = sign_up(api_client, "kbfilter")
    repository = make_repository(api_client, db_session, token)
    finding = make_finding(db_session, repository.id)
    # A decoy whose text is deliberately closer to the query than the correct
    # entry, but which belongs to another CWE.
    decoy = cwe_document(
        "CWE-1004",
        "Decoy",
        "Weak hash algorithm MD5 SHA-1 Java MessageDigest collision broken integrity",
    )
    build_knowledge(db_session, stub_embedder, [*CORPUS, decoy])

    passages = api_client.get(
        f"/api/v1/findings/{finding.id}/knowledge", headers=auth(token)
    ).json()["passages"]

    by_id = {passage["external_id"]: passage for passage in passages}
    # The decoy is the better *semantic* match — and it still comes second,
    # because it was not in the filtered set.
    assert passages[0]["external_id"] == "CWE-327"
    assert by_id["CWE-1004"]["score"] > by_id["CWE-327"]["score"]
    assert by_id["CWE-1004"]["matched_by"] == "semantic"


def test_a_rule_note_outranks_catalogue_text_for_the_same_finding(
    api_client: TestClient, db_session: Session, stub_embedder
) -> None:  # noqa: ANN001
    """Our note names the actual call to change; the catalogue entry is written
    to cover every language at once."""
    token = sign_up(api_client, "kbnote")
    repository = make_repository(api_client, db_session, token)
    finding = make_finding(db_session, repository.id)
    build_knowledge(db_session, stub_embedder, [*CORPUS, *notes.build_documents()])

    body = api_client.get(f"/api/v1/findings/{finding.id}/knowledge", headers=auth(token)).json()
    reasons = [passage["matched_by"] for passage in body["passages"]]
    assert "rule" in reasons
    assert any(
        passage["source"] == "SENTINELFORGE" and passage["external_id"] == "JV003"
        for passage in body["passages"]
    )


def test_passages_are_ordered_by_specificity_then_score(
    api_client: TestClient, db_session: Session, stub_embedder
) -> None:  # noqa: ANN001
    """Specificity first, similarity second — and descending within each tier.

    Pure score order was the first contract and it was wrong. On the real model
    it put JavaScript advice above the Java note for a Java finding, by three
    hundredths of a point: small embedding models read a passage's topic well
    and its qualifiers poorly. Which rule a finding came from is not an estimate.
    """
    token = sign_up(api_client, "kborder")
    repository = make_repository(api_client, db_session, token)
    finding = make_finding(db_session, repository.id)
    build_knowledge(db_session, stub_embedder, [*CORPUS, *notes.build_documents()])

    passages = api_client.get(
        f"/api/v1/findings/{finding.id}/knowledge", headers=auth(token)
    ).json()["passages"]

    priority = {"rule": 0, "cwe": 1, "owasp": 2, "semantic": 3}
    keys = [(priority[passage["matched_by"]], -passage["score"]) for passage in passages]
    assert keys == sorted(keys)


def test_another_languages_note_is_never_shown_for_this_finding(
    api_client: TestClient, db_session: Session, stub_embedder
) -> None:  # noqa: ANN001
    """JV003 and JS005 are the same weakness in two languages, so they share a
    CWE. Handing a Java developer "use crypto.createHash" is worse than handing
    them nothing — and the catalogue already carries the language-neutral form.
    """
    token = sign_up(api_client, "kblang")
    repository = make_repository(api_client, db_session, token)
    finding = make_finding(db_session, repository.id)  # JV003, Java, CWE-327
    build_knowledge(db_session, stub_embedder, [*CORPUS, *notes.build_documents()])

    passages = api_client.get(
        f"/api/v1/findings/{finding.id}/knowledge", headers=auth(token)
    ).json()["passages"]

    ours = [p for p in passages if p["source"] == "SENTINELFORGE"]
    assert ours, "the rule's own note should still be retrieved"
    assert {p["external_id"] for p in ours} == {"JV003"}
    # JS005 and PY007 are also CWE-327 and must not appear.
    assert not [p for p in passages if p["external_id"] in {"JS005", "PY007"}]


def test_the_answer_always_contains_something_about_fixing_it(
    api_client: TestClient, db_session: Session, stub_embedder
) -> None:  # noqa: ANN001
    """The query describes a problem, so it embeds closest to descriptions of
    that problem. Left to similarity alone the first real run returned three
    restatements of what the developer was already looking at.

    Here the rule note is withheld and every catalogue section except the
    mitigation one is made to look like the query, so similarity alone would
    fill every slot with prose about the problem.
    """
    token = sign_up(api_client, "kbfix")
    repository = make_repository(api_client, db_session, token)
    finding = make_finding(db_session, repository.id)
    problem_shaped = SourceDocument(
        source=KnowledgeSource.CWE,
        external_id="CWE-327",
        title="CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
        sections=[
            Section(name="Description", text="Weak hash algorithm MD5 SHA-1 collision broken Java"),
            Section(
                name="Consequences", text="Weak hash algorithm MD5 SHA-1 collision broken Java"
            ),
            Section(
                name="Applicable platforms",
                text="Weak hash algorithm MD5 SHA-1 collision broken Java",
            ),
            Section(name="Mitigations", text="Prefer SHA-256 from a maintained library."),
        ],
        cwe_id="CWE-327",
    )
    build_knowledge(db_session, stub_embedder, [problem_shaped])

    passages = api_client.get(
        f"/api/v1/findings/{finding.id}/knowledge", headers=auth(token)
    ).json()["passages"]

    assert any(passage["section"] == "Mitigations" for passage in passages)


def test_the_reserved_slot_costs_at_most_one_position(
    api_client: TestClient, db_session: Session, stub_embedder, monkeypatch
) -> None:  # noqa: ANN001
    """The guarantee displaces the weakest selected passage, not the best one.
    A reservation that reordered the whole list would be the model's job taken
    away rather than constrained."""
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "KNOWLEDGE_RETRIEVAL_LIMIT", 2)
    token = sign_up(api_client, "kbslot")
    repository = make_repository(api_client, db_session, token)
    finding = make_finding(db_session, repository.id)
    document = SourceDocument(
        source=KnowledgeSource.CWE,
        external_id="CWE-327",
        title="CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
        sections=[
            Section(name="Description", text="Weak hash algorithm MD5 SHA-1 collision broken Java"),
            Section(name="Consequences", text="Weak hash algorithm MD5 SHA-1 broken"),
            Section(name="Mitigations", text="Prefer SHA-256 from a maintained library."),
        ],
        cwe_id="CWE-327",
    )
    build_knowledge(db_session, stub_embedder, [document])

    passages = api_client.get(
        f"/api/v1/findings/{finding.id}/knowledge", headers=auth(token)
    ).json()["passages"]

    assert [passage["section"] for passage in passages] == ["Description", "Mitigations"]


def test_the_owasp_category_is_a_filter_dimension_too(
    api_client: TestClient, db_session: Session, stub_embedder
) -> None:  # noqa: ANN001
    """Without it, OWASP material would be reachable only through the
    unrestricted fallback — which almost never runs — and would in practice
    never be retrieved at all."""
    token = sign_up(api_client, "kbowasp")
    repository = make_repository(api_client, db_session, token)
    finding = make_finding(db_session, repository.id)
    owasp_document = SourceDocument(
        source=KnowledgeSource.OWASP,
        external_id="A02:2021",
        title="A02:2021 – Cryptographic Failures",
        sections=[
            Section(name="How to Prevent", text="Use strong, current cryptographic algorithms.")
        ],
        url="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        source_version="2021",
        owasp_category="A02:2021",
    )
    build_knowledge(db_session, stub_embedder, [*CORPUS, owasp_document])

    body = api_client.get(f"/api/v1/findings/{finding.id}/knowledge", headers=auth(token)).json()
    assert any(passage["matched_by"] == "owasp" for passage in body["passages"])


def test_a_finding_with_no_identifiers_falls_back_to_similarity(
    api_client: TestClient, db_session: Session, stub_embedder
) -> None:  # noqa: ANN001
    """Not every rule maps to a CWE. Such a finding must still be explainable."""
    token = sign_up(api_client, "kbfallback")
    repository = make_repository(api_client, db_session, token)
    finding = make_finding(
        db_session,
        repository.id,
        rule_id="XX999",
        cwe_id=None,
        owasp_category=None,
        title="SQL query built by concatenation",
        message="Use prepared statements with bound parameters rather than concatenation.",
    )
    build_knowledge(db_session, stub_embedder)

    body = api_client.get(f"/api/v1/findings/{finding.id}/knowledge", headers=auth(token)).json()
    assert {passage["matched_by"] for passage in body["passages"]} == {"semantic"}
    assert body["passages"][0]["external_id"] == "CWE-89"


def test_the_fallback_refuses_passages_below_the_similarity_floor(
    api_client: TestClient, db_session: Session, stub_embedder, monkeypatch
) -> None:  # noqa: ANN001
    """A passage returned only because it was the least-bad match is noise with
    a citation attached."""
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "KNOWLEDGE_MIN_SIMILARITY", 0.99)
    token = sign_up(api_client, "kbfloor")
    repository = make_repository(api_client, db_session, token)
    finding = make_finding(
        db_session, repository.id, rule_id="XX999", cwe_id=None, owasp_category=None
    )
    build_knowledge(db_session, stub_embedder)

    body = api_client.get(f"/api/v1/findings/{finding.id}/knowledge", headers=auth(token)).json()
    assert body["passages"] == []


def test_the_query_is_returned_so_a_result_can_be_reproduced(
    api_client: TestClient, db_session: Session, stub_embedder
) -> None:  # noqa: ANN001
    token = sign_up(api_client, "kbquery")
    repository = make_repository(api_client, db_session, token)
    finding = make_finding(db_session, repository.id)
    build_knowledge(db_session, stub_embedder)

    body = api_client.get(f"/api/v1/findings/{finding.id}/knowledge", headers=auth(token)).json()
    assert "CWE-327" in body["query"]
    assert "in Java" in body["query"]
    # The snippet is metadata the query must never carry.
    assert "MessageDigest" not in body["query"]


# --- failure states -------------------------------------------------------


def test_an_unbuilt_knowledge_base_says_so_rather_than_returning_nothing(
    api_client: TestClient, db_session: Session
) -> None:
    """An empty list reads as "there is nothing to say about this
    vulnerability", which is a lie about the vulnerability."""
    token = sign_up(api_client, "kbempty")
    repository = make_repository(api_client, db_session, token)
    finding = make_finding(db_session, repository.id)

    response = api_client.get(f"/api/v1/findings/{finding.id}/knowledge", headers=auth(token))
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "KNOWLEDGE_BASE_NOT_BUILT"
    assert "build_knowledge" in response.json()["error"]["message"]


def test_a_knowledge_base_built_by_another_model_is_refused(
    api_client: TestClient, db_session: Session, stub_embedder
) -> None:  # noqa: ANN001
    """The dot products would still be numbers. Every one of them would be
    meaningless, and nothing on the page would look wrong."""
    from tests.helpers import HashingEmbedder

    build_knowledge(db_session, HashingEmbedder(model_id="some-other-model"))
    token = sign_up(api_client, "kbmodel")
    repository = make_repository(api_client, db_session, token)
    finding = make_finding(db_session, repository.id)

    response = api_client.get(f"/api/v1/findings/{finding.id}/knowledge", headers=auth(token))
    assert response.status_code == 503
    assert "Rebuild it" in response.json()["error"]["message"]


def test_a_knowledge_base_with_two_models_is_refused(
    api_client: TestClient, db_session: Session, stub_embedder
) -> None:  # noqa: ANN001
    from tests.helpers import HashingEmbedder

    build_knowledge(db_session, stub_embedder, CORPUS[:1])
    build_knowledge(db_session, HashingEmbedder(model_id="second-model"), CORPUS[1:])
    token = sign_up(api_client, "kbmixed")
    repository = make_repository(api_client, db_session, token)
    finding = make_finding(db_session, repository.id)

    response = api_client.get(f"/api/v1/findings/{finding.id}/knowledge", headers=auth(token))
    assert response.status_code == 503
    assert "more than one embedding model" in response.json()["error"]["message"]


def test_one_unreadable_vector_does_not_break_the_explanation(
    api_client: TestClient, db_session: Session, stub_embedder
) -> None:  # noqa: ANN001
    """A corrupt row is a builder problem. Losing the whole explanation of a
    vulnerability over it would be a worse one."""
    from sqlalchemy import select

    from app.models import KnowledgeChunk

    build_knowledge(db_session, stub_embedder, [*CORPUS, *notes.build_documents()])
    broken = db_session.scalars(
        select(KnowledgeChunk).where(KnowledgeChunk.cwe_id == "CWE-327")
    ).first()
    broken.embedding = b"\x00\x00\x00"  # not a whole number of float32 values
    db_session.flush()

    token = sign_up(api_client, "kbbroken")
    repository = make_repository(api_client, db_session, token)
    finding = make_finding(db_session, repository.id)

    response = api_client.get(f"/api/v1/findings/{finding.id}/knowledge", headers=auth(token))
    assert response.status_code == 200
    returned = {passage["id"] for passage in response.json()["passages"]}
    assert broken.id not in returned
    assert returned


# --- ownership ------------------------------------------------------------


def test_another_users_finding_is_not_explainable(
    api_client: TestClient, db_session: Session, stub_embedder
) -> None:  # noqa: ANN001
    """404, not 403: a 403 would confirm the finding id exists."""
    owner = sign_up(api_client, "kbowner")
    repository = make_repository(api_client, db_session, owner)
    finding = make_finding(db_session, repository.id)
    build_knowledge(db_session, stub_embedder)

    intruder = sign_up(api_client, "kbintruder")
    response = api_client.get(f"/api/v1/findings/{finding.id}/knowledge", headers=auth(intruder))
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "FINDING_NOT_FOUND"


def test_knowledge_for_a_finding_requires_authentication(
    api_client: TestClient, db_session: Session
) -> None:
    token = sign_up(api_client, "kbanon")
    repository = make_repository(api_client, db_session, token)
    finding = make_finding(db_session, repository.id)
    assert api_client.get(f"/api/v1/findings/{finding.id}/knowledge").status_code == 401


def test_a_finding_that_does_not_exist_is_a_404(api_client: TestClient) -> None:
    token = sign_up(api_client, "kbmissing")
    response = api_client.get("/api/v1/findings/999999/knowledge", headers=auth(token))
    assert response.status_code == 404
