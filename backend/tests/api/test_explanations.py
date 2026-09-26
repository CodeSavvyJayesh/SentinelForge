"""Explaining a finding with the local model, end to end.

The model is faked; everything else is real — the queue, the worker, the
retrieval, the contract, the ownership joins. What is being tested is the
machinery around a language model, which is the only part of this that a test
*can* meaningfully pin down: what the model says today is not a property of
this codebase.

The tests that matter most are the refusals. A system that explains
vulnerabilities is only trustworthy if it is visibly capable of declining to.
"""

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.knowledge.builder import KnowledgeBuilder
from app.knowledge.chunking import Section, SourceDocument
from app.llm.client import LlmTimeoutError, LlmUnavailableError
from app.models import (
    Confidence,
    Explanation,
    ExplanationStatus,
    Finding,
    KnowledgeChunk,
    KnowledgeSource,
    Repository,
    RepositorySource,
    RepositoryStatus,
    Severity,
)

pytestmark = pytest.mark.integration

PROJECTS = "/api/v1/projects"
PASSWORD = "a-long-enough-passphrase"

CORPUS = [
    SourceDocument(
        source=KnowledgeSource.CWE,
        external_id="CWE-327",
        title="CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
        sections=[
            Section(name="Mitigations", text="Use a strong hash such as SHA-256."),
            Section(name="Description", text="MD5 and SHA-1 are collision-broken."),
        ],
        url="https://cwe.mitre.org/data/definitions/327.html",
        source_version="4.20",
        cwe_id="CWE-327",
    ),
]


def sign_up(client: TestClient, name: str) -> str:
    client.post(
        "/api/v1/auth/register",
        json={"email": f"{name}@example.com", "username": name, "password": PASSWORD},
    )
    return client.post(
        "/api/v1/auth/login", json={"identifier": name, "password": PASSWORD}
    ).json()["access_token"]


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def make_finding(client: TestClient, db: Session, token: str, **overrides) -> Finding:  # noqa: ANN003
    project_id = client.post(PROJECTS, json={"name": "llm"}, headers=auth(token)).json()["id"]
    repository = Repository(
        project_id=project_id,
        source=RepositorySource.UPLOAD,
        status=RepositoryStatus.READY,
        origin="x.zip",
        workspace_path=f"project-{project_id}/repo-x",
        file_count=1,
        total_bytes=10,
    )
    db.add(repository)
    db.flush()
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
        "snippet": 'MessageDigest.getInstance("MD5")',
        "fingerprint": f"fp-{project_id}",
    }
    finding = Finding(repository_id=repository.id, **{**defaults, **overrides})
    db.add(finding)
    db.flush()
    return finding


def build_knowledge(db: Session, embedder) -> None:  # noqa: ANN001
    KnowledgeBuilder(db, embedder, max_chunk_chars=1200).build(CORPUS)


def explain(client: TestClient, token: str, finding_id: int, worker) -> dict:  # noqa: ANN001
    """Request an explanation and run the worker, the way the app does."""
    queued = client.post(f"/api/v1/findings/{finding_id}/explanation", headers=auth(token))
    assert queued.status_code == 202, queued.text
    worker.drain()
    return client.get(f"/api/v1/explanations/{queued.json()['id']}", headers=auth(token)).json()


# --- the happy path -------------------------------------------------------


def test_requesting_an_explanation_returns_immediately_and_queues_it(
    api_client: TestClient, db_session: Session, stub_embedder
) -> None:  # noqa: ANN001
    """202, not 200: the work is accepted, not done. A 7B model on a CPU takes
    tens of seconds, which is not a thing to hold an HTTP connection open for."""
    token = sign_up(api_client, "exqueue")
    finding = make_finding(api_client, db_session, token)
    build_knowledge(db_session, stub_embedder)

    response = api_client.post(f"/api/v1/findings/{finding.id}/explanation", headers=auth(token))

    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "QUEUED"
    assert body["summary"] is None


def test_the_worker_generates_and_stores_the_explanation(
    api_client: TestClient, db_session: Session, stub_embedder, explanation_worker, fake_llm
) -> None:  # noqa: ANN001
    token = sign_up(api_client, "exrun")
    finding = make_finding(api_client, db_session, token)
    build_knowledge(db_session, stub_embedder)

    body = explain(api_client, token, finding.id, explanation_worker)

    assert body["status"] == "COMPLETED"
    assert "MD5" in body["summary"]
    assert body["remediation"]
    assert body["model"] == fake_llm.model
    assert body["prompt_version"] == 1
    assert body["duration_ms"] is not None


def test_the_prompt_contains_the_finding_and_its_retrieved_passages(
    api_client: TestClient, db_session: Session, stub_embedder, explanation_worker, fake_llm
) -> None:  # noqa: ANN001
    """The grounding claim, asserted against what was actually sent."""
    token = sign_up(api_client, "exprompt")
    finding = make_finding(api_client, db_session, token)
    build_knowledge(db_session, stub_embedder)

    explain(api_client, token, finding.id, explanation_worker)

    sent = fake_llm.prompts[0]
    assert "JV003" in sent
    assert 'MessageDigest.getInstance("MD5")' in sent
    assert "[1]" in sent
    assert "SHA-256" in sent  # the retrieved mitigation text
    assert fake_llm.systems[0] is not None


def test_citations_resolve_back_to_real_documents(
    api_client: TestClient, db_session: Session, stub_embedder, explanation_worker
) -> None:  # noqa: ANN001
    """The model produced the integer 1. Everything shown beside it — source,
    title, link — is read from our own knowledge base."""
    token = sign_up(api_client, "excite")
    finding = make_finding(api_client, db_session, token)
    build_knowledge(db_session, stub_embedder)

    body = explain(api_client, token, finding.id, explanation_worker)

    assert body["grounded"] is True
    citation = body["citations"][0]
    assert citation["number"] == 1
    assert citation["source"] == "CWE"
    assert citation["external_id"] == "CWE-327"
    assert citation["url"].startswith("https://cwe.mitre.org/")


def test_a_citation_resolves_to_the_passage_it_actually_names(
    api_client: TestClient, db_session: Session, stub_embedder, explanation_worker, fake_llm
) -> None:  # noqa: ANN001
    """Numbering is shared by three things that each read it separately: the
    prompt, the citation check and this resolution. An off-by-one keeps every
    label on screen and silently attributes the advice to the wrong document —
    the failure mode where a reader clicks through to a page about a different
    weakness and is told it is the source.

    So: two documents, the model cites the second, and the link must be the
    second one's.
    """
    fake_llm.response = json.dumps(
        {
            "summary": "MD5 is weak.",
            "impact": "Collisions are cheap.",
            "remediation": "Use SHA-256.",
            "citations": [2],
        }
    )
    token = sign_up(api_client, "exorder")
    finding = make_finding(api_client, db_session, token)
    build_knowledge(db_session, stub_embedder)

    queued = api_client.post(
        f"/api/v1/findings/{finding.id}/explanation", headers=auth(token)
    ).json()
    explanation_worker.drain()
    body = api_client.get(f"/api/v1/explanations/{queued['id']}", headers=auth(token)).json()

    stored = db_session.get(Explanation, queued["id"])
    assert [citation["number"] for citation in body["citations"]] == [2]
    assert body["citations"][0]["chunk_id"] == stored.passage_chunk_ids[1]

    # The invariant the three readers share, asserted directly: the marker the
    # model saw beside a passage must be the position that resolution uses to
    # find it again. Comparing a citation to a chunk id cannot catch a shift,
    # because both sides would move together; comparing the *prompt text* to
    # the stored order can.
    sent = fake_llm.prompts[-1]
    for position, chunk_id in enumerate(stored.passage_chunk_ids, start=1):
        chunk = db_session.get(KnowledgeChunk, chunk_id)
        assert f"[{position}] {chunk.document.source} {chunk.document.external_id}" in sent


def test_the_latest_explanation_is_readable_from_the_finding(
    api_client: TestClient, db_session: Session, stub_embedder, explanation_worker
) -> None:  # noqa: ANN001
    token = sign_up(api_client, "exlatest")
    finding = make_finding(api_client, db_session, token)
    build_knowledge(db_session, stub_embedder)
    explain(api_client, token, finding.id, explanation_worker)

    body = api_client.get(f"/api/v1/findings/{finding.id}/explanation", headers=auth(token)).json()
    assert body["status"] == "COMPLETED"


def test_a_finding_never_explained_returns_204_not_an_empty_object(
    api_client: TestClient, db_session: Session
) -> None:
    """ "Never asked for" and "asked for and produced nothing" are different
    states, and the UI shows different things for them."""
    token = sign_up(api_client, "exnone")
    finding = make_finding(api_client, db_session, token)

    response = api_client.get(f"/api/v1/findings/{finding.id}/explanation", headers=auth(token))
    assert response.status_code == 204


# --- invented citations, end to end ---------------------------------------


def test_an_invented_citation_is_dropped_and_counted(
    api_client: TestClient, db_session: Session, stub_embedder, explanation_worker, fake_llm
) -> None:  # noqa: ANN001
    """The control that matters. A fabricated source reads exactly like a real
    one; the only thing that can tell them apart is knowing what the model was
    handed."""
    fake_llm.response = json.dumps(
        {
            "summary": "MD5 is weak.",
            "impact": "Collisions are cheap.",
            "remediation": "Use SHA-256.",
            "citations": [1, 42],
        }
    )
    token = sign_up(api_client, "exfake")
    finding = make_finding(api_client, db_session, token)
    build_knowledge(db_session, stub_embedder)

    body = explain(api_client, token, finding.id, explanation_worker)

    assert [citation["number"] for citation in body["citations"]] == [1]
    assert body["dropped_citations"] == 1
    assert body["grounded"] is True


def test_an_explanation_citing_nothing_real_is_stored_but_marked_ungrounded(
    api_client: TestClient, db_session: Session, stub_embedder, explanation_worker, fake_llm
) -> None:  # noqa: ANN001
    fake_llm.response = json.dumps(
        {
            "summary": "MD5 is weak.",
            "impact": "Collisions are cheap.",
            "remediation": "Use SHA-256.",
            "citations": [88],
        }
    )
    token = sign_up(api_client, "exungrounded")
    finding = make_finding(api_client, db_session, token)
    build_knowledge(db_session, stub_embedder)

    body = explain(api_client, token, finding.id, explanation_worker)

    assert body["status"] == "COMPLETED"
    assert body["grounded"] is False
    assert body["dropped_citations"] == 1


def test_a_model_authored_link_never_reaches_the_reader(
    api_client: TestClient, db_session: Session, stub_embedder, explanation_worker, fake_llm
) -> None:  # noqa: ANN001
    fake_llm.response = json.dumps(
        {
            "summary": "MD5 is weak.",
            "impact": "See https://evil.example/advice for details.",
            "remediation": "Use SHA-256.",
            "citations": [1],
        }
    )
    token = sign_up(api_client, "exlink")
    finding = make_finding(api_client, db_session, token)
    build_knowledge(db_session, stub_embedder)

    body = explain(api_client, token, finding.id, explanation_worker)

    assert "evil.example" not in json.dumps(body["impact"])
    assert body["links_removed"] == 1


# --- refusals -------------------------------------------------------------


def test_an_unbuilt_knowledge_base_fails_the_job_rather_than_guessing(
    api_client: TestClient, db_session: Session, explanation_worker
) -> None:
    """The whole claim of this phase is that the explanation rests on indexed
    sources. With none, the honest answer is to stop — not to let the model
    answer from memory and present it identically."""
    token = sign_up(api_client, "exnokb")
    finding = make_finding(api_client, db_session, token)

    body = explain(api_client, token, finding.id, explanation_worker)

    assert body["status"] == "FAILED"
    assert "build_knowledge" in body["error_message"]
    assert body["summary"] is None


def test_a_model_that_is_not_installed_names_the_command_that_fixes_it(
    api_client: TestClient, db_session: Session, stub_embedder, explanation_worker, fake_llm
) -> None:  # noqa: ANN001
    fake_llm.ready_error = LlmUnavailableError(
        "The model 'qwen2.5-coder:7b' is not installed in Ollama (found: none). "
        "Install it with:  ollama pull qwen2.5-coder:7b"
    )
    token = sign_up(api_client, "exnomodel")
    finding = make_finding(api_client, db_session, token)
    build_knowledge(db_session, stub_embedder)

    body = explain(api_client, token, finding.id, explanation_worker)

    assert body["status"] == "FAILED"
    assert "ollama pull" in body["error_message"]


def test_a_timeout_is_reported_rather_than_hanging_the_worker(
    api_client: TestClient, db_session: Session, stub_embedder, explanation_worker, fake_llm
) -> None:  # noqa: ANN001
    fake_llm.error = LlmTimeoutError(180)
    token = sign_up(api_client, "extimeout")
    finding = make_finding(api_client, db_session, token)
    build_knowledge(db_session, stub_embedder)

    body = explain(api_client, token, finding.id, explanation_worker)

    assert body["status"] == "FAILED"
    assert "180 seconds" in body["error_message"]


def test_malformed_output_fails_the_job_instead_of_storing_half_an_answer(
    api_client: TestClient, db_session: Session, stub_embedder, explanation_worker, fake_llm
) -> None:  # noqa: ANN001
    fake_llm.response = "Sure! Here is my analysis of the code."
    token = sign_up(api_client, "exbadjson")
    finding = make_finding(api_client, db_session, token)
    build_knowledge(db_session, stub_embedder)

    body = explain(api_client, token, finding.id, explanation_worker)

    assert body["status"] == "FAILED"
    assert body["summary"] is None
    assert "JSON" in body["error_message"]


def test_a_crash_in_generation_never_leaks_internals(
    api_client: TestClient, db_session: Session, stub_embedder, explanation_worker, fake_llm
) -> None:  # noqa: ANN001
    fake_llm.error = RuntimeError("/home/secret/path blew up at line 42")
    token = sign_up(api_client, "excrash")
    finding = make_finding(api_client, db_session, token)
    build_knowledge(db_session, stub_embedder)

    body = explain(api_client, token, finding.id, explanation_worker)

    assert body["status"] == "FAILED"
    assert "secret" not in body["error_message"]
    assert body["error_message"] == "Generating this explanation failed unexpectedly."


def test_a_failed_generation_leaves_the_finding_untouched(
    api_client: TestClient, db_session: Session, stub_embedder, explanation_worker, fake_llm
) -> None:  # noqa: ANN001
    """The model has no authority over findings, and a failure is where that
    would show up if it did."""
    fake_llm.error = LlmTimeoutError(180)
    token = sign_up(api_client, "exuntouched")
    finding = make_finding(api_client, db_session, token)
    build_knowledge(db_session, stub_embedder)
    before = (finding.severity, finding.status, finding.message)

    explain(api_client, token, finding.id, explanation_worker)
    db_session.refresh(finding)

    assert (finding.severity, finding.status, finding.message) == before


# --- the queue ------------------------------------------------------------


def test_a_second_request_while_one_is_running_is_refused(
    api_client: TestClient, db_session: Session, stub_embedder
) -> None:  # noqa: ANN001
    """A double click otherwise costs a minute of CPU and produces two answers
    with nothing to say which is current."""
    token = sign_up(api_client, "exdouble")
    finding = make_finding(api_client, db_session, token)
    build_knowledge(db_session, stub_embedder)

    api_client.post(f"/api/v1/findings/{finding.id}/explanation", headers=auth(token))
    second = api_client.post(f"/api/v1/findings/{finding.id}/explanation", headers=auth(token))

    assert second.status_code == 409
    assert second.json()["error"]["code"] == "EXPLANATION_ALREADY_RUNNING"


def test_a_finished_finding_can_be_explained_again(
    api_client: TestClient, db_session: Session, stub_embedder, explanation_worker
) -> None:  # noqa: ANN001
    """Re-explaining after a model change is the point of storing the model
    name — the refusal is on concurrency, not on ever asking twice."""
    token = sign_up(api_client, "exagain")
    finding = make_finding(api_client, db_session, token)
    build_knowledge(db_session, stub_embedder)
    explain(api_client, token, finding.id, explanation_worker)

    again = api_client.post(f"/api/v1/findings/{finding.id}/explanation", headers=auth(token))
    assert again.status_code == 202


def test_the_worker_recovers_a_request_left_running_by_a_dead_process(
    api_client: TestClient, db_session: Session, stub_embedder, explanation_worker
) -> None:  # noqa: ANN001
    """Without the sweep, one power cut leaves a row that says RUNNING forever
    and a finding that can never be explained again, because the "already
    running" check keeps refusing."""
    from datetime import UTC, datetime, timedelta

    token = sign_up(api_client, "exstale")
    finding = make_finding(api_client, db_session, token)
    build_knowledge(db_session, stub_embedder)

    stale = Explanation(
        finding_id=finding.id,
        status=ExplanationStatus.RUNNING,
        attempts=1,
        started_at=datetime.now(UTC) - timedelta(hours=2),
    )
    db_session.add(stale)
    db_session.flush()

    assert explanation_worker.recover_stale_explanations() == 1
    db_session.refresh(stale)
    assert stale.status is ExplanationStatus.QUEUED


def test_a_request_retried_too_often_is_given_up_on(
    api_client: TestClient, db_session: Session, stub_embedder, explanation_worker
) -> None:  # noqa: ANN001
    from datetime import UTC, datetime, timedelta

    token = sign_up(api_client, "exgiveup")
    finding = make_finding(api_client, db_session, token)
    build_knowledge(db_session, stub_embedder)

    stuck = Explanation(
        finding_id=finding.id,
        status=ExplanationStatus.RUNNING,
        attempts=99,
        started_at=datetime.now(UTC) - timedelta(hours=2),
    )
    db_session.add(stuck)
    db_session.flush()

    explanation_worker.recover_stale_explanations()
    db_session.refresh(stuck)
    assert stuck.status is ExplanationStatus.FAILED
    assert "giving up" in stuck.error_message


# --- ownership ------------------------------------------------------------


def test_another_users_finding_cannot_be_explained(
    api_client: TestClient, db_session: Session, stub_embedder
) -> None:  # noqa: ANN001
    """404, not 403: a 403 would confirm the finding id exists."""
    owner = sign_up(api_client, "exowner")
    finding = make_finding(api_client, db_session, owner)
    build_knowledge(db_session, stub_embedder)

    intruder = sign_up(api_client, "exintruder")
    response = api_client.post(f"/api/v1/findings/{finding.id}/explanation", headers=auth(intruder))
    assert response.status_code == 404


def test_another_users_explanation_cannot_be_read(
    api_client: TestClient, db_session: Session, stub_embedder, explanation_worker
) -> None:  # noqa: ANN001
    owner = sign_up(api_client, "exowner2")
    finding = make_finding(api_client, db_session, owner)
    build_knowledge(db_session, stub_embedder)
    queued = api_client.post(
        f"/api/v1/findings/{finding.id}/explanation", headers=auth(owner)
    ).json()
    explanation_worker.drain()

    intruder = sign_up(api_client, "exintruder2")
    response = api_client.get(f"/api/v1/explanations/{queued['id']}", headers=auth(intruder))
    assert response.status_code == 404


def test_requesting_an_explanation_requires_authentication(
    api_client: TestClient, db_session: Session
) -> None:
    token = sign_up(api_client, "exanon")
    finding = make_finding(api_client, db_session, token)
    assert api_client.post(f"/api/v1/findings/{finding.id}/explanation").status_code == 401
