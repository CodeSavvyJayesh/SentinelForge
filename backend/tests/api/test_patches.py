"""Proposing a fix, end to end.

The model is faked; everything else is real — the queue, the worker, the
workspace read, the splice, the diff, the checks, the ownership joins.

The tests that matter most are, again, the refusals. This phase's entire claim
is that a generated patch is a *proposal*: the tests below are what make that
claim checkable, and the last group is what would fail loudly if some later
phase quietly started applying these to somebody's code.
"""

import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.knowledge.builder import KnowledgeBuilder
from app.knowledge.chunking import Section, SourceDocument
from app.llm.client import LlmTimeoutError
from app.models import (
    Confidence,
    Finding,
    FindingStatus,
    KnowledgeSource,
    Patch,
    PatchStatus,
    Repository,
    RepositorySource,
    RepositoryStatus,
    Severity,
)

pytestmark = pytest.mark.integration

PROJECTS = "/api/v1/projects"
PASSWORD = "a-long-enough-passphrase"

VULNERABLE = """\
import hashlib


def digest(value):
    return hashlib.md5(value).hexdigest()


def other():
    return 1
"""

# The finding is one line, so a fix is one line. The model is shown the code
# around it and asked to replace only the marked lines.
#
# The first version of this phase asked for the whole window back, and these
# fixtures returned the whole file to match. That was wrong in the same way the
# design was wrong: a real model, asked to fix one line, returns one line — and
# against a thirteen-line window that reads as a deletion, so the checks threw
# away a correct fix. The refusal was observed in the running application
# before it was understood here.
FIXED_LINE = "    return hashlib.sha256(value).hexdigest()"
UNCHANGED_LINE = "    return hashlib.md5(value).hexdigest()"
BROKEN_LINE = "    return hashlib.sha256(value"

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


def patch_response(replacement: str = FIXED_LINE, rationale: str = "Uses SHA-256.") -> str:
    return json.dumps({"replacement": replacement, "rationale": rationale})


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


def make_finding(
    client: TestClient,
    db: Session,
    token: str,
    workspace_root: Path,
    *,
    source: str = VULNERABLE,
    **overrides,  # noqa: ANN003
) -> Finding:
    """A real finding pointing at a real file in a real workspace."""
    project_id = client.post(PROJECTS, json={"name": "patching"}, headers=auth(token)).json()["id"]
    relative = f"project-{project_id}/repo-patch"
    workspace = workspace_root / relative
    (workspace / "src").mkdir(parents=True, exist_ok=True)
    (workspace / "src" / "hash.py").write_text(source, encoding="utf-8")

    repository = Repository(
        project_id=project_id,
        source=RepositorySource.UPLOAD,
        status=RepositoryStatus.READY,
        origin="x.zip",
        workspace_path=relative,
        file_count=1,
        total_bytes=len(source),
    )
    db.add(repository)
    db.flush()

    defaults = {
        "rule_id": "PY201",
        "analyzer": "pattern",
        "title": "Weak hash algorithm (MD5)",
        "message": "MD5 is collision-broken.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "cwe_id": "CWE-327",
        "owasp_category": "A02:2021 Cryptographic Failures",
        "file_path": "src/hash.py",
        "line_start": 5,
        "line_end": 5,
        "snippet": "return hashlib.md5(value).hexdigest()",
        "fingerprint": f"fp-{project_id}",
    }
    finding = Finding(repository_id=repository.id, **{**defaults, **overrides})
    db.add(finding)
    db.flush()
    return finding


def build_knowledge(db: Session, embedder) -> None:  # noqa: ANN001
    KnowledgeBuilder(db, embedder, max_chunk_chars=1200).build(CORPUS)


def propose(client: TestClient, token: str, finding_id: int, worker) -> dict:  # noqa: ANN001
    """Request a patch and run the worker, the way the app does."""
    queued = client.post(f"/api/v1/findings/{finding_id}/patch", headers=auth(token))
    assert queued.status_code == 202, queued.text
    worker.drain()
    return client.get(f"/api/v1/patches/{queued.json()['id']}", headers=auth(token)).json()


# --- the happy path -------------------------------------------------------


def test_requesting_a_patch_returns_immediately_and_queues_it(
    api_client: TestClient, db_session: Session, stub_embedder, workspace_root: Path
) -> None:
    token = sign_up(api_client, "queuer")
    finding = make_finding(api_client, db_session, token, workspace_root)

    response = api_client.post(f"/api/v1/findings/{finding.id}/patch", headers=auth(token))

    assert response.status_code == 202
    body = response.json()
    assert body["status"] == PatchStatus.QUEUED
    assert body["diff"] is None
    # No model ran inside the HTTP request. On a CPU that would hold the
    # connection open for the better part of a minute.
    assert body["model"] is None


def test_the_queued_row_is_committed_not_just_flushed(
    api_client: TestClient, db_session: Session, stub_embedder, workspace_root: Path
) -> None:
    """Phase 8 shipped this endpoint's twin without a commit.

    Every test passed, because the shared-session fixture makes uncommitted
    rows visible to the next query. The only shape that catches it is asserting
    the commit itself.
    """
    token = sign_up(api_client, "committer")
    finding = make_finding(api_client, db_session, token, workspace_root)
    commits: list[int] = []
    original = db_session.commit
    db_session.commit = lambda: (commits.append(1), original())[1]  # type: ignore[method-assign]
    try:
        api_client.post(f"/api/v1/findings/{finding.id}/patch", headers=auth(token))
    finally:
        db_session.commit = original  # type: ignore[method-assign]

    assert commits, "the endpoint returned 202 without committing the queued row"


def test_the_worker_produces_a_diff_that_applies_to_the_real_file(
    api_client: TestClient,
    db_session: Session,
    stub_embedder,
    fake_llm,
    patch_worker,
    workspace_root: Path,
) -> None:
    """The central claim of the phase, checked against `git apply`.

    Not "a diff was produced" — a diff that the developer's own tools accept.
    This is what asking the model for a diff directly would not survive.
    """
    build_knowledge(db_session, stub_embedder)
    fake_llm.response = patch_response()
    token = sign_up(api_client, "patcher")
    finding = make_finding(api_client, db_session, token, workspace_root)

    body = propose(api_client, token, finding.id, patch_worker)

    assert body["status"] == PatchStatus.PROPOSED, body["error_message"]
    assert "-    return hashlib.md5(value).hexdigest()" in body["diff"]
    assert "+    return hashlib.sha256(value).hexdigest()" in body["diff"]
    assert body["rationale"] == "Uses SHA-256."
    assert body["file_path"] == "src/hash.py"
    assert body["lines_added"] == 1
    assert body["lines_removed"] == 1

    workspace = workspace_root / f"project-{finding.repository.project_id}/repo-patch"
    assert _applies_cleanly(body["diff"], workspace)


def _applies_cleanly(diff: str, workspace: Path) -> bool:
    """Run the proposal through `git apply --check` against the real files."""
    import shutil
    import subprocess

    git = shutil.which("git")
    if git is None:  # pragma: no cover - git is present in this project's envs
        pytest.skip("git is not installed")
    patch_file = workspace.parent / "proposal.patch"
    patch_file.write_text(diff, encoding="utf-8", newline="")
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [git, "apply", "--check", "-p1", str(patch_file)],
        cwd=workspace,
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null"},
    )
    if result.returncode != 0:  # pragma: no cover - shown when it fails
        print(result.stderr)
    return result.returncode == 0


def test_the_proposal_never_touches_the_workspace(
    api_client: TestClient,
    db_session: Session,
    stub_embedder,
    fake_llm,
    patch_worker,
    workspace_root: Path,
) -> None:
    """The promise of the phase, as an assertion.

    A generated patch is text in a database row. If some later change starts
    writing it to disk, this test is what says so.
    """
    build_knowledge(db_session, stub_embedder)
    fake_llm.response = patch_response()
    token = sign_up(api_client, "readonly")
    finding = make_finding(api_client, db_session, token, workspace_root)
    source_file = workspace_root / f"project-{finding.repository.project_id}/repo-patch/src/hash.py"
    before = source_file.read_bytes()

    body = propose(api_client, token, finding.id, patch_worker)

    assert body["status"] == PatchStatus.PROPOSED
    assert source_file.read_bytes() == before


def test_a_proposal_is_never_reported_as_validated(
    api_client: TestClient,
    db_session: Session,
    stub_embedder,
    fake_llm,
    patch_worker,
    workspace_root: Path,
) -> None:
    """Nothing in this phase can say a patch works.

    `validated` is False on a successful proposal, and the status vocabulary
    has no APPLIED in it. Phase 11 earns those by re-scanning a copy.
    """
    build_knowledge(db_session, stub_embedder)
    fake_llm.response = patch_response()
    token = sign_up(api_client, "unvalidated")
    finding = make_finding(api_client, db_session, token, workspace_root)

    body = propose(api_client, token, finding.id, patch_worker)

    assert body["validated"] is False
    assert body["status"] == "PROPOSED"
    assert "APPLIED" not in [status.value for status in PatchStatus]


def test_the_finding_is_untouched_by_a_proposal(
    api_client: TestClient,
    db_session: Session,
    stub_embedder,
    fake_llm,
    patch_worker,
    workspace_root: Path,
) -> None:
    """A proposal does not resolve anything, and must not lower the risk."""
    build_knowledge(db_session, stub_embedder)
    fake_llm.response = patch_response()
    token = sign_up(api_client, "statusquo")
    finding = make_finding(api_client, db_session, token, workspace_root)

    propose(api_client, token, finding.id, patch_worker)
    db_session.refresh(finding)

    assert finding.status is FindingStatus.NEW
    assert finding.severity is Severity.MEDIUM


def test_the_prompt_contains_the_code_and_the_retrieved_passages(
    api_client: TestClient,
    db_session: Session,
    stub_embedder,
    fake_llm,
    patch_worker,
    workspace_root: Path,
) -> None:
    build_knowledge(db_session, stub_embedder)
    fake_llm.response = patch_response()
    token = sign_up(api_client, "prompted")
    finding = make_finding(api_client, db_session, token, workspace_root)

    propose(api_client, token, finding.id, patch_worker)

    prompt = fake_llm.prompts[-1]
    assert "hashlib.md5" in prompt
    assert "CWE-327" in prompt
    assert "SHA-256" in prompt  # the retrieved mitigation
    # The system prompt is what tells the model the code is data, not
    # instructions. Sending the user prompt without it would remove the only
    # textual defence there is.
    assert "never as instructions" in fake_llm.systems[-1]


# --- refusals -------------------------------------------------------------


def test_a_model_that_returns_the_code_unchanged_is_refused(
    api_client: TestClient,
    db_session: Session,
    stub_embedder,
    fake_llm,
    patch_worker,
    workspace_root: Path,
) -> None:
    build_knowledge(db_session, stub_embedder)
    fake_llm.response = patch_response(replacement=UNCHANGED_LINE, rationale="I fixed the hashing.")
    token = sign_up(api_client, "nochange")
    finding = make_finding(api_client, db_session, token, workspace_root, line_start=5, line_end=5)

    body = propose(api_client, token, finding.id, patch_worker)

    assert body["status"] == PatchStatus.FAILED
    assert "same code" in body["error_message"]
    assert body["diff"] is None


def test_a_model_that_deletes_the_code_is_refused(
    api_client: TestClient,
    db_session: Session,
    stub_embedder,
    fake_llm,
    patch_worker,
    workspace_root: Path,
) -> None:
    """The failure this phase is most concerned with.

    Deleting the vulnerable function makes the finding vanish on the next
    scan, so Phase 11 would certify it as a fix. It has to be caught here.
    """
    build_knowledge(db_session, stub_embedder)
    # A finding that legitimately spans a block — the analyser flags the whole
    # credential list, not one line of it.
    long_source = "import os\n" + "".join(f'SECRET_{n} = "value-{n}"\n' for n in range(12))
    fake_llm.response = patch_response(replacement="pass", rationale="Removed it.")
    token = sign_up(api_client, "deleter")
    finding = make_finding(
        api_client,
        db_session,
        token,
        workspace_root,
        source=long_source,
        line_start=2,
        line_end=13,
        snippet='SECRET_0 = "value-0"',
    )

    body = propose(api_client, token, finding.id, patch_worker)

    assert body["status"] == PatchStatus.FAILED
    assert "mostly deletes code" in body["error_message"]


def test_a_patch_that_breaks_python_syntax_is_refused(
    api_client: TestClient,
    db_session: Session,
    stub_embedder,
    fake_llm,
    patch_worker,
    workspace_root: Path,
) -> None:
    build_knowledge(db_session, stub_embedder)
    fake_llm.response = patch_response(replacement=BROKEN_LINE)
    token = sign_up(api_client, "broken")
    finding = make_finding(api_client, db_session, token, workspace_root)

    body = propose(api_client, token, finding.id, patch_worker)

    assert body["status"] == PatchStatus.FAILED
    assert "does not parse as Python" in body["error_message"]


def test_a_finding_whose_code_has_moved_is_refused(
    api_client: TestClient,
    db_session: Session,
    stub_embedder,
    fake_llm,
    patch_worker,
    workspace_root: Path,
) -> None:
    """The worst available outcome is a patch that applies to the wrong lines.

    A finding recorded against line 5 of a file that has since been edited
    would otherwise produce a clean-applying diff that changes innocent code.
    """
    build_knowledge(db_session, stub_embedder)
    fake_llm.response = patch_response()
    token = sign_up(api_client, "drifted")
    finding = make_finding(api_client, db_session, token, workspace_root)
    source_file = workspace_root / f"project-{finding.repository.project_id}/repo-patch/src/hash.py"
    source_file.write_text(
        "import hashlib\n\n\ndef digest(value):\n    return 'rewritten'\n", encoding="utf-8"
    )

    body = propose(api_client, token, finding.id, patch_worker)

    assert body["status"] == PatchStatus.FAILED
    assert "Scan again" in body["error_message"]
    assert not fake_llm.prompts, "the model was called for code that had already changed"


def test_a_missing_knowledge_base_fails_rather_than_guessing(
    api_client: TestClient,
    db_session: Session,
    stub_embedder,
    fake_llm,
    patch_worker,
    workspace_root: Path,
) -> None:
    """Same rule as explanations: no sources, no output.

    A fix proposed from the model's memory alone is exactly what this project
    promised not to produce.
    """
    fake_llm.response = patch_response()
    token = sign_up(api_client, "ungrounded")
    finding = make_finding(api_client, db_session, token, workspace_root)

    body = propose(api_client, token, finding.id, patch_worker)

    assert body["status"] == PatchStatus.FAILED
    assert "knowledge base" in body["error_message"].lower()
    assert not fake_llm.prompts


def test_a_timeout_is_reported_with_the_command_that_fixes_it(
    api_client: TestClient,
    db_session: Session,
    stub_embedder,
    fake_llm,
    patch_worker,
    workspace_root: Path,
) -> None:
    build_knowledge(db_session, stub_embedder)
    fake_llm.error = LlmTimeoutError(180, base_url="http://localhost:11434")
    token = sign_up(api_client, "timedout")
    finding = make_finding(api_client, db_session, token, workspace_root)

    body = propose(api_client, token, finding.id, patch_worker)

    assert body["status"] == PatchStatus.FAILED
    assert "ollama serve" in body["error_message"]


def test_garbage_from_the_model_is_reported_not_crashed(
    api_client: TestClient,
    db_session: Session,
    stub_embedder,
    fake_llm,
    patch_worker,
    workspace_root: Path,
) -> None:
    build_knowledge(db_session, stub_embedder)
    fake_llm.response = "I'm sorry, I can't help with that."
    token = sign_up(api_client, "garbage")
    finding = make_finding(api_client, db_session, token, workspace_root)

    body = propose(api_client, token, finding.id, patch_worker)

    assert body["status"] == PatchStatus.FAILED
    assert "not valid JSON" in body["error_message"]


def test_an_already_fixed_finding_cannot_be_patched(
    api_client: TestClient, db_session: Session, stub_embedder, workspace_root: Path
) -> None:
    token = sign_up(api_client, "alreadyfixed")
    finding = make_finding(
        api_client, db_session, token, workspace_root, status=FindingStatus.FIXED
    )

    response = api_client.post(f"/api/v1/findings/{finding.id}/patch", headers=auth(token))

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "FINDING_NOT_PATCHABLE"


def test_a_second_request_while_one_is_running_is_refused(
    api_client: TestClient, db_session: Session, stub_embedder, workspace_root: Path
) -> None:
    """A double click otherwise costs a minute of CPU and produces two
    proposals with nothing to say which is current."""
    token = sign_up(api_client, "doubler")
    finding = make_finding(api_client, db_session, token, workspace_root)

    first = api_client.post(f"/api/v1/findings/{finding.id}/patch", headers=auth(token))
    second = api_client.post(f"/api/v1/findings/{finding.id}/patch", headers=auth(token))

    assert first.status_code == 202
    assert second.status_code == 409
    assert str(first.json()["id"]) in second.json()["error"]["message"]


# --- reading --------------------------------------------------------------


def test_the_latest_endpoint_is_204_before_anything_is_requested(
    api_client: TestClient, db_session: Session, stub_embedder, workspace_root: Path
) -> None:
    """ "Never asked for" has to be distinguishable from "asked for and refused"."""
    token = sign_up(api_client, "never")
    finding = make_finding(api_client, db_session, token, workspace_root)

    response = api_client.get(f"/api/v1/findings/{finding.id}/patch", headers=auth(token))

    assert response.status_code == 204


def test_the_latest_endpoint_returns_a_failed_attempt(
    api_client: TestClient,
    db_session: Session,
    stub_embedder,
    fake_llm,
    patch_worker,
    workspace_root: Path,
) -> None:
    """A refusal is information, and the UI needs it to explain itself."""
    build_knowledge(db_session, stub_embedder)
    fake_llm.response = "not json"
    token = sign_up(api_client, "failedlatest")
    finding = make_finding(api_client, db_session, token, workspace_root)
    propose(api_client, token, finding.id, patch_worker)

    response = api_client.get(f"/api/v1/findings/{finding.id}/patch", headers=auth(token))

    assert response.status_code == 200
    assert response.json()["status"] == PatchStatus.FAILED


def test_another_user_cannot_read_a_patch(
    api_client: TestClient,
    db_session: Session,
    stub_embedder,
    fake_llm,
    patch_worker,
    workspace_root: Path,
) -> None:
    """Ownership runs back to the project that owns the code, not to the
    requester — the same join every other resource uses."""
    build_knowledge(db_session, stub_embedder)
    fake_llm.response = patch_response()
    owner = sign_up(api_client, "owner")
    finding = make_finding(api_client, db_session, owner, workspace_root)
    queued = api_client.post(f"/api/v1/findings/{finding.id}/patch", headers=auth(owner)).json()
    patch_worker.drain()

    intruder = sign_up(api_client, "intruder")
    response = api_client.get(f"/api/v1/patches/{queued['id']}", headers=auth(intruder))

    assert response.status_code == 404


def test_requesting_a_patch_for_someone_elses_finding_is_404(
    api_client: TestClient, db_session: Session, stub_embedder, workspace_root: Path
) -> None:
    owner = sign_up(api_client, "owner2")
    finding = make_finding(api_client, db_session, owner, workspace_root)
    intruder = sign_up(api_client, "intruder2")

    response = api_client.post(f"/api/v1/findings/{finding.id}/patch", headers=auth(intruder))

    assert response.status_code == 404


# --- the queue ------------------------------------------------------------


def test_a_crashed_run_is_requeued_and_then_given_up_on(
    api_client: TestClient, db_session: Session, stub_embedder, workspace_root: Path
) -> None:
    """A process that dies mid-generation leaves a RUNNING row behind.

    It is requeued once, and on the second interruption it is failed with a
    message rather than retried forever — each attempt costs a minute of CPU.
    """
    from datetime import UTC, datetime, timedelta

    from app.repositories.patch_repository import PatchRepository

    token = sign_up(api_client, "stale")
    finding = make_finding(api_client, db_session, token, workspace_root)
    repository = PatchRepository(db_session)
    patch = repository.add(Patch(finding_id=finding.id, status=PatchStatus.RUNNING, attempts=1))
    patch.started_at = datetime.now(UTC) - timedelta(hours=2)
    db_session.flush()

    repository.requeue_stale(older_than_seconds=300, max_attempts=2)
    assert patch.status is PatchStatus.QUEUED

    patch.status = PatchStatus.RUNNING
    patch.attempts = 2
    patch.started_at = datetime.now(UTC) - timedelta(hours=2)
    db_session.flush()
    repository.requeue_stale(older_than_seconds=300, max_attempts=2)

    assert patch.status is PatchStatus.FAILED
    assert "giving up" in patch.error_message


# --- the refusal seen in the running application --------------------------


def test_a_one_line_fix_for_a_one_line_finding_is_accepted(
    api_client: TestClient,
    db_session: Session,
    stub_embedder,
    fake_llm,
    patch_worker,
    workspace_root: Path,
) -> None:
    """The regression test for the bug this phase shipped with.

    A real qwen2.5-coder:7b, asked to fix an f-string SQL query, returned the
    single corrected line — the right answer. Against the whole thirteen-line
    window it was asked to replace, that read as deleting twelve lines, and the
    deletion check refused it. The user saw "the proposed change mostly deletes
    code" for a correct fix.

    The model is now asked only for the marked lines, so the obvious answer is
    also the accepted one.
    """
    build_knowledge(db_session, stub_embedder)
    fake_llm.response = patch_response(replacement=FIXED_LINE)
    token = sign_up(api_client, "oneliner")
    finding = make_finding(api_client, db_session, token, workspace_root)

    body = propose(api_client, token, finding.id, patch_worker)

    assert body["status"] == PatchStatus.PROPOSED, body["error_message"]
    assert body["lines_added"] == 1
    assert body["lines_removed"] == 1


def test_the_prompt_asks_for_the_marked_lines_only(
    api_client: TestClient,
    db_session: Session,
    stub_embedder,
    fake_llm,
    patch_worker,
    workspace_root: Path,
) -> None:
    """Context is shown outside the markers; only the finding's line is inside."""
    from app.patching.region import REPLACE_END, REPLACE_START

    build_knowledge(db_session, stub_embedder)
    fake_llm.response = patch_response()
    token = sign_up(api_client, "marked")
    finding = make_finding(api_client, db_session, token, workspace_root)

    propose(api_client, token, finding.id, patch_worker)

    prompt = fake_llm.prompts[-1]
    lines = prompt.splitlines()
    start = next(i for i, line in enumerate(lines) if REPLACE_START in line)
    end = next(i for i, line in enumerate(lines) if REPLACE_END in line)
    assert end - start == 2, "exactly one line should be inside the markers"
    assert "hashlib.md5" in lines[start + 1]
    assert any("def digest" in line for line in lines[:start])


def test_a_refused_proposal_keeps_what_the_model_returned(
    api_client: TestClient,
    db_session: Session,
    stub_embedder,
    fake_llm,
    patch_worker,
    workspace_root: Path,
) -> None:
    """A rejection that keeps only its reason cannot be diagnosed.

    The first real refusal in this project had to be worked out by inference,
    because the row recorded why the proposal was thrown away but not the
    proposal. It is also the failure data the evaluation needs.
    """
    build_knowledge(db_session, stub_embedder)
    fake_llm.response = patch_response(replacement=UNCHANGED_LINE)
    token = sign_up(api_client, "diagnosable")
    finding = make_finding(api_client, db_session, token, workspace_root)
    queued = api_client.post(f"/api/v1/findings/{finding.id}/patch", headers=auth(token)).json()
    patch_worker.drain()

    from app.models import Patch as PatchRow

    stored = db_session.get(PatchRow, queued["id"])
    db_session.refresh(stored)

    assert stored.status is PatchStatus.FAILED
    assert stored.rejected_code == UNCHANGED_LINE


def test_a_successful_proposal_keeps_no_rejected_code(
    api_client: TestClient,
    db_session: Session,
    stub_embedder,
    fake_llm,
    patch_worker,
    workspace_root: Path,
) -> None:
    build_knowledge(db_session, stub_embedder)
    fake_llm.response = patch_response()
    token = sign_up(api_client, "clean")
    finding = make_finding(api_client, db_session, token, workspace_root)
    queued = api_client.post(f"/api/v1/findings/{finding.id}/patch", headers=auth(token)).json()
    patch_worker.drain()

    from app.models import Patch as PatchRow

    stored = db_session.get(PatchRow, queued["id"])
    db_session.refresh(stored)

    assert stored.status is PatchStatus.PROPOSED
    assert stored.rejected_code is None


def test_the_first_attempt_is_deterministic(
    api_client: TestClient,
    db_session: Session,
    stub_embedder,
    fake_llm,
    patch_worker,
    workspace_root: Path,
) -> None:
    """Temperature 0 on the first run, so the same finding gives the same fix."""
    build_knowledge(db_session, stub_embedder)
    fake_llm.response = patch_response()
    token = sign_up(api_client, "deterministic")
    finding = make_finding(api_client, db_session, token, workspace_root)

    propose(api_client, token, finding.id, patch_worker)

    assert fake_llm.temperatures[-1] is None  # the configured default, which is 0


def test_a_retry_is_not_bit_identical_to_the_attempt_that_failed(
    api_client: TestClient,
    db_session: Session,
    stub_embedder,
    fake_llm,
    patch_worker,
    workspace_root: Path,
) -> None:
    """At temperature 0 a retry returns the identical failure.

    The UI offers "Try again" after a refusal. If that button could only ever
    reproduce the same rejection, it would be the interface telling a lie, so a
    retry asks a slightly different question.
    """
    from app.services.patch_service import RETRY_TEMPERATURE

    build_knowledge(db_session, stub_embedder)
    fake_llm.response = patch_response()
    token = sign_up(api_client, "retrier")
    finding = make_finding(api_client, db_session, token, workspace_root)
    queued = api_client.post(f"/api/v1/findings/{finding.id}/patch", headers=auth(token)).json()

    # Put the row back in the queue as a second attempt, the way the stale
    # sweep does after an interrupted run.
    from app.models import Patch as PatchRow

    row = db_session.get(PatchRow, queued["id"])
    row.status = PatchStatus.QUEUED
    row.attempts = 1
    db_session.flush()
    patch_worker.drain()

    assert fake_llm.temperatures[-1] == RETRY_TEMPERATURE
    db_session.refresh(row)
    assert row.temperature == RETRY_TEMPERATURE
