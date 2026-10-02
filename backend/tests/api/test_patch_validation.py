"""Validating a proposed change, end to end.

The model is faked, as everywhere. Nothing else is: a real workspace on disk,
a real finding the real analyser produced, a real proposal through the real
patch worker, and a real re-scan of a real copy.

The claims being pinned down are the ones the interface makes to a developer:
that "validated" appears only when a re-scan supports it, that it never appears
for a change that merely made the finding disappear, and that a validated patch
still has not fixed anything — the code on disk is the same and the finding is
still open.
"""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.engine import analyze_workspace
from app.core.config import get_settings
from app.knowledge.builder import KnowledgeBuilder
from app.knowledge.chunking import Section, SourceDocument
from app.models import (
    AuditAction,
    AuditLog,
    Confidence,
    Finding,
    FindingStatus,
    KnowledgeSource,
    Patch,
    PatchStatus,
    PatchValidation,
    PatchValidationStatus,
    Repository,
    RepositorySource,
    RepositoryStatus,
    Severity,
)

pytestmark = pytest.mark.integration

PROJECTS = "/api/v1/projects"
PASSWORD = "a-long-enough-passphrase"

SOURCE = """\
import hashlib
import os


def digest(value):
    return hashlib.md5(value).hexdigest()


def other():
    return 1
"""

GOOD_FIX = "    return hashlib.sha256(value).hexdigest()"
REWORDED = "    return hashlib.sha1(value).hexdigest()"
NEW_WEAKNESS = '    os.system("sha256sum " + value)\n    return hashlib.sha256(value).hexdigest()'

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


def real_finding(client: TestClient, db: Session, token: str, workspace_root: Path) -> Finding:
    """A finding the real analyser produced, in a real workspace.

    Not a hand-written row. Validation re-runs the analyser and looks for this
    finding by its fingerprint, so a made-up fingerprint would test nothing.
    """
    project_id = client.post(PROJECTS, json={"name": "validating"}, headers=auth(token)).json()[
        "id"
    ]
    relative = f"project-{project_id}/repo-validate"
    workspace = workspace_root / relative
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "hash.py").write_bytes(SOURCE.encode())

    repository = Repository(
        project_id=project_id,
        source=RepositorySource.UPLOAD,
        status=RepositoryStatus.READY,
        origin="x.zip",
        workspace_path=relative,
        file_count=1,
        total_bytes=len(SOURCE),
    )
    db.add(repository)
    db.flush()

    found = next(
        item
        for item in analyze_workspace(workspace, get_settings()).findings
        if item.rule_id == "PY007"
    )
    finding = Finding(
        repository_id=repository.id,
        rule_id=found.rule_id,
        analyzer=found.analyzer,
        title=found.title,
        message=found.message,
        severity=Severity(str(found.severity)),
        confidence=Confidence(str(found.confidence)),
        cwe_id=found.cwe_id,
        owasp_category=found.owasp_category,
        file_path=found.file_path,
        line_start=found.line_start,
        line_end=found.line_end,
        snippet=found.snippet,
        fingerprint=found.fingerprint,
    )
    db.add(finding)
    db.flush()
    return finding


def source_file(workspace_root: Path, finding: Finding) -> Path:
    return workspace_root / f"project-{finding.repository.project_id}/repo-validate/hash.py"


def propose(  # noqa: PLR0913
    client: TestClient,
    db: Session,
    token: str,
    finding: Finding,
    fake_llm,  # noqa: ANN001
    patch_worker,  # noqa: ANN001
    stub_embedder,  # noqa: ANN001
    replacement: str = GOOD_FIX,
) -> dict:
    """Run the real Phase 10 flow and return the proposed patch."""
    KnowledgeBuilder(db, stub_embedder, max_chunk_chars=1200).build(CORPUS)
    fake_llm.response = json.dumps({"replacement": replacement, "rationale": "Changed the hash."})
    queued = client.post(f"/api/v1/findings/{finding.id}/patch", headers=auth(token))
    assert queued.status_code == 202, queued.text
    patch_worker.drain()
    body = client.get(f"/api/v1/patches/{queued.json()['id']}", headers=auth(token)).json()
    assert body["status"] == PatchStatus.PROPOSED, body["error_message"]
    return body


def read_patch(client: TestClient, token: str, patch_id: int) -> dict:
    return client.get(f"/api/v1/patches/{patch_id}", headers=auth(token)).json()


def checks(body: dict) -> dict[str, str]:
    return {check["key"]: check["outcome"] for check in body["validation"]["checks"]}


# --- every proposal is checked ---------------------------------------------


def test_a_proposal_queues_its_own_validation(
    api_client, db_session, stub_embedder, fake_llm, patch_worker, workspace_root
) -> None:
    """Nobody has to ask. There is no window in which a diff is on screen and
    nothing has tried to test it."""
    token = sign_up(api_client, "autoqueue")
    finding = real_finding(api_client, db_session, token, workspace_root)

    body = propose(api_client, db_session, token, finding, fake_llm, patch_worker, stub_embedder)

    assert body["validation"]["status"] == PatchValidationStatus.QUEUED
    # Queued is not validated. The word appears only after a re-scan says so.
    assert body["validated"] is False


def test_a_refused_proposal_queues_nothing(
    api_client, db_session, stub_embedder, fake_llm, patch_worker, workspace_root
) -> None:
    """There is no diff to apply, so there is nothing to check."""
    KnowledgeBuilder(db_session, stub_embedder, max_chunk_chars=1200).build(CORPUS)
    fake_llm.response = "not json"
    token = sign_up(api_client, "noqueue")
    finding = real_finding(api_client, db_session, token, workspace_root)
    queued = api_client.post(f"/api/v1/findings/{finding.id}/patch", headers=auth(token)).json()
    patch_worker.drain()

    body = read_patch(api_client, token, queued["id"])

    assert body["status"] == PatchStatus.FAILED
    assert body["validation"] is None
    assert body["validated"] is False


def test_a_real_fix_is_reported_validated_with_its_evidence(
    api_client, db_session, stub_embedder, fake_llm, patch_worker, validation_worker,
    workspace_root,
) -> None:  # fmt: skip
    token = sign_up(api_client, "validated")
    finding = real_finding(api_client, db_session, token, workspace_root)
    patch = propose(api_client, db_session, token, finding, fake_llm, patch_worker, stub_embedder)

    validation_worker.drain()
    body = read_patch(api_client, token, patch["id"])

    assert body["validated"] is True
    assert body["validation"]["status"] == PatchValidationStatus.PASSED
    # The verdict travels with what was tested, not on its own.
    assert checks(body) == {
        "target_resolved": "passed",
        "no_new_findings": "passed",
        "not_a_deletion": "passed",
        "still_parses": "passed",
    }
    assert body["validation"]["findings_before"] == 1
    assert body["validation"]["findings_after"] == 0
    assert body["validation"]["error_message"] is None


def test_a_validated_patch_has_still_fixed_nothing(
    api_client, db_session, stub_embedder, fake_llm, patch_worker, validation_worker,
    workspace_root,
) -> None:  # fmt: skip
    """The claim this project is most careful about.

    A passed validation means the *proposed* code would not be flagged. The
    code on disk is the same code, so the finding is still open, still at its
    severity, and the file has not changed by a byte. Only a scan of the real
    code closes a finding.
    """
    token = sign_up(api_client, "stillopen")
    finding = real_finding(api_client, db_session, token, workspace_root)
    on_disk = source_file(workspace_root, finding).read_bytes()
    patch = propose(api_client, db_session, token, finding, fake_llm, patch_worker, stub_embedder)

    validation_worker.drain()

    assert read_patch(api_client, token, patch["id"])["validated"] is True
    db_session.refresh(finding)
    assert finding.status is FindingStatus.NEW
    assert finding.severity is Severity.MEDIUM
    assert finding.fixed_in_scan_id is None
    assert source_file(workspace_root, finding).read_bytes() == on_disk


# --- the finding disappears and the verdict is still no ---------------------


def test_a_reworded_weakness_is_rejected_not_validated(
    api_client, db_session, stub_embedder, fake_llm, patch_worker, validation_worker,
    workspace_root,
) -> None:  # fmt: skip
    """MD5 to SHA-1 passes every Phase 10 check: it changes something, it is
    small, it is not a deletion, it parses. Only scanning it again shows that
    the same rule still fires."""
    token = sign_up(api_client, "reworded")
    finding = real_finding(api_client, db_session, token, workspace_root)
    patch = propose(
        api_client, db_session, token, finding, fake_llm, patch_worker, stub_embedder, REWORDED
    )

    validation_worker.drain()
    body = read_patch(api_client, token, patch["id"])

    assert body["validated"] is False
    assert body["validation"]["status"] == PatchValidationStatus.REJECTED
    assert checks(body)["no_new_findings"] == "failed"
    assert body["validation"]["new_findings"][0]["rule_id"] == "PY007"
    # The proposal itself is unchanged: still a proposal, now with a verdict.
    assert body["status"] == PatchStatus.PROPOSED


def test_a_fix_that_adds_a_new_weakness_is_rejected_and_names_it(
    api_client, db_session, stub_embedder, fake_llm, patch_worker, validation_worker,
    workspace_root,
) -> None:  # fmt: skip
    token = sign_up(api_client, "newweakness")
    finding = real_finding(api_client, db_session, token, workspace_root)
    patch = propose(
        api_client, db_session, token, finding, fake_llm, patch_worker, stub_embedder,
        NEW_WEAKNESS,
    )  # fmt: skip

    validation_worker.drain()
    body = read_patch(api_client, token, patch["id"])

    assert body["validated"] is False
    assert checks(body)["target_resolved"] == "passed"
    assert checks(body)["no_new_findings"] == "failed"
    new = body["validation"]["new_findings"]
    assert new
    assert new[0]["file_path"] == "hash.py"
    assert new[0]["rule_id"] != "PY007"


# --- could not be judged ----------------------------------------------------


def test_code_that_moved_is_reported_as_unchecked_not_as_rejected(
    api_client, db_session, stub_embedder, fake_llm, patch_worker, validation_worker,
    workspace_root,
) -> None:  # fmt: skip
    """A stale workspace says nothing about the patch. Recording it as a
    rejection would blame the model for something the model did not do — and
    would poison any measurement of how often its fixes hold up."""
    token = sign_up(api_client, "moved")
    finding = real_finding(api_client, db_session, token, workspace_root)
    patch = propose(api_client, db_session, token, finding, fake_llm, patch_worker, stub_embedder)
    source_file(workspace_root, finding).write_text(
        SOURCE.replace("def digest(value):", "def digest(v):"), encoding="utf-8"
    )

    validation_worker.drain()
    body = read_patch(api_client, token, patch["id"])

    assert body["validation"]["status"] == PatchValidationStatus.FAILED
    assert body["validation"]["status"] != PatchValidationStatus.REJECTED
    assert body["validated"] is False
    assert "changed since" in body["validation"]["error_message"]
    assert body["validation"]["checks"] == []


# --- asking again -----------------------------------------------------------


def test_a_validation_can_be_requested_again(
    api_client, db_session, stub_embedder, fake_llm, patch_worker, validation_worker,
    workspace_root,
) -> None:  # fmt: skip
    token = sign_up(api_client, "again")
    finding = real_finding(api_client, db_session, token, workspace_root)
    patch = propose(api_client, db_session, token, finding, fake_llm, patch_worker, stub_embedder)
    validation_worker.drain()
    first = read_patch(api_client, token, patch["id"])["validation"]["id"]

    response = api_client.post(f"/api/v1/patches/{patch['id']}/validation", headers=auth(token))

    assert response.status_code == 202
    body = response.json()
    assert body["id"] == patch["id"]
    assert body["validation"]["id"] != first
    assert body["validation"]["status"] == PatchValidationStatus.QUEUED


def test_validated_follows_the_latest_check_not_the_best_one(
    api_client, db_session, stub_embedder, fake_llm, patch_worker, validation_worker,
    workspace_root,
) -> None:  # fmt: skip
    """A patch that passed yesterday and is being re-checked now is not
    "validated" while the new check is pending. The word tracks the most recent
    evidence, never the most flattering."""
    token = sign_up(api_client, "latest")
    finding = real_finding(api_client, db_session, token, workspace_root)
    patch = propose(api_client, db_session, token, finding, fake_llm, patch_worker, stub_embedder)
    validation_worker.drain()
    assert read_patch(api_client, token, patch["id"])["validated"] is True

    api_client.post(f"/api/v1/patches/{patch['id']}/validation", headers=auth(token))
    assert read_patch(api_client, token, patch["id"])["validated"] is False

    # And when the code has moved by the time it runs, it stays false.
    source_file(workspace_root, finding).write_text(
        SOURCE.replace("def digest(value):", "def digest(v):"), encoding="utf-8"
    )
    validation_worker.drain()
    assert read_patch(api_client, token, patch["id"])["validated"] is False


def test_the_queued_validation_is_committed_not_just_flushed(
    api_client, db_session, stub_embedder, fake_llm, patch_worker, validation_worker,
    workspace_root,
) -> None:  # fmt: skip
    """The same trap as every other 202 endpoint in this project: without the
    commit the row is rolled back with the request, the worker never sees it,
    and the shared-session fixture hides the difference."""
    token = sign_up(api_client, "committing")
    finding = real_finding(api_client, db_session, token, workspace_root)
    patch = propose(api_client, db_session, token, finding, fake_llm, patch_worker, stub_embedder)
    validation_worker.drain()
    commits: list[int] = []
    original = db_session.commit
    db_session.commit = lambda: (commits.append(1), original())[1]  # type: ignore[method-assign]
    try:
        api_client.post(f"/api/v1/patches/{patch['id']}/validation", headers=auth(token))
    finally:
        db_session.commit = original  # type: ignore[method-assign]

    assert commits, "the endpoint returned 202 without committing the queued validation"


def test_a_second_request_while_one_is_pending_is_refused(
    api_client, db_session, stub_embedder, fake_llm, patch_worker, workspace_root
) -> None:
    token = sign_up(api_client, "doublecheck")
    finding = real_finding(api_client, db_session, token, workspace_root)
    # The automatic validation is still queued: the worker has not run.
    patch = propose(api_client, db_session, token, finding, fake_llm, patch_worker, stub_embedder)

    response = api_client.post(f"/api/v1/patches/{patch['id']}/validation", headers=auth(token))

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "VALIDATION_ALREADY_RUNNING"


def test_a_patch_that_was_never_proposed_cannot_be_validated(
    api_client, db_session, stub_embedder, fake_llm, patch_worker, workspace_root
) -> None:
    KnowledgeBuilder(db_session, stub_embedder, max_chunk_chars=1200).build(CORPUS)
    fake_llm.response = "not json"
    token = sign_up(api_client, "nothingtocheck")
    finding = real_finding(api_client, db_session, token, workspace_root)
    queued = api_client.post(f"/api/v1/findings/{finding.id}/patch", headers=auth(token)).json()
    patch_worker.drain()

    response = api_client.post(f"/api/v1/patches/{queued['id']}/validation", headers=auth(token))

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "PATCH_NOT_VALIDATABLE"


def test_someone_elses_patch_cannot_be_validated_or_seen(
    api_client, db_session, stub_embedder, fake_llm, patch_worker, validation_worker,
    workspace_root,
) -> None:  # fmt: skip
    owner = sign_up(api_client, "vowner")
    finding = real_finding(api_client, db_session, owner, workspace_root)
    patch = propose(api_client, db_session, owner, finding, fake_llm, patch_worker, stub_embedder)
    validation_worker.drain()
    intruder = sign_up(api_client, "vintruder")

    asked = api_client.post(f"/api/v1/patches/{patch['id']}/validation", headers=auth(intruder))
    missing = api_client.post("/api/v1/patches/999999/validation", headers=auth(intruder))

    # Same status and same body for "not yours" and "does not exist".
    assert asked.status_code == missing.status_code == 404
    assert asked.json()["error"]["code"] == missing.json()["error"]["code"]


def test_validation_requires_a_signed_in_user(api_client) -> None:
    assert api_client.post("/api/v1/patches/1/validation").status_code == 401


# --- the record -------------------------------------------------------------


def test_each_verdict_is_written_to_the_audit_log(
    api_client, db_session, stub_embedder, fake_llm, patch_worker, validation_worker,
    workspace_root,
) -> None:  # fmt: skip
    token = sign_up(api_client, "audited")
    finding = real_finding(api_client, db_session, token, workspace_root)
    patch = propose(
        api_client, db_session, token, finding, fake_llm, patch_worker, stub_embedder, REWORDED
    )
    validation_worker.drain()
    api_client.post(f"/api/v1/patches/{patch['id']}/validation", headers=auth(token))

    actions = set(db_session.scalars(select(AuditLog.action)))

    assert str(AuditAction.PATCH_VALIDATION_REJECTED) in actions
    assert str(AuditAction.PATCH_VALIDATION_REQUESTED) in actions
    rejected = db_session.scalars(
        select(AuditLog).where(AuditLog.action == str(AuditAction.PATCH_VALIDATION_REJECTED))
    ).first()
    assert rejected.details["failed_checks"] == ["no_new_findings"]


def test_an_interrupted_validation_fails_rather_than_rejecting(
    api_client, db_session, stub_embedder, fake_llm, patch_worker, workspace_root
) -> None:
    """A process that died mid-check learned nothing about the patch. It is
    retried once, then recorded as FAILED — never as REJECTED, which is a
    verdict."""
    from datetime import UTC, datetime, timedelta

    from app.repositories.patch_validation_repository import PatchValidationRepository

    token = sign_up(api_client, "interrupted")
    finding = real_finding(api_client, db_session, token, workspace_root)
    patch = propose(api_client, db_session, token, finding, fake_llm, patch_worker, stub_embedder)
    validation = db_session.scalars(
        select(PatchValidation).where(PatchValidation.patch_id == patch["id"])
    ).one()
    repository = PatchValidationRepository(db_session)

    validation.status = PatchValidationStatus.RUNNING
    validation.attempts = 1
    validation.started_at = datetime.now(UTC) - timedelta(hours=1)
    db_session.flush()
    repository.requeue_stale(older_than_seconds=30, max_attempts=2)
    assert validation.status is PatchValidationStatus.QUEUED

    validation.status = PatchValidationStatus.RUNNING
    validation.attempts = 2
    validation.started_at = datetime.now(UTC) - timedelta(hours=1)
    db_session.flush()
    repository.requeue_stale(older_than_seconds=30, max_attempts=2)

    assert validation.status is PatchValidationStatus.FAILED
    assert "giving up" in validation.error_message


def test_deleting_a_patch_takes_its_validations_with_it(
    api_client, db_session, stub_embedder, fake_llm, patch_worker, validation_worker,
    workspace_root,
) -> None:  # fmt: skip
    token = sign_up(api_client, "cascade")
    finding = real_finding(api_client, db_session, token, workspace_root)
    patch = propose(api_client, db_session, token, finding, fake_llm, patch_worker, stub_embedder)
    validation_worker.drain()

    db_session.delete(db_session.get(Patch, patch["id"]))
    db_session.flush()

    assert db_session.scalars(select(PatchValidation)).all() == []
