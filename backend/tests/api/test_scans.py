"""Scans: queueing, running, history, and the finding lifecycle.

The interesting tests here are the lifecycle ones. Phase 5 deleted and
re-inserted findings on every run, so "you fixed two things" was unsayable —
the fixed ones just vanished. These tests pin the behaviour that replaced it.
"""

import io
import zipfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditAction, AuditLog, Finding, FindingStatus, Repository, Scan, ScanStatus

pytestmark = pytest.mark.integration

PROJECTS = "/api/v1/projects"
PASSWORD = "a-long-enough-passphrase"

VULNERABLE = {
    "app/main.py": (
        b"import os\n"
        b"import hashlib\n"
        b"\n"
        b"def handle(command, cursor, user_id):\n"
        b"    os.system(command)\n"
        b'    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
        b"    return hashlib.md5(command.encode()).hexdigest()\n"
    ),
}
PARTLY_FIXED = {
    "app/main.py": (
        b"import os\n"
        b"import hashlib\n"
        b"\n"
        b"def handle(command, cursor, user_id):\n"
        b"    os.system(command)\n"
        b'    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
        b"    return hashlib.sha256(command.encode()).hexdigest()\n"
    ),
}


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


def zip_bytes(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def ingest(client: TestClient, token: str, entries: dict[str, bytes], name: str = "SecureBank"):
    created = client.post(PROJECTS, json={"name": name}, headers=auth(token))
    project_id = created.json()["id"]
    response = client.post(
        f"{PROJECTS}/{project_id}/repositories/upload",
        files={"file": ("code.zip", zip_bytes(entries), "application/zip")},
        headers=auth(token),
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def queue_scan(client: TestClient, token: str, repository_id: int):
    return client.post(f"/api/v1/repositories/{repository_id}/scans", headers=auth(token))


def findings_of(client: TestClient, token: str, repository_id: int, query: str = ""):
    return client.get(
        f"/api/v1/repositories/{repository_id}/findings{query}", headers=auth(token)
    ).json()


# --- queueing -------------------------------------------------------------


def test_queueing_a_scan_returns_immediately(api_client: TestClient) -> None:
    token = sign_up(api_client, "alice")
    repository_id = ingest(api_client, token, VULNERABLE)

    response = queue_scan(api_client, token, repository_id)

    # 202, not 200: the work has been accepted, not done.
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "QUEUED"
    assert body["started_at"] is None
    assert body["total_findings"] == 0


def test_no_analysis_happens_until_the_worker_runs(
    api_client: TestClient, db_session: Session
) -> None:
    token = sign_up(api_client, "alice")
    repository_id = ingest(api_client, token, VULNERABLE)

    queue_scan(api_client, token, repository_id)

    assert db_session.scalars(select(Finding)).all() == []


def test_the_worker_runs_the_scan_and_records_what_it_found(
    api_client: TestClient, scan_worker
) -> None:
    token = sign_up(api_client, "alice")
    repository_id = ingest(api_client, token, VULNERABLE)
    scan_id = queue_scan(api_client, token, repository_id).json()["id"]

    assert scan_worker.tick() is True

    scan = api_client.get(f"/api/v1/scans/{scan_id}", headers=auth(token)).json()
    assert scan["status"] == "COMPLETED"
    assert scan["total_findings"] == 3
    assert scan["new_findings"] == 3
    assert scan["fixed_findings"] == 0
    assert scan["files_scanned"] == 1
    assert scan["duration_ms"] is not None
    assert scan["error_message"] is None


def test_a_second_scan_of_the_same_repository_is_refused(api_client: TestClient) -> None:
    """Two scans writing the same findings would race, and the loser's idea of
    what is fixed would be silently overwritten."""
    token = sign_up(api_client, "alice")
    repository_id = ingest(api_client, token, VULNERABLE)
    queue_scan(api_client, token, repository_id)

    second = queue_scan(api_client, token, repository_id)

    assert second.status_code == 409
    assert second.json()["error"]["code"] == "SCAN_ALREADY_RUNNING"


def test_a_repository_with_no_code_cannot_be_scanned(api_client: TestClient) -> None:
    token = sign_up(api_client, "alice")
    project_id = api_client.post(PROJECTS, json={"name": "X"}, headers=auth(token)).json()["id"]
    api_client.post(
        f"{PROJECTS}/{project_id}/repositories/upload",
        files={"file": ("broken.zip", b"not a zip", "application/zip")},
        headers=auth(token),
    )
    repository_id = api_client.get(
        f"{PROJECTS}/{project_id}/repositories", headers=auth(token)
    ).json()["items"][0]["id"]

    response = queue_scan(api_client, token, repository_id)

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "REPOSITORY_NOT_SCANNABLE"


# --- the lifecycle --------------------------------------------------------


def test_first_scan_marks_everything_new(api_client: TestClient, scan_worker) -> None:
    token = sign_up(api_client, "alice")
    repository_id = ingest(api_client, token, VULNERABLE)
    queue_scan(api_client, token, repository_id)
    scan_worker.tick()

    body = findings_of(api_client, token, repository_id)

    assert {item["status"] for item in body["items"]} == {"NEW"}
    assert body["by_status"] == {"NEW": 3}


def test_an_unchanged_repository_moves_new_to_open(api_client: TestClient, scan_worker) -> None:
    token = sign_up(api_client, "alice")
    repository_id = ingest(api_client, token, VULNERABLE)
    queue_scan(api_client, token, repository_id)
    scan_worker.tick()

    second = queue_scan(api_client, token, repository_id).json()
    scan_worker.tick()

    scan = api_client.get(f"/api/v1/scans/{second['id']}", headers=auth(token)).json()
    assert (scan["total_findings"], scan["new_findings"], scan["fixed_findings"]) == (3, 0, 0)
    body = findings_of(api_client, token, repository_id)
    assert body["by_status"] == {"OPEN": 3}


def test_fixing_code_marks_findings_fixed_without_deleting_them(
    api_client: TestClient, scan_worker, db_session: Session, workspace_root
) -> None:
    """The point of the whole phase: 'you fixed two things' has to be sayable."""
    token = sign_up(api_client, "alice")
    repository_id = ingest(api_client, token, VULNERABLE)
    queue_scan(api_client, token, repository_id)
    scan_worker.tick()

    # Edit the code in place, the way a developer would, then scan again.
    row = db_session.get(Repository, repository_id)
    (workspace_root / row.workspace_path / "app" / "main.py").write_bytes(
        PARTLY_FIXED["app/main.py"]
    )
    second_id = queue_scan(api_client, token, repository_id).json()["id"]
    scan_worker.tick()

    scan = api_client.get(f"/api/v1/scans/{second_id}", headers=auth(token)).json()
    assert scan["fixed_findings"] == 2  # the SQL injection and the weak hash
    assert scan["total_findings"] == 1  # os.system survives
    assert scan["new_findings"] == 0

    body = findings_of(api_client, token, repository_id)
    assert body["by_status"] == {"OPEN": 1, "FIXED": 2}
    fixed = [item for item in body["items"] if item["status"] == "FIXED"]
    assert {item["rule_id"] for item in fixed} == {"PY010", "PY007"}
    assert all(item["fixed_in_scan_id"] == second_id for item in fixed)


def test_a_vulnerability_that_comes_back_counts_as_new_again(
    api_client: TestClient, scan_worker, db_session: Session, workspace_root
) -> None:
    """A reverted fix is a regression, and calling it OPEN would hide that."""
    token = sign_up(api_client, "alice")
    repository_id = ingest(api_client, token, VULNERABLE)
    queue_scan(api_client, token, repository_id)
    scan_worker.tick()
    row = db_session.get(Repository, repository_id)
    source = workspace_root / row.workspace_path / "app" / "main.py"

    source.write_bytes(PARTLY_FIXED["app/main.py"])
    queue_scan(api_client, token, repository_id)
    scan_worker.tick()

    source.write_bytes(VULNERABLE["app/main.py"])  # the fix is reverted
    third_id = queue_scan(api_client, token, repository_id).json()["id"]
    scan_worker.tick()

    scan = api_client.get(f"/api/v1/scans/{third_id}", headers=auth(token)).json()
    assert scan["new_findings"] == 2
    body = findings_of(api_client, token, repository_id)
    assert body["by_status"] == {"NEW": 2, "OPEN": 1}
    assert all(item["fixed_in_scan_id"] is None for item in body["items"])


def test_fixed_findings_do_not_count_towards_severity_totals(
    api_client: TestClient, scan_worker, db_session: Session, workspace_root
) -> None:
    """A CRITICAL you fixed last week is not still a CRITICAL."""
    token = sign_up(api_client, "alice")
    repository_id = ingest(api_client, token, VULNERABLE)
    queue_scan(api_client, token, repository_id)
    scan_worker.tick()
    assert findings_of(api_client, token, repository_id)["by_severity"]["CRITICAL"] == 1

    row = db_session.get(Repository, repository_id)
    (workspace_root / row.workspace_path / "app" / "main.py").write_bytes(
        PARTLY_FIXED["app/main.py"]
    )
    queue_scan(api_client, token, repository_id)
    scan_worker.tick()

    body = findings_of(api_client, token, repository_id)
    assert "CRITICAL" not in body["by_severity"]
    assert body["by_status"]["FIXED"] == 2


def test_findings_can_be_filtered_by_status(api_client: TestClient, scan_worker) -> None:
    token = sign_up(api_client, "alice")
    repository_id = ingest(api_client, token, VULNERABLE)
    queue_scan(api_client, token, repository_id)
    scan_worker.tick()

    body = findings_of(api_client, token, repository_id, "?finding_status=NEW")

    assert len(body["items"]) == 3
    assert findings_of(api_client, token, repository_id, "?finding_status=FIXED")["items"] == []


# --- history --------------------------------------------------------------


def test_scan_history_is_newest_first_and_keeps_its_own_numbers(
    api_client: TestClient, scan_worker, db_session: Session, workspace_root
) -> None:
    token = sign_up(api_client, "alice")
    repository_id = ingest(api_client, token, VULNERABLE)
    queue_scan(api_client, token, repository_id)
    scan_worker.tick()
    row = db_session.get(Repository, repository_id)
    (workspace_root / row.workspace_path / "app" / "main.py").write_bytes(
        PARTLY_FIXED["app/main.py"]
    )
    queue_scan(api_client, token, repository_id)
    scan_worker.tick()

    history = api_client.get(
        f"/api/v1/repositories/{repository_id}/scans", headers=auth(token)
    ).json()

    assert history["total"] == 2
    newest, oldest = history["items"]
    assert newest["id"] > oldest["id"]
    # The first scan still reports what it found, even though the code moved on.
    assert (oldest["new_findings"], oldest["fixed_findings"]) == (3, 0)
    assert (newest["new_findings"], newest["fixed_findings"]) == (0, 2)


def test_scans_are_audited(api_client: TestClient, scan_worker, db_session: Session) -> None:
    token = sign_up(api_client, "alice")
    repository_id = ingest(api_client, token, VULNERABLE)
    queue_scan(api_client, token, repository_id)
    scan_worker.tick()

    actions = set(db_session.scalars(select(AuditLog.action)))

    assert str(AuditAction.SCAN_QUEUED) in actions
    assert str(AuditAction.SCAN_COMPLETED) in actions


def test_deleting_a_repository_deletes_its_scans(
    api_client: TestClient, scan_worker, db_session: Session
) -> None:
    token = sign_up(api_client, "alice")
    repository_id = ingest(api_client, token, VULNERABLE)
    queue_scan(api_client, token, repository_id)
    scan_worker.tick()

    api_client.delete(f"/api/v1/repositories/{repository_id}", headers=auth(token))

    assert db_session.scalars(select(Scan)).all() == []
    assert db_session.scalars(select(Finding)).all() == []


# --- ownership ------------------------------------------------------------


def test_another_user_cannot_queue_read_or_list_your_scans(
    api_client: TestClient, scan_worker
) -> None:
    alice = sign_up(api_client, "alice")
    bob = sign_up(api_client, "bob")
    repository_id = ingest(api_client, alice, VULNERABLE)
    scan_id = queue_scan(api_client, alice, repository_id).json()["id"]
    scan_worker.tick()

    assert queue_scan(api_client, bob, repository_id).status_code == 404
    seen = api_client.get(f"/api/v1/scans/{scan_id}", headers=auth(bob))
    missing = api_client.get("/api/v1/scans/99999", headers=auth(bob))
    assert seen.status_code == missing.status_code == 404
    # Indistinguishable from a scan that does not exist.
    assert seen.json()["error"]["message"] == missing.json()["error"]["message"]
    assert (
        api_client.get(f"/api/v1/repositories/{repository_id}/scans", headers=auth(bob)).status_code
        == 404
    )


def test_scan_endpoints_need_a_token(api_client: TestClient) -> None:
    assert api_client.post("/api/v1/repositories/1/scans").status_code == 401
    assert api_client.get("/api/v1/repositories/1/scans").status_code == 401
    assert api_client.get("/api/v1/scans/1").status_code == 401


# --- failure --------------------------------------------------------------


def test_a_scan_whose_workspace_vanished_fails_with_a_reason(
    api_client: TestClient, scan_worker, db_session: Session, workspace_root
) -> None:
    """Not "0 findings", which would read as "your code is clean"."""
    import shutil

    token = sign_up(api_client, "alice")
    repository_id = ingest(api_client, token, VULNERABLE)
    scan_id = queue_scan(api_client, token, repository_id).json()["id"]
    row = db_session.get(Repository, repository_id)
    shutil.rmtree(workspace_root / row.workspace_path)

    scan_worker.tick()

    scan = api_client.get(f"/api/v1/scans/{scan_id}", headers=auth(token)).json()
    assert scan["status"] == "FAILED"
    assert "missing" in scan["error_message"].lower()
    assert scan["total_findings"] == 0


def test_a_failed_scan_leaves_earlier_findings_alone(
    api_client: TestClient, scan_worker, db_session: Session, workspace_root
) -> None:
    import shutil

    token = sign_up(api_client, "alice")
    repository_id = ingest(api_client, token, VULNERABLE)
    queue_scan(api_client, token, repository_id)
    scan_worker.tick()
    row = db_session.get(Repository, repository_id)
    shutil.rmtree(workspace_root / row.workspace_path)

    queue_scan(api_client, token, repository_id)
    scan_worker.tick()

    body = findings_of(api_client, token, repository_id)
    # A scan that failed changes nothing: the findings are exactly as the last
    # successful scan left them. Marking them FIXED would be the dangerous bug
    # here — "we could not look" is not "the problem is gone".
    assert body["total"] == 3
    assert body["by_status"] == {"NEW": 3}
    assert all(item["fixed_in_scan_id"] is None for item in body["items"])


def test_a_failed_scan_is_audited(api_client: TestClient, scan_worker, db_session: Session) -> None:
    import shutil

    token = sign_up(api_client, "alice")
    repository_id = ingest(api_client, token, VULNERABLE)
    queue_scan(api_client, token, repository_id)
    shutil.rmtree(workspace_root_of(db_session, repository_id))
    scan_worker.tick()

    entry = db_session.scalars(
        select(AuditLog).where(AuditLog.action == str(AuditAction.SCAN_FAILED))
    ).one()
    assert entry.details["repository_id"] == repository_id
    assert entry.details["reason"] == "REPOSITORY_NOT_SCANNABLE"


def workspace_root_of(db_session: Session, repository_id: int):
    from app.core.config import get_settings
    from app.ingestion.workspace import WorkspaceManager

    row = db_session.get(Repository, repository_id)
    return WorkspaceManager(get_settings()).absolute(row.workspace_path)


def test_the_repository_records_when_it_was_last_scanned(
    api_client: TestClient, scan_worker, db_session: Session
) -> None:
    token = sign_up(api_client, "alice")
    repository_id = ingest(api_client, token, VULNERABLE)
    assert db_session.get(Repository, repository_id).analyzed_at is None

    queue_scan(api_client, token, repository_id)
    scan_worker.tick()

    db_session.expire_all()
    assert db_session.get(Repository, repository_id).analyzed_at is not None
    assert db_session.get(Repository, repository_id).findings[0].status is FindingStatus.NEW
    assert (
        db_session.scalars(select(Scan).where(Scan.repository_id == repository_id)).one().status
        is ScanStatus.COMPLETED
    )
