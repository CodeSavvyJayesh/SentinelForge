"""Analysis through the API: real code in, real findings out, scoped to you."""

import io
import zipfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditAction, AuditLog, Finding, Repository

pytestmark = pytest.mark.integration

PROJECTS = "/api/v1/projects"
PASSWORD = "a-long-enough-passphrase"

VULNERABLE_PROJECT = {
    "app/main.py": (
        b"import os\n"
        b"import hashlib\n"
        b"import subprocess\n"
        b"\n"
        b"DB_PASSWORD = 'sup3r-s3cret-database-value'\n"
        b"\n"
        b"def handle(command, user_id, cursor):\n"
        b"    os.system(command)\n"
        b"    subprocess.run(command, shell=True)\n"
        b'    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
        b"    return hashlib.md5(command.encode()).hexdigest()\n"
    ),
    "web/app.js": b"document.getElementById('out').innerHTML = userComment;\n",
    "README.md": b"# Deliberately vulnerable demo\n",
}

CLEAN_PROJECT = {
    "app/main.py": (
        b"import secrets\n\n\ndef token() -> str:\n    return secrets.token_urlsafe(32)\n"
    ),
}


def sign_up(client: TestClient, name: str) -> str:
    client.post(
        "/api/v1/auth/register",
        json={"email": f"{name}@example.com", "username": name, "password": PASSWORD},
    )
    response = client.post("/api/v1/auth/login", json={"identifier": name, "password": PASSWORD})
    return response.json()["access_token"]


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def zip_bytes(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def ingested_repository(
    client: TestClient, token: str, entries: dict[str, bytes] = VULNERABLE_PROJECT
) -> int:
    created = client.post(PROJECTS, json={"name": "SecureBank"}, headers=auth(token))
    project_id = created.json()["id"]
    response = client.post(
        f"{PROJECTS}/{project_id}/repositories/upload",
        files={"file": ("code.zip", zip_bytes(entries), "application/zip")},
        headers=auth(token),
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


# --- analysing ------------------------------------------------------------


def test_analysing_a_repository_finds_real_issues(api_client: TestClient) -> None:
    token = sign_up(api_client, "alice")
    repository_id = ingested_repository(api_client, token)

    response = api_client.post(f"/api/v1/repositories/{repository_id}/analyze", headers=auth(token))

    assert response.status_code == 200, response.text
    summary = response.json()
    assert summary["findings"] > 0
    assert summary["files_scanned"] == 3
    assert summary["by_severity"]["CRITICAL"] >= 1
    assert summary["truncated"] is False
    assert summary["analyzed_at"] is not None


def test_the_findings_are_the_ones_planted(api_client: TestClient) -> None:
    token = sign_up(api_client, "alice")
    repository_id = ingested_repository(api_client, token)
    api_client.post(f"/api/v1/repositories/{repository_id}/analyze", headers=auth(token))

    body = api_client.get(
        f"/api/v1/repositories/{repository_id}/findings", headers=auth(token)
    ).json()

    found = {item["rule_id"] for item in body["items"]}
    assert {"PY003", "PY002", "PY010", "PY007", "PY006", "JS003"} <= found
    # Worst first.
    assert body["items"][0]["severity"] == "CRITICAL"
    assert body["total"] == len(body["items"])


def test_findings_carry_their_cwe_and_location(api_client: TestClient) -> None:
    token = sign_up(api_client, "alice")
    repository_id = ingested_repository(api_client, token)
    api_client.post(f"/api/v1/repositories/{repository_id}/analyze", headers=auth(token))

    items = api_client.get(
        f"/api/v1/repositories/{repository_id}/findings", headers=auth(token)
    ).json()["items"]
    sql = next(item for item in items if item["rule_id"] == "PY010")

    assert sql["cwe_id"] == "CWE-89"
    assert sql["owasp_category"].startswith("A03")
    assert sql["file_path"] == "app/main.py"
    assert sql["line_start"] == 10
    assert "SELECT" in sql["snippet"]


def test_a_stored_credential_finding_never_contains_the_credential(
    api_client: TestClient, db_session: Session
) -> None:
    token = sign_up(api_client, "alice")
    repository_id = ingested_repository(api_client, token)
    api_client.post(f"/api/v1/repositories/{repository_id}/analyze", headers=auth(token))

    rows = db_session.scalars(select(Finding).where(Finding.repository_id == repository_id)).all()

    assert any(row.rule_id == "PY006" for row in rows)
    for row in rows:
        assert "sup3r-s3cret-database-value" not in row.snippet
        assert "sup3r-s3cret-database-value" not in row.message


def test_a_clean_repository_reports_zero_not_an_error(api_client: TestClient) -> None:
    token = sign_up(api_client, "alice")
    repository_id = ingested_repository(api_client, token, CLEAN_PROJECT)

    response = api_client.post(f"/api/v1/repositories/{repository_id}/analyze", headers=auth(token))

    assert response.status_code == 200
    assert response.json()["findings"] == 0
    assert response.json()["files_scanned"] == 1


def test_re_analysis_replaces_rather_than_duplicates(
    api_client: TestClient, db_session: Session
) -> None:
    token = sign_up(api_client, "alice")
    repository_id = ingested_repository(api_client, token)

    first = api_client.post(
        f"/api/v1/repositories/{repository_id}/analyze", headers=auth(token)
    ).json()
    second = api_client.post(
        f"/api/v1/repositories/{repository_id}/analyze", headers=auth(token)
    ).json()

    assert first["findings"] == second["findings"]
    rows = db_session.scalars(select(Finding).where(Finding.repository_id == repository_id)).all()
    assert len(rows) == second["findings"]


def test_analysing_records_when_it_happened(api_client: TestClient, db_session: Session) -> None:
    token = sign_up(api_client, "alice")
    repository_id = ingested_repository(api_client, token)
    assert db_session.get(Repository, repository_id).analyzed_at is None

    api_client.post(f"/api/v1/repositories/{repository_id}/analyze", headers=auth(token))

    db_session.expire_all()
    assert db_session.get(Repository, repository_id).analyzed_at is not None


def test_analysis_is_audited_with_counts_not_code(
    api_client: TestClient, db_session: Session
) -> None:
    token = sign_up(api_client, "alice")
    repository_id = ingested_repository(api_client, token)
    api_client.post(f"/api/v1/repositories/{repository_id}/analyze", headers=auth(token))

    entry = db_session.scalars(
        select(AuditLog).where(AuditLog.action == str(AuditAction.REPOSITORY_ANALYZED))
    ).one()

    assert entry.entity_type == "repository"
    assert entry.details["findings"] > 0
    assert "sup3r-s3cret-database-value" not in str(entry.details)


# --- filtering and pagination --------------------------------------------


def test_findings_can_be_filtered_by_severity(api_client: TestClient) -> None:
    token = sign_up(api_client, "alice")
    repository_id = ingested_repository(api_client, token)
    api_client.post(f"/api/v1/repositories/{repository_id}/analyze", headers=auth(token))

    body = api_client.get(
        f"/api/v1/repositories/{repository_id}/findings?severity=CRITICAL",
        headers=auth(token),
    ).json()

    assert body["items"], "the demo project has a critical finding"
    assert {item["severity"] for item in body["items"]} == {"CRITICAL"}
    # The summary counts stay whole-repository, so filtering cannot make the
    # totals shown next to the filter lie.
    assert sum(body["by_severity"].values()) > body["total"]


def test_an_unknown_severity_is_rejected(api_client: TestClient) -> None:
    token = sign_up(api_client, "alice")
    repository_id = ingested_repository(api_client, token)

    response = api_client.get(
        f"/api/v1/repositories/{repository_id}/findings?severity=SEVERE", headers=auth(token)
    )

    assert response.status_code == 422


def test_findings_paginate(api_client: TestClient) -> None:
    token = sign_up(api_client, "alice")
    repository_id = ingested_repository(api_client, token)
    api_client.post(f"/api/v1/repositories/{repository_id}/analyze", headers=auth(token))

    first = api_client.get(
        f"/api/v1/repositories/{repository_id}/findings?limit=2&offset=0", headers=auth(token)
    ).json()
    second = api_client.get(
        f"/api/v1/repositories/{repository_id}/findings?limit=2&offset=2", headers=auth(token)
    ).json()

    assert len(first["items"]) == 2
    first_ids = {item["id"] for item in first["items"]}
    second_ids = {item["id"] for item in second["items"]}
    assert first_ids & second_ids == set()


# --- refusals -------------------------------------------------------------


def test_analysing_a_failed_repository_is_refused(api_client: TestClient) -> None:
    token = sign_up(api_client, "alice")
    project_id = api_client.post(PROJECTS, json={"name": "X"}, headers=auth(token)).json()["id"]
    api_client.post(
        f"{PROJECTS}/{project_id}/repositories/upload",
        files={"file": ("broken.zip", b"not a zip at all", "application/zip")},
        headers=auth(token),
    )
    repository_id = api_client.get(
        f"{PROJECTS}/{project_id}/repositories", headers=auth(token)
    ).json()["items"][0]["id"]

    response = api_client.post(f"/api/v1/repositories/{repository_id}/analyze", headers=auth(token))

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "REPOSITORY_NOT_ANALYSABLE"


def test_a_missing_workspace_is_refused_not_reported_as_clean(
    api_client: TestClient, db_session: Session, workspace_root
) -> None:
    """ "0 findings" would read as "your code is fine". It is not the same thing."""
    import shutil

    token = sign_up(api_client, "alice")
    repository_id = ingested_repository(api_client, token)
    row = db_session.get(Repository, repository_id)
    shutil.rmtree(workspace_root / row.workspace_path)

    response = api_client.post(f"/api/v1/repositories/{repository_id}/analyze", headers=auth(token))

    assert response.status_code == 409
    assert "missing" in response.json()["error"]["message"].lower()


# --- ownership ------------------------------------------------------------


def test_another_user_cannot_analyse_your_repository(api_client: TestClient) -> None:
    alice_token = sign_up(api_client, "alice")
    bob_token = sign_up(api_client, "bob")
    repository_id = ingested_repository(api_client, alice_token)

    response = api_client.post(
        f"/api/v1/repositories/{repository_id}/analyze", headers=auth(bob_token)
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "REPOSITORY_NOT_FOUND"


def test_another_user_cannot_read_your_findings(api_client: TestClient) -> None:
    alice_token = sign_up(api_client, "alice")
    bob_token = sign_up(api_client, "bob")
    repository_id = ingested_repository(api_client, alice_token)
    api_client.post(f"/api/v1/repositories/{repository_id}/analyze", headers=auth(alice_token))
    finding_id = api_client.get(
        f"/api/v1/repositories/{repository_id}/findings", headers=auth(alice_token)
    ).json()["items"][0]["id"]

    listed = api_client.get(
        f"/api/v1/repositories/{repository_id}/findings", headers=auth(bob_token)
    )
    single = api_client.get(f"/api/v1/findings/{finding_id}", headers=auth(bob_token))
    missing = api_client.get("/api/v1/findings/99999", headers=auth(bob_token))

    assert listed.status_code == 404
    assert single.status_code == 404
    # A finding that exists and one that does not are indistinguishable.
    assert single.json()["error"]["code"] == missing.json()["error"]["code"]
    assert single.json()["error"]["message"] == missing.json()["error"]["message"]


def test_analysis_endpoints_need_a_token(api_client: TestClient) -> None:
    assert api_client.post("/api/v1/repositories/1/analyze").status_code == 401
    assert api_client.get("/api/v1/repositories/1/findings").status_code == 401
    assert api_client.get("/api/v1/findings/1").status_code == 401


def test_deleting_a_repository_deletes_its_findings(
    api_client: TestClient, db_session: Session
) -> None:
    token = sign_up(api_client, "alice")
    repository_id = ingested_repository(api_client, token)
    api_client.post(f"/api/v1/repositories/{repository_id}/analyze", headers=auth(token))

    api_client.delete(f"/api/v1/repositories/{repository_id}", headers=auth(token))

    remaining = db_session.scalars(
        select(Finding).where(Finding.repository_id == repository_id)
    ).all()
    assert remaining == []
