"""Repository ingestion through the API: ownership, limits and failures.

The unit tests prove the archive and clone modules refuse dangerous input.
These prove the endpoints use them, that a rejection is recorded rather than
swallowed, and that one user can never reach another user's code.
"""

import io
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import AuditAction, AuditLog, Repository, RepositoryStatus
from tests.git_server import build_repository, find_http_backend, serve_repository

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


def new_project(client: TestClient, token: str, name: str = "SecureBank") -> int:
    return client.post(PROJECTS, json={"name": name}, headers=auth(token)).json()["id"]


def zip_bytes(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


SAMPLE_CODE = {
    "app/main.py": b"import os\n\ndef run():\n    return os.getenv('MODE')\n" * 20,
    "app/util.js": b"export const add = (a, b) => a + b;\n",
    "README.md": b"# Demo\n",
}


def upload(
    client: TestClient, token: str, project_id: int, data: bytes, filename: str = "code.zip"
):
    return client.post(
        f"{PROJECTS}/{project_id}/repositories/upload",
        files={"file": (filename, data, "application/zip")},
        headers=auth(token),
    )


# --- uploading ------------------------------------------------------------


def test_uploading_a_zip_ingests_and_summarises_it(api_client: TestClient) -> None:
    token = sign_up(api_client, "alice")
    project_id = new_project(api_client, token)

    response = upload(api_client, token, project_id, zip_bytes(SAMPLE_CODE))

    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "READY"
    assert body["source"] == "UPLOAD"
    assert body["file_count"] == 3
    assert body["total_bytes"] > 0
    assert body["primary_language"] == "Python"
    assert body["language_breakdown"]["Python"] > 0
    assert body["error_message"] is None
    assert body["ingested_at"] is not None


def test_the_workspace_path_is_never_exposed(api_client: TestClient) -> None:
    token = sign_up(api_client, "alice")
    project_id = new_project(api_client, token)

    body = upload(api_client, token, project_id, zip_bytes(SAMPLE_CODE)).json()

    assert "workspace_path" not in body
    assert "/" not in str(body.get("origin", "")), "the origin is a filename, not a path"


def test_the_files_really_land_in_an_isolated_workspace(
    api_client: TestClient, db_session: Session, workspace_root: Path
) -> None:
    token = sign_up(api_client, "alice")
    project_id = new_project(api_client, token)
    repository_id = upload(api_client, token, project_id, zip_bytes(SAMPLE_CODE)).json()["id"]

    row = db_session.get(Repository, repository_id)
    assert row is not None and row.workspace_path is not None
    workspace = workspace_root / row.workspace_path

    assert workspace.is_dir()
    assert (workspace / "app/main.py").exists()
    assert workspace.is_relative_to(workspace_root)
    # Nothing is executable, whatever the archive claimed.
    assert (workspace / "app/main.py").stat().st_mode & 0o111 == 0


def test_a_github_style_wrapper_folder_is_unwrapped(
    api_client: TestClient, db_session: Session, workspace_root: Path
) -> None:
    token = sign_up(api_client, "alice")
    project_id = new_project(api_client, token)
    wrapped = {f"flask-main/{name}": content for name, content in SAMPLE_CODE.items()}

    repository_id = upload(api_client, token, project_id, zip_bytes(wrapped)).json()["id"]

    row = db_session.get(Repository, repository_id)
    assert row is not None and row.workspace_path
    workspace = workspace_root / row.workspace_path
    assert (workspace / "app/main.py").exists()
    assert not (workspace / "flask-main").exists()


def test_a_malicious_archive_is_refused_and_recorded(
    api_client: TestClient, db_session: Session, workspace_root: Path
) -> None:
    token = sign_up(api_client, "alice")
    project_id = new_project(api_client, token)

    response = upload(
        api_client, token, project_id, zip_bytes({"../../escaped.py": b"payload"}), "evil.zip"
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "ARCHIVE_UNSAFE"

    # The attempt survives as a FAILED row with no workspace left behind.
    row = db_session.scalars(select(Repository).where(Repository.project_id == project_id)).one()
    assert row.status is RepositoryStatus.FAILED
    assert row.workspace_path is None
    assert row.error_message
    assert not (workspace_root / f"project-{project_id}").exists() or not any(
        (workspace_root / f"project-{project_id}").iterdir()
    )
    assert not (workspace_root.parent / "escaped.py").exists()


def test_a_failed_ingest_is_audited(api_client: TestClient, db_session: Session) -> None:
    token = sign_up(api_client, "alice")
    project_id = new_project(api_client, token)
    upload(api_client, token, project_id, b"this is not a zip file")

    actions = set(db_session.scalars(select(AuditLog.action)))
    assert str(AuditAction.REPOSITORY_INGEST_FAILED) in actions

    entry = db_session.scalars(
        select(AuditLog).where(AuditLog.action == str(AuditAction.REPOSITORY_INGEST_FAILED))
    ).one()
    assert entry.details["reason"] == "ARCHIVE_INVALID"
    assert "not a zip" not in str(entry.details), "the submitted bytes never reach the audit log"


def test_a_successful_ingest_is_audited(api_client: TestClient, db_session: Session) -> None:
    token = sign_up(api_client, "alice")
    project_id = new_project(api_client, token)
    upload(api_client, token, project_id, zip_bytes(SAMPLE_CODE))

    entry = db_session.scalars(
        select(AuditLog).where(AuditLog.action == str(AuditAction.REPOSITORY_CONNECTED))
    ).one()
    assert entry.entity_type == "repository"
    assert entry.details["file_count"] == 3


def test_an_empty_archive_is_rejected(api_client: TestClient) -> None:
    token = sign_up(api_client, "alice")
    project_id = new_project(api_client, token)

    response = upload(api_client, token, project_id, zip_bytes({}))

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "REPOSITORY_EMPTY"


def test_an_archive_of_only_ignored_files_is_rejected(api_client: TestClient) -> None:
    token = sign_up(api_client, "alice")
    project_id = new_project(api_client, token)

    response = upload(
        api_client, token, project_id, zip_bytes({"node_modules/x/index.js": b"var a = 1;\n"})
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "REPOSITORY_EMPTY"


def test_an_oversized_upload_is_refused(api_client: TestClient) -> None:
    token = sign_up(api_client, "alice")
    project_id = new_project(api_client, token)
    settings = get_settings()
    # Incompressible, so the *upload* size limit is what stops it.
    import secrets

    payload = secrets.token_bytes(settings.MAX_ARCHIVE_BYTES + 200 * 1024)

    response = upload(api_client, token, project_id, payload, "huge.zip")

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "ARCHIVE_TOO_LARGE"


def test_a_zip_bomb_is_refused(api_client: TestClient) -> None:
    token = sign_up(api_client, "alice")
    project_id = new_project(api_client, token)
    bomb = zip_bytes({"bomb.txt": b"\0" * (3 * 1024 * 1024)})
    assert len(bomb) < 100 * 1024, "the bomb must be small on the wire"

    response = upload(api_client, token, project_id, bomb)

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "ARCHIVE_EXPANDS_TOO_MUCH"


def test_the_repository_limit_is_enforced(api_client: TestClient) -> None:
    token = sign_up(api_client, "alice")
    project_id = new_project(api_client, token)
    limit = get_settings().MAX_REPOSITORIES_PER_PROJECT
    for _ in range(limit):
        assert upload(api_client, token, project_id, zip_bytes(SAMPLE_CODE)).status_code == 201

    response = upload(api_client, token, project_id, zip_bytes(SAMPLE_CODE))

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "REPOSITORY_LIMIT_REACHED"


def test_a_dangerous_filename_is_stored_harmlessly(
    api_client: TestClient, db_session: Session
) -> None:
    token = sign_up(api_client, "alice")
    project_id = new_project(api_client, token)

    body = upload(
        api_client, token, project_id, zip_bytes(SAMPLE_CODE), "../../../etc/passwd.zip"
    ).json()

    assert body["origin"] == "passwd.zip"
    row = db_session.get(Repository, body["id"])
    assert row is not None and ".." not in row.origin


# --- ownership ------------------------------------------------------------


def test_uploading_to_someone_elses_project_is_a_404(api_client: TestClient) -> None:
    alice_token = sign_up(api_client, "alice")
    bob_token = sign_up(api_client, "bob")
    alice_project = new_project(api_client, alice_token)

    response = upload(api_client, bob_token, alice_project, zip_bytes(SAMPLE_CODE))

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "PROJECT_NOT_FOUND"


def test_another_users_repository_is_invisible(api_client: TestClient) -> None:
    alice_token = sign_up(api_client, "alice")
    bob_token = sign_up(api_client, "bob")
    alice_project = new_project(api_client, alice_token)
    repository_id = upload(api_client, alice_token, alice_project, zip_bytes(SAMPLE_CODE)).json()[
        "id"
    ]

    seen = api_client.get(f"/api/v1/repositories/{repository_id}", headers=auth(bob_token))
    missing = api_client.get("/api/v1/repositories/99999", headers=auth(bob_token))

    assert seen.status_code == 404
    # Indistinguishable from an id that does not exist at all.
    assert seen.json()["error"] == missing.json()["error"] | {
        "request_id": seen.json()["error"]["request_id"]
    }


def test_another_users_repository_cannot_be_deleted(
    api_client: TestClient, db_session: Session, workspace_root: Path
) -> None:
    alice_token = sign_up(api_client, "alice")
    bob_token = sign_up(api_client, "bob")
    alice_project = new_project(api_client, alice_token)
    repository_id = upload(api_client, alice_token, alice_project, zip_bytes(SAMPLE_CODE)).json()[
        "id"
    ]

    response = api_client.delete(f"/api/v1/repositories/{repository_id}", headers=auth(bob_token))

    assert response.status_code == 404
    row = db_session.get(Repository, repository_id)
    assert row is not None, "Alice's repository must still exist"
    assert (workspace_root / row.workspace_path).is_dir(), "and its files must still be there"


def test_listing_someone_elses_project_repositories_is_a_404(api_client: TestClient) -> None:
    alice_token = sign_up(api_client, "alice")
    bob_token = sign_up(api_client, "bob")
    alice_project = new_project(api_client, alice_token)

    response = api_client.get(f"{PROJECTS}/{alice_project}/repositories", headers=auth(bob_token))

    assert response.status_code == 404


def test_every_repository_endpoint_needs_a_token(api_client: TestClient) -> None:
    token = sign_up(api_client, "alice")
    project_id = new_project(api_client, token)

    assert api_client.get(f"{PROJECTS}/{project_id}/repositories").status_code == 401
    assert api_client.get("/api/v1/repositories/1").status_code == 401
    assert api_client.delete("/api/v1/repositories/1").status_code == 401
    assert (
        api_client.post(
            f"{PROJECTS}/{project_id}/repositories/upload",
            files={"file": ("x.zip", zip_bytes(SAMPLE_CODE), "application/zip")},
        ).status_code
        == 401
    )


# --- listing and deleting -------------------------------------------------


def test_listing_shows_only_this_projects_repositories(api_client: TestClient) -> None:
    token = sign_up(api_client, "alice")
    first = new_project(api_client, token, "First")
    second = new_project(api_client, token, "Second")
    upload(api_client, token, first, zip_bytes(SAMPLE_CODE))
    upload(api_client, token, second, zip_bytes(SAMPLE_CODE))

    body = api_client.get(f"{PROJECTS}/{first}/repositories", headers=auth(token)).json()

    assert body["total"] == 1
    assert body["items"][0]["project_id"] == first


def test_deleting_removes_the_row_and_the_files(
    api_client: TestClient, db_session: Session, workspace_root: Path
) -> None:
    token = sign_up(api_client, "alice")
    project_id = new_project(api_client, token)
    created = upload(api_client, token, project_id, zip_bytes(SAMPLE_CODE)).json()
    row = db_session.get(Repository, created["id"])
    assert row is not None
    workspace = workspace_root / row.workspace_path

    response = api_client.delete(f"/api/v1/repositories/{created['id']}", headers=auth(token))

    assert response.status_code == 204
    assert not workspace.exists()
    assert (
        api_client.get(f"{PROJECTS}/{project_id}/repositories", headers=auth(token)).json()["total"]
        == 0
    )


def test_deleting_a_project_deletes_its_repositories(
    api_client: TestClient, db_session: Session
) -> None:
    token = sign_up(api_client, "alice")
    project_id = new_project(api_client, token)
    upload(api_client, token, project_id, zip_bytes(SAMPLE_CODE))

    assert api_client.delete(f"{PROJECTS}/{project_id}", headers=auth(token)).status_code == 204

    remaining = db_session.scalars(
        select(Repository).where(Repository.project_id == project_id)
    ).all()
    assert remaining == []


# --- git ------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ext::sh -c 'id'",
        "git://github.com/x/y",
        "https://127.0.0.1/x.git",
        "https://169.254.169.254/latest/meta-data",
        "http://github.com/x/y.git",
    ],
)
def test_dangerous_clone_urls_are_refused_by_the_endpoint(
    api_client: TestClient, db_session: Session, url: str
) -> None:
    token = sign_up(api_client, "alice")
    project_id = new_project(api_client, token)

    response = api_client.post(
        f"{PROJECTS}/{project_id}/repositories/git",
        json={"repository_url": url},
        headers=auth(token),
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "REPOSITORY_URL_INVALID"
    # A URL rejected before any work starts leaves nothing behind at all.
    assert db_session.scalars(select(Repository)).all() == []


@pytest.fixture
def local_clones_allowed(api_client: TestClient):
    """Let this test clone from 127.0.0.1 over http.

    Both switches are real settings an internal deployment can turn on, so the
    production defaults (https only, public hosts only) are still what the
    other tests exercise.
    """
    from app.core.deps import get_settings as settings_dependency

    relaxed = get_settings().model_copy(
        update={"ALLOW_INSECURE_GIT_URLS": True, "ALLOW_PRIVATE_GIT_HOSTS": True}
    )
    api_client.app.dependency_overrides[settings_dependency] = lambda: relaxed
    yield relaxed
    api_client.app.dependency_overrides.pop(settings_dependency, None)


def test_cloning_a_real_repository(
    api_client: TestClient, tmp_path: Path, local_clones_allowed: object
) -> None:
    if find_http_backend() is None:  # pragma: no cover - depends on the git install
        pytest.skip("git-http-backend is not installed")

    token = sign_up(api_client, "alice")
    project_id = new_project(api_client, token)
    repository = tmp_path / "served" / "demo.git"
    build_repository(repository, {"app.py": "print('hi')\n" * 50, "README.md": "# demo\n"})

    with serve_repository(repository) as url:
        response = api_client.post(
            f"{PROJECTS}/{project_id}/repositories/git",
            json={"repository_url": url, "branch": "main"},
            headers=auth(token),
        )

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "READY"
    assert body["source"] == "GIT"
    assert body["branch"] == "main"
    assert len(body["commit_hash"]) == 40
    assert body["primary_language"] == "Python"
    # Two files: the .git directory is never counted as source code.
    assert body["file_count"] == 2


def test_a_clone_that_fails_leaves_a_failed_row(
    api_client: TestClient, db_session: Session, local_clones_allowed: object
) -> None:
    token = sign_up(api_client, "alice")
    project_id = new_project(api_client, token)

    # Port 1 refuses the connection immediately: a clone failure, not a hang.
    response = api_client.post(
        f"{PROJECTS}/{project_id}/repositories/git",
        json={"repository_url": "http://127.0.0.1:1/nope.git"},
        headers=auth(token),
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "CLONE_FAILED"
    row = db_session.scalars(select(Repository)).one()
    assert row.status is RepositoryStatus.FAILED
    assert row.workspace_path is None
    assert row.error_message
    # Nothing from git's own output (paths, "fatal:") reaches the client.
    assert "fatal" not in response.json()["error"]["message"].lower()
