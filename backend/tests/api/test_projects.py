"""Project CRUD, and the ownership boundary between users."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditAction, AuditLog, Project, User
from app.services.project_service import MAX_PROJECTS_PER_USER

pytestmark = pytest.mark.integration

PROJECTS = "/api/v1/projects"
PASSWORD = "a-long-enough-passphrase"


def sign_up(client: TestClient, name: str) -> str:
    """Register and sign in; returns an access token."""
    client.post(
        "/api/v1/auth/register",
        json={"email": f"{name}@example.com", "username": name, "password": PASSWORD},
    )
    response = client.post("/api/v1/auth/login", json={"identifier": name, "password": PASSWORD})
    return response.json()["access_token"]


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def create_project(client: TestClient, token: str, **overrides: object):
    payload: dict[str, object] = {"name": "SecureBank", **overrides}
    return client.post(PROJECTS, json=payload, headers=auth(token))


# --- creating -------------------------------------------------------------


def test_create_returns_the_project_owned_by_the_caller(api_client: TestClient) -> None:
    token = sign_up(api_client, "alice")
    response = create_project(
        api_client,
        token,
        description="Demo banking app",
        repository_url="https://example.com/x.git",
    )

    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "SecureBank"
    assert body["default_branch"] == "main"
    assert body["language"] is None  # detected in Phase 4, never guessed
    assert body["id"] > 0


def test_owner_comes_from_the_token_not_the_request_body(
    api_client: TestClient, db_session: Session
) -> None:
    alice_token = sign_up(api_client, "alice")
    bob_token = sign_up(api_client, "bob")
    bob = db_session.scalars(select(User).where(User.username == "bob")).one()

    # Bob tries to create a project owned by Alice.
    response = api_client.post(
        PROJECTS, json={"name": "Planted", "owner_id": 1}, headers=auth(bob_token)
    )

    assert response.status_code == 201
    assert response.json()["owner_id"] == bob.id
    assert api_client.get(PROJECTS, headers=auth(alice_token)).json()["total"] == 0


def test_same_name_twice_for_one_user_is_refused(api_client: TestClient) -> None:
    token = sign_up(api_client, "alice")
    create_project(api_client, token)
    response = create_project(api_client, token, name="securebank")  # case-insensitive

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "PROJECT_NAME_TAKEN"


def test_two_users_may_use_the_same_project_name(api_client: TestClient) -> None:
    alice_token = sign_up(api_client, "alice")
    bob_token = sign_up(api_client, "bob")

    assert create_project(api_client, alice_token).status_code == 201
    assert create_project(api_client, bob_token).status_code == 201


@pytest.mark.parametrize(
    "payload",
    [
        {"name": ""},
        {"name": "   "},
        {"name": "x" * 121},
        {"name": "ok", "repository_url": "javascript:alert(1)"},
        {"name": "ok", "default_branch": "bad branch"},
    ],
)
def test_invalid_input_is_refused(api_client: TestClient, payload: dict) -> None:
    token = sign_up(api_client, "alice")
    assert api_client.post(PROJECTS, json=payload, headers=auth(token)).status_code == 422


def test_project_limit_is_enforced(
    api_client: TestClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = sign_up(api_client, "alice")
    user = db_session.scalars(select(User).where(User.username == "alice")).one()
    db_session.add_all(
        [Project(owner_id=user.id, name=f"p{index}") for index in range(MAX_PROJECTS_PER_USER)]
    )
    db_session.flush()

    response = create_project(api_client, token, name="one-too-many")
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "PROJECT_LIMIT_REACHED"


# --- ownership boundary ---------------------------------------------------


def test_another_users_project_is_invisible_not_forbidden(api_client: TestClient) -> None:
    """404, not 403: a 403 would confirm that this project id exists."""
    alice_token = sign_up(api_client, "alice")
    project_id = create_project(api_client, alice_token, name="SecretAudit").json()["id"]

    bob_token = sign_up(api_client, "bob")
    response = api_client.get(f"{PROJECTS}/{project_id}", headers=auth(bob_token))

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "PROJECT_NOT_FOUND"
    assert "SecretAudit" not in response.text  # the name must not leak either


def test_another_user_cannot_update_or_delete(api_client: TestClient) -> None:
    alice_token = sign_up(api_client, "alice")
    project_id = create_project(api_client, alice_token).json()["id"]
    bob_token = sign_up(api_client, "bob")

    patched = api_client.patch(
        f"{PROJECTS}/{project_id}", json={"name": "Hijacked"}, headers=auth(bob_token)
    )
    deleted = api_client.delete(f"{PROJECTS}/{project_id}", headers=auth(bob_token))

    assert patched.status_code == 404
    assert deleted.status_code == 404
    # Alice's project is untouched.
    assert (
        api_client.get(f"{PROJECTS}/{project_id}", headers=auth(alice_token)).json()["name"]
        == "SecureBank"
    )


def test_missing_project_and_other_users_project_are_indistinguishable(
    api_client: TestClient,
) -> None:
    alice_token = sign_up(api_client, "alice")
    project_id = create_project(api_client, alice_token).json()["id"]
    bob_token = sign_up(api_client, "bob")

    theirs = api_client.get(f"{PROJECTS}/{project_id}", headers=auth(bob_token))
    missing = api_client.get(f"{PROJECTS}/999999", headers=auth(bob_token))

    assert theirs.status_code == missing.status_code == 404
    assert theirs.json()["error"]["message"] == missing.json()["error"]["message"]


def test_listing_shows_only_your_own_projects(api_client: TestClient) -> None:
    alice_token = sign_up(api_client, "alice")
    create_project(api_client, alice_token, name="Alice One")
    create_project(api_client, alice_token, name="Alice Two")

    bob_token = sign_up(api_client, "bob")
    create_project(api_client, bob_token, name="Bob One")

    bob_projects = api_client.get(PROJECTS, headers=auth(bob_token)).json()
    assert bob_projects["total"] == 1
    assert [item["name"] for item in bob_projects["items"]] == ["Bob One"]

    alice_projects = api_client.get(PROJECTS, headers=auth(alice_token)).json()
    assert alice_projects["total"] == 2
    assert "Bob One" not in str(alice_projects)


def test_admin_has_no_special_access_to_projects(api_client: TestClient) -> None:
    """The first account is an admin; that must not grant project access."""
    admin_token = sign_up(api_client, "founder")  # first account -> ADMIN
    member_token = sign_up(api_client, "member")
    project_id = create_project(api_client, member_token, name="Members Only").json()["id"]

    assert api_client.get(f"{PROJECTS}/{project_id}", headers=auth(admin_token)).status_code == 404
    assert api_client.get(PROJECTS, headers=auth(admin_token)).json()["total"] == 0


def test_every_endpoint_requires_authentication(api_client: TestClient) -> None:
    token = sign_up(api_client, "alice")
    project_id = create_project(api_client, token).json()["id"]

    assert api_client.get(PROJECTS).status_code == 401
    assert api_client.post(PROJECTS, json={"name": "x"}).status_code == 401
    assert api_client.get(f"{PROJECTS}/{project_id}").status_code == 401
    assert api_client.patch(f"{PROJECTS}/{project_id}", json={"name": "x"}).status_code == 401
    assert api_client.delete(f"{PROJECTS}/{project_id}").status_code == 401


# --- reading, updating, deleting -----------------------------------------


def test_search_and_pagination(api_client: TestClient) -> None:
    token = sign_up(api_client, "alice")
    for name in ["Alpha API", "Beta API", "Gamma Web"]:
        create_project(api_client, token, name=name)

    searched = api_client.get(f"{PROJECTS}?search=api", headers=auth(token)).json()
    assert searched["total"] == 2
    assert {item["name"] for item in searched["items"]} == {"Alpha API", "Beta API"}

    page = api_client.get(f"{PROJECTS}?limit=2&offset=0", headers=auth(token)).json()
    assert len(page["items"]) == 2
    assert page["total"] == 3


def test_search_wildcards_are_escaped(api_client: TestClient) -> None:
    token = sign_up(api_client, "alice")
    create_project(api_client, token, name="Alpha")
    create_project(api_client, token, name="100% coverage")

    result = api_client.get(f"{PROJECTS}?search=%25", headers=auth(token)).json()
    assert [item["name"] for item in result["items"]] == ["100% coverage"]


def test_update_changes_only_the_fields_sent(api_client: TestClient) -> None:
    token = sign_up(api_client, "alice")
    created = create_project(api_client, token, description="original").json()

    response = api_client.patch(
        f"{PROJECTS}/{created['id']}", json={"description": "updated"}, headers=auth(token)
    )

    assert response.status_code == 200
    body = response.json()
    assert body["description"] == "updated"
    assert body["name"] == created["name"]  # untouched
    assert body["updated_at"] >= created["updated_at"]


def test_renaming_to_an_existing_name_is_refused(api_client: TestClient) -> None:
    token = sign_up(api_client, "alice")
    create_project(api_client, token, name="First")
    second_id = create_project(api_client, token, name="Second").json()["id"]

    response = api_client.patch(
        f"{PROJECTS}/{second_id}", json={"name": "First"}, headers=auth(token)
    )
    assert response.status_code == 409


def test_renaming_a_project_to_its_own_name_is_allowed(api_client: TestClient) -> None:
    token = sign_up(api_client, "alice")
    project_id = create_project(api_client, token, name="First").json()["id"]

    response = api_client.patch(
        f"{PROJECTS}/{project_id}",
        json={"name": "First", "description": "same name"},
        headers=auth(token),
    )
    assert response.status_code == 200


def test_delete_removes_the_project(api_client: TestClient) -> None:
    token = sign_up(api_client, "alice")
    project_id = create_project(api_client, token).json()["id"]

    assert api_client.delete(f"{PROJECTS}/{project_id}", headers=auth(token)).status_code == 204
    assert api_client.get(f"{PROJECTS}/{project_id}", headers=auth(token)).status_code == 404
    assert api_client.get(PROJECTS, headers=auth(token)).json()["total"] == 0


def test_deleting_a_user_deletes_only_their_projects(
    api_client: TestClient, db_session: Session
) -> None:
    alice_token = sign_up(api_client, "alice")
    create_project(api_client, alice_token, name="Alice Project")
    bob_token = sign_up(api_client, "bob")
    create_project(api_client, bob_token, name="Bob Project")

    alice = db_session.scalars(select(User).where(User.username == "alice")).one()
    db_session.delete(alice)
    db_session.flush()

    remaining = db_session.scalars(select(Project)).all()
    assert [project.name for project in remaining] == ["Bob Project"]


# --- audit ----------------------------------------------------------------


def test_project_changes_are_audited(api_client: TestClient, db_session: Session) -> None:
    token = sign_up(api_client, "alice")
    project_id = create_project(api_client, token).json()["id"]
    api_client.patch(f"{PROJECTS}/{project_id}", json={"description": "d"}, headers=auth(token))
    api_client.delete(f"{PROJECTS}/{project_id}", headers=auth(token))

    actions = [entry.action for entry in db_session.scalars(select(AuditLog))]
    assert AuditAction.PROJECT_CREATED in actions
    assert AuditAction.PROJECT_UPDATED in actions
    assert AuditAction.PROJECT_DELETED in actions

    updated = db_session.scalars(
        select(AuditLog).where(AuditLog.action == AuditAction.PROJECT_UPDATED)
    ).one()
    # Field names are recorded, not their values.
    assert updated.details == {"fields": ["description"]}
    assert updated.entity_type == "project"
    assert updated.entity_id == str(project_id)
