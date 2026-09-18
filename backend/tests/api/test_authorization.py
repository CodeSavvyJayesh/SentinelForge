"""Role-based access control on the admin endpoint."""

import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.integration

USERS = "/api/v1/users"
PASSWORD = "a-long-enough-passphrase"


def create_user(client: TestClient, name: str) -> str:
    """Register, log in and return an access token."""
    client.post(
        "/api/v1/auth/register",
        json={"email": f"{name}@example.com", "username": name, "password": PASSWORD},
    )
    response = client.post(
        "/api/v1/auth/login", json={"identifier": f"{name}@example.com", "password": PASSWORD}
    )
    return response.json()["access_token"]


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_admin_can_list_users(api_client: TestClient) -> None:
    admin_token = create_user(api_client, "founder")  # first account is the admin
    create_user(api_client, "member")

    response = api_client.get(USERS, headers=auth(admin_token))
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert {item["username"] for item in body["items"]} == {"founder", "member"}
    assert "hashed_password" not in response.text


def test_regular_user_is_forbidden(api_client: TestClient) -> None:
    create_user(api_client, "founder")
    member_token = create_user(api_client, "member")

    response = api_client.get(USERS, headers=auth(member_token))
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


def test_anonymous_request_is_unauthorised(api_client: TestClient) -> None:
    response = api_client.get(USERS)
    assert response.status_code == 401


def test_pagination_parameters_are_validated(api_client: TestClient) -> None:
    admin_token = create_user(api_client, "founder")
    response = api_client.get(f"{USERS}?limit=0", headers=auth(admin_token))
    assert response.status_code == 422
