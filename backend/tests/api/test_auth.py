"""End-to-end authentication flow against a real database."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, REFRESH_COOKIE_NAME
from app.models import AuditAction, AuditLog, RefreshSession, User, UserRole

pytestmark = pytest.mark.integration

REGISTER = "/api/v1/auth/register"
LOGIN = "/api/v1/auth/login"
REFRESH = "/api/v1/auth/refresh"
LOGOUT = "/api/v1/auth/logout"
ME = "/api/v1/auth/me"

PASSWORD = "a-long-enough-passphrase"


def register(client: TestClient, *, email: str = "dev@example.com", username: str = "dev"):
    return client.post(REGISTER, json={"email": email, "username": username, "password": PASSWORD})


def login(client: TestClient, *, identifier: str = "dev@example.com", password: str = PASSWORD):
    return client.post(LOGIN, json={"identifier": identifier, "password": password})


def csrf_headers(client: TestClient) -> dict[str, str]:
    return {CSRF_HEADER_NAME: client.cookies.get(CSRF_COOKIE_NAME, "")}


# --- registration ---------------------------------------------------------


def test_register_creates_user_and_hides_password(api_client: TestClient) -> None:
    response = register(api_client)
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "dev@example.com"
    assert body["is_active"] is True
    assert "password" not in response.text
    assert "hash" not in response.text


def test_first_account_becomes_admin_and_later_ones_do_not(api_client: TestClient) -> None:
    first = register(api_client)
    second = register(api_client, email="second@example.com", username="second")
    assert first.json()["role"] == UserRole.ADMIN
    assert second.json()["role"] == UserRole.USER


def test_password_is_stored_hashed(api_client: TestClient, db_session: Session) -> None:
    register(api_client)
    user = db_session.scalars(select(User).where(User.email == "dev@example.com")).one()
    assert PASSWORD not in user.hashed_password
    assert user.hashed_password.startswith("scrypt$")


@pytest.mark.parametrize(
    ("email", "username"),
    [("dev@example.com", "another"), ("another@example.com", "dev")],
)
def test_duplicate_email_or_username_is_refused_without_saying_which(
    api_client: TestClient, email: str, username: str
) -> None:
    register(api_client)
    response = register(api_client, email=email, username=username)
    assert response.status_code == 409
    message = response.json()["error"]["message"].lower()
    assert "email" not in message and "username" not in message


@pytest.mark.parametrize(
    "payload",
    [
        {"email": "not-an-email", "username": "dev", "password": PASSWORD},
        {"email": "dev@example.com", "username": "has space", "password": PASSWORD},
        {"email": "dev@example.com", "username": "dev", "password": "short"},
    ],
)
def test_invalid_registration_is_rejected(api_client: TestClient, payload: dict) -> None:
    response = api_client.post(REGISTER, json=payload)
    assert response.status_code == 422
    assert PASSWORD not in response.text


# --- login ----------------------------------------------------------------


def test_login_returns_access_token_and_sets_cookies(api_client: TestClient) -> None:
    register(api_client)
    response = login(api_client)
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] > 0
    assert body["user"]["username"] == "dev"

    cookies = response.headers.get_list("set-cookie")
    refresh_cookie = next(c for c in cookies if c.startswith(REFRESH_COOKIE_NAME))
    csrf_cookie = next(c for c in cookies if c.startswith(CSRF_COOKIE_NAME))
    assert "httponly" in refresh_cookie.lower()
    assert "path=/api/v1/auth" in refresh_cookie.lower()
    assert "httponly" not in csrf_cookie.lower()  # the frontend must read this one
    assert body["access_token"] not in refresh_cookie


def test_login_works_with_username_too(api_client: TestClient) -> None:
    register(api_client)
    assert login(api_client, identifier="dev").status_code == 200


def test_wrong_password_and_unknown_user_give_the_same_answer(api_client: TestClient) -> None:
    register(api_client)
    wrong_password = login(api_client, password="not-the-password!")
    unknown_user = login(api_client, identifier="ghost@example.com", password=PASSWORD)
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json()["error"] == unknown_user.json()["error"] | {
        "request_id": wrong_password.json()["error"]["request_id"]
    }


def test_deactivated_account_cannot_log_in(api_client: TestClient, db_session: Session) -> None:
    register(api_client)
    user = db_session.scalars(select(User).where(User.username == "dev")).one()
    user.is_active = False
    db_session.flush()
    response = login(api_client)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "ACCOUNT_INACTIVE"


def test_repeated_failures_are_rate_limited(api_client: TestClient) -> None:
    register(api_client)
    statuses = [login(api_client, password="wrong-password-here").status_code for _ in range(6)]
    assert statuses[-1] == 429
    blocked = login(api_client, password="wrong-password-here")
    assert int(blocked.headers["retry-after"]) > 0


# --- current user ---------------------------------------------------------


def test_me_requires_a_token(api_client: TestClient) -> None:
    response = api_client.get(ME)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_me_returns_the_signed_in_user(api_client: TestClient) -> None:
    register(api_client)
    token = login(api_client).json()["access_token"]
    response = api_client.get(ME, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["username"] == "dev"


def test_tampered_token_is_rejected(api_client: TestClient) -> None:
    register(api_client)
    token = login(api_client).json()["access_token"]
    response = api_client.get(ME, headers={"Authorization": f"Bearer {token[:-3]}abc"})
    assert response.status_code == 401


def test_token_of_deactivated_user_stops_working(
    api_client: TestClient, db_session: Session
) -> None:
    register(api_client)
    token = login(api_client).json()["access_token"]
    user = db_session.scalars(select(User).where(User.username == "dev")).one()
    user.is_active = False
    db_session.flush()
    response = api_client.get(ME, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


# --- refresh and logout ---------------------------------------------------


def test_refresh_rotates_the_token_and_returns_a_new_access_token(
    api_client: TestClient, db_session: Session
) -> None:
    register(api_client)
    first_login = login(api_client)
    old_refresh = api_client.cookies.get(REFRESH_COOKIE_NAME, domain="testserver.local")

    response = api_client.post(REFRESH, headers=csrf_headers(api_client))
    assert response.status_code == 200
    assert response.json()["access_token"] != first_login.json()["access_token"]

    new_refresh = api_client.cookies.get(REFRESH_COOKIE_NAME, domain="testserver.local")
    assert new_refresh != old_refresh
    sessions = db_session.scalars(select(RefreshSession)).all()
    assert len(sessions) == 2
    assert sum(1 for session in sessions if session.revoked_at is None) == 1


def test_refresh_without_csrf_header_is_forbidden(api_client: TestClient) -> None:
    register(api_client)
    login(api_client)
    response = api_client.post(REFRESH)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "CSRF_TOKEN_INVALID"


def test_refresh_with_mismatched_csrf_header_is_forbidden(api_client: TestClient) -> None:
    register(api_client)
    login(api_client)
    response = api_client.post(REFRESH, headers={CSRF_HEADER_NAME: "not-the-cookie-value"})
    assert response.status_code == 403


def test_reusing_an_old_refresh_token_kills_the_whole_family(
    api_client: TestClient, db_session: Session
) -> None:
    register(api_client)
    login(api_client)
    stolen = api_client.cookies.get(REFRESH_COOKIE_NAME, domain="testserver.local")
    api_client.post(REFRESH, headers=csrf_headers(api_client))  # legitimate rotation

    # Replay the old token (as a thief who captured it earlier would).
    api_client.cookies.set(
        REFRESH_COOKIE_NAME, stolen, domain="testserver.local", path="/api/v1/auth"
    )
    replay = api_client.post(REFRESH, headers=csrf_headers(api_client))
    assert replay.status_code == 401

    sessions = db_session.scalars(select(RefreshSession)).all()
    assert all(session.revoked_at is not None for session in sessions)
    actions = set(db_session.scalars(select(AuditLog.action)))
    assert AuditAction.REFRESH_REUSE_DETECTED in actions


def test_unknown_refresh_token_is_rejected(api_client: TestClient) -> None:
    register(api_client)
    login(api_client)
    api_client.cookies.set(
        REFRESH_COOKIE_NAME, "made-up-token", domain="testserver.local", path="/api/v1/auth"
    )
    response = api_client.post(REFRESH, headers=csrf_headers(api_client))
    assert response.status_code == 401


def test_logout_revokes_the_session(api_client: TestClient, db_session: Session) -> None:
    register(api_client)
    login(api_client)
    response = api_client.post(LOGOUT, headers=csrf_headers(api_client))
    assert response.status_code == 204

    sessions = db_session.scalars(select(RefreshSession)).all()
    assert all(session.revoked_at is not None for session in sessions)


# --- audit log ------------------------------------------------------------


def test_audit_log_records_the_security_events(api_client: TestClient, db_session: Session) -> None:
    register(api_client)
    login(api_client, password="wrong-password-here")
    login(api_client)
    api_client.post(REFRESH, headers=csrf_headers(api_client))
    api_client.post(LOGOUT, headers=csrf_headers(api_client))

    entries = db_session.scalars(select(AuditLog)).all()
    actions = [entry.action for entry in entries]
    assert AuditAction.USER_REGISTERED in actions
    assert AuditAction.LOGIN_FAILED in actions
    assert AuditAction.LOGIN_SUCCEEDED in actions
    assert AuditAction.TOKEN_REFRESHED in actions
    assert AuditAction.LOGOUT in actions

    serialised = " ".join(str(entry.details) for entry in entries)
    assert PASSWORD not in serialised
    assert all(entry.request_id for entry in entries)
