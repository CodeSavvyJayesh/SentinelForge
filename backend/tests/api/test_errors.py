"""Standard error envelope."""

from collections.abc import Iterator

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient
from pydantic import BaseModel

from app.core.errors import AppError
from app.main import create_app


class LoginAttempt(BaseModel):
    username: str
    password: str
    remember_me: bool


router = APIRouter(prefix="/_test")


@router.post("/validate")
def validate(payload: LoginAttempt) -> dict[str, str]:
    return {"username": payload.username}


@router.get("/app-error")
def app_error() -> None:
    raise AppError("PROJECT_NOT_FOUND", "Project not found", status_code=404, details={"id": 7})


@router.get("/crash")
def crash() -> None:
    raise RuntimeError("database password is hunter2")


@pytest.fixture
def error_client() -> Iterator[TestClient]:
    app = create_app()
    app.include_router(router)
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


def assert_envelope(response, status_code: int, code: str) -> dict:  # type: ignore[no-untyped-def]
    assert response.status_code == status_code
    error = response.json()["error"]
    assert set(error) == {"code", "message", "details", "request_id"}
    assert error["code"] == code
    assert error["request_id"] == response.headers["X-Request-ID"]
    return error


def test_unknown_route_returns_not_found_envelope(error_client: TestClient) -> None:
    assert_envelope(error_client.get("/api/v1/does-not-exist"), 404, "NOT_FOUND")


def test_wrong_method_returns_method_not_allowed_envelope(error_client: TestClient) -> None:
    assert_envelope(error_client.delete("/api/v1/health/live"), 405, "METHOD_NOT_ALLOWED")


def test_validation_error_lists_fields_without_echoing_input(error_client: TestClient) -> None:
    response = error_client.post(
        "/_test/validate", json={"username": "alice", "password": "S3cr3t!", "remember_me": "maybe"}
    )
    error = assert_envelope(response, 422, "VALIDATION_ERROR")
    assert error["details"][0]["location"] == ["body", "remember_me"]
    assert "S3cr3t!" not in response.text


def test_app_error_is_rendered_with_its_code_and_details(error_client: TestClient) -> None:
    error = assert_envelope(error_client.get("/_test/app-error"), 404, "PROJECT_NOT_FOUND")
    assert error["message"] == "Project not found"
    assert error["details"] == {"id": 7}


def test_unhandled_exception_returns_generic_500(error_client: TestClient) -> None:
    response = error_client.get("/_test/crash")
    error = assert_envelope(response, 500, "INTERNAL_ERROR")
    assert error["message"] == "An unexpected error occurred"
    assert "hunter2" not in response.text
    assert "Traceback" not in response.text
