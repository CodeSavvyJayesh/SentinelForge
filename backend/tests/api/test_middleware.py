"""Request IDs, security headers and CORS."""

from fastapi.testclient import TestClient


def test_request_id_is_generated_when_missing(client: TestClient) -> None:
    response = client.get("/api/v1/health/live")
    request_id = response.headers["X-Request-ID"]
    assert len(request_id) == 32


def test_valid_incoming_request_id_is_propagated(client: TestClient) -> None:
    response = client.get("/api/v1/health/live", headers={"X-Request-ID": "ci-run-42.step_1"})
    assert response.headers["X-Request-ID"] == "ci-run-42.step_1"


def test_malformed_incoming_request_id_is_replaced(client: TestClient) -> None:
    malicious = "abc def<script>" + "x" * 80
    response = client.get("/api/v1/health/live", headers={"X-Request-ID": malicious})
    assert response.headers["X-Request-ID"] != malicious
    assert len(response.headers["X-Request-ID"]) == 32


def test_security_headers_are_present(client: TestClient) -> None:
    headers = client.get("/api/v1/health/live").headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"


def test_cors_preflight_allows_configured_frontend_origin(client: TestClient) -> None:
    response = client.options(
        "/api/v1/health",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"},
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_cors_allows_credentials_for_the_refresh_cookie(client: TestClient) -> None:
    response = client.options(
        "/api/v1/auth/refresh",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST"},
    )
    assert response.headers["access-control-allow-credentials"] == "true"
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_cors_preflight_allows_the_csrf_header(client: TestClient) -> None:
    """Without this the browser blocks /auth/refresh before it is even sent."""
    response = client.options(
        "/api/v1/auth/refresh",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "x-csrf-token",
        },
    )
    assert response.status_code == 200
    assert "x-csrf-token" in response.headers["access-control-allow-headers"].lower()


def test_cors_does_not_allow_unknown_origin(client: TestClient) -> None:
    response = client.get("/api/v1/health/live", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in response.headers


def test_openapi_schema_is_available(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    assert "/api/v1/health" in schema["paths"]
    assert "/api/v1/health/live" in schema["paths"]
