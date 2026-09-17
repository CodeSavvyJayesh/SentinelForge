"""Health endpoints."""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core.deps import get_db
from app.main import create_app

UNREACHABLE_DB_URL = "postgresql+psycopg://nobody:secret-password@127.0.0.1:9/unreachable_test"


def test_liveness_does_not_need_the_database(client: TestClient) -> None:
    response = client.get("/api/v1/health/live")
    assert response.status_code == 200
    assert response.json()["status"] == "alive"


def test_health_reports_503_without_leaking_details_when_database_is_down() -> None:
    broken_engine = create_engine(UNREACHABLE_DB_URL, connect_args={"connect_timeout": 1})

    def broken_db() -> Iterator[Session]:
        session = Session(bind=broken_engine)
        try:
            yield session
        finally:
            session.close()

    app = create_app()
    app.dependency_overrides[get_db] = broken_db
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/api/v1/health")

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "unhealthy"
    assert body["checks"]["database"] == {
        "status": "down",
        "latency_ms": None,
        "message": "Database connection failed",
    }
    assert "secret-password" not in response.text
    assert "127.0.0.1" not in response.text


@pytest.mark.integration
def test_health_is_healthy_with_test_database(client: TestClient, database_available: None) -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert body["checks"]["database"]["status"] == "up"
    assert body["checks"]["database"]["latency_ms"] >= 0
