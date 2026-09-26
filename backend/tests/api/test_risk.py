"""Risk through the API, and the snapshot a scan leaves behind.

Two claims here that the unit tests cannot make: that the score a reader sees
comes with enough working to argue with, and that the history is a record of
what each run concluded rather than a recomputation of today's findings dressed
in old timestamps.
"""

import io
import zipfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import (
    Confidence,
    Finding,
    FindingStatus,
    Repository,
    RepositorySource,
    RepositoryStatus,
    Scan,
    Severity,
)

pytestmark = pytest.mark.integration

PROJECTS = "/api/v1/projects"
PASSWORD = "a-long-enough-passphrase"

VULNERABLE = {
    "app/main.py": (
        b"import os\nimport hashlib\n\n\n"
        b"def handle(command, cursor, user_id):\n"
        b"    os.system(command)\n"
        b'    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
        b"    return hashlib.md5(command.encode()).hexdigest()\n"
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


def make_repository(client: TestClient, db: Session, token: str) -> Repository:
    project_id = client.post(PROJECTS, json={"name": "risk"}, headers=auth(token)).json()["id"]
    repository = Repository(
        project_id=project_id,
        source=RepositorySource.UPLOAD,
        status=RepositoryStatus.READY,
        origin="risk.zip",
        workspace_path=f"project-{project_id}/repo-risk",
        file_count=1,
        total_bytes=10,
    )
    db.add(repository)
    db.flush()
    return repository


def add_finding(db: Session, repository_id: int, **overrides) -> Finding:  # noqa: ANN003
    defaults = {
        "rule_id": "PY010",
        "analyzer": "python-ast",
        "title": "SQL query built by string formatting",
        "message": "A value formatted into SQL can change the statement.",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021 Injection",
        "file_path": "app/users.py",
        "line_start": 24,
        "line_end": 24,
        "snippet": "cursor.execute(...)",
        "status": FindingStatus.OPEN,
    }
    merged = {**defaults, **overrides}
    merged.setdefault(
        "fingerprint", f"fp-{repository_id}-{merged['file_path']}-{merged['line_start']}"
    )
    finding = Finding(repository_id=repository_id, **merged)
    db.add(finding)
    db.flush()
    return finding


# --- the score ------------------------------------------------------------


def test_a_repository_with_no_findings_scores_zero(
    api_client: TestClient, db_session: Session
) -> None:
    token = sign_up(api_client, "riskclean")
    repository = make_repository(api_client, db_session, token)

    body = api_client.get(f"/api/v1/repositories/{repository.id}/risk", headers=auth(token)).json()

    assert body["score"] == 0.0
    assert body["grade"] == "A"
    assert body["finding_count"] == 0


def test_the_score_comes_with_its_working(api_client: TestClient, db_session: Session) -> None:
    """The feature, not a debugging convenience. A reviewer shown only a number
    can accept it or ignore it; one shown the multiplication can disagree with a
    step, and that is how a risk model gets corrected."""
    token = sign_up(api_client, "riskwork")
    repository = make_repository(api_client, db_session, token)
    add_finding(db_session, repository.id, confidence=Confidence.MEDIUM)

    body = api_client.get(f"/api/v1/repositories/{repository.id}/risk", headers=auth(token)).json()

    top = body["top"][0]
    assert top["base"] == 40.0
    names = {factor["name"] for factor in top["factors"]}
    assert {"confidence", "application path", "age"} <= names
    assert "40 base" in top["explanation"]
    # Enough of the finding to recognise it without a second request.
    assert top["title"] == "SQL query built by string formatting"
    assert top["file_path"] == "app/users.py"


def test_every_factor_says_why_it_applied(api_client: TestClient, db_session: Session) -> None:
    token = sign_up(api_client, "riskwhy")
    repository = make_repository(api_client, db_session, token)
    add_finding(db_session, repository.id, file_path="tests/test_users.py")

    body = api_client.get(f"/api/v1/repositories/{repository.id}/risk", headers=auth(token)).json()

    reasons = {factor["name"]: factor["reason"] for factor in body["top"][0]["factors"]}
    assert reasons["test path"] == "in test or fixture code"


def test_severity_counts_exclude_fixed_findings(
    api_client: TestClient, db_session: Session
) -> None:
    token = sign_up(api_client, "riskfixed")
    repository = make_repository(api_client, db_session, token)
    add_finding(db_session, repository.id, line_start=1)
    add_finding(db_session, repository.id, line_start=2, status=FindingStatus.FIXED)

    body = api_client.get(f"/api/v1/repositories/{repository.id}/risk", headers=auth(token)).json()

    assert body["counts_by_severity"] == {"CRITICAL": 1}
    assert body["finding_count"] == 1
    assert [item["finding_id"] for item in body["top"]] != []


def test_the_top_list_is_bounded_by_the_query_parameter(
    api_client: TestClient, db_session: Session
) -> None:
    token = sign_up(api_client, "risktop")
    repository = make_repository(api_client, db_session, token)
    for line in range(1, 11):
        add_finding(db_session, repository.id, line_start=line)

    body = api_client.get(
        f"/api/v1/repositories/{repository.id}/risk?top=3", headers=auth(token)
    ).json()
    assert len(body["top"]) == 3


# --- the snapshot a scan leaves -------------------------------------------


def test_a_completed_scan_records_the_score_it_produced(
    api_client: TestClient, db_session: Session, scan_worker
) -> None:  # noqa: ANN001
    """Frozen on the row, for the same reason as the finding counts: a history
    entry has to keep the number it produced, not borrow today's."""
    token = sign_up(api_client, "risksnap")
    project_id = api_client.post(PROJECTS, json={"name": "snap"}, headers=auth(token)).json()["id"]
    upload = api_client.post(
        f"{PROJECTS}/{project_id}/repositories/upload",
        files={"file": ("risk.zip", zip_bytes(VULNERABLE), "application/zip")},
        headers=auth(token),
    )
    repository_id = upload.json()["id"]
    api_client.post(f"/api/v1/repositories/{repository_id}/scans", headers=auth(token))
    scan_worker.drain()

    from sqlalchemy import select

    stored = db_session.scalars(select(Scan).where(Scan.repository_id == repository_id)).one()

    assert stored.risk_score is not None
    assert stored.risk_score > 0
    assert stored.risk_grade in {"A", "B", "C", "D", "F"}
    assert stored.risk_policy_version == 1


def test_history_is_oldest_first_and_skips_scans_without_a_score(
    api_client: TestClient, db_session: Session
) -> None:
    """A chart reads left to right. And a pre-Phase-9 scan plotted as zero would
    invent an improvement that never happened, so it is left out instead."""
    from datetime import UTC, datetime, timedelta

    from app.models import ScanStatus

    token = sign_up(api_client, "riskhist")
    repository = make_repository(api_client, db_session, token)
    base = datetime(2026, 9, 1, tzinfo=UTC)

    # One from before this phase existed, then two with scores.
    for index, (score, grade) in enumerate([(None, None), (60.0, "D"), (30.0, "C")]):
        db_session.add(
            Scan(
                repository_id=repository.id,
                status=ScanStatus.COMPLETED,
                created_at=base + timedelta(hours=index),
                finished_at=base + timedelta(hours=index, minutes=1),
                total_findings=3,
                risk_score=score,
                risk_grade=grade,
                risk_policy_version=1 if score is not None else None,
            )
        )
    db_session.flush()

    body = api_client.get(
        f"/api/v1/repositories/{repository.id}/risk/history", headers=auth(token)
    ).json()

    assert [point["score"] for point in body["points"]] == [60.0, 30.0]
    assert [point["grade"] for point in body["points"]] == ["D", "C"]


def test_history_carries_the_policy_version_of_each_point(
    api_client: TestClient, db_session: Session
) -> None:
    """Two scores from different policies are not two points on the same line,
    and the chart needs to be able to tell."""
    from datetime import UTC, datetime

    from app.models import ScanStatus

    token = sign_up(api_client, "riskpolicy")
    repository = make_repository(api_client, db_session, token)
    db_session.add(
        Scan(
            repository_id=repository.id,
            status=ScanStatus.COMPLETED,
            finished_at=datetime(2026, 9, 1, tzinfo=UTC),
            risk_score=42.0,
            risk_grade="C",
            risk_policy_version=1,
        )
    )
    db_session.flush()

    body = api_client.get(
        f"/api/v1/repositories/{repository.id}/risk/history", headers=auth(token)
    ).json()
    assert body["points"][0]["policy_version"] == 1


# --- ownership ------------------------------------------------------------


def test_another_users_repository_has_no_risk_to_read(
    api_client: TestClient, db_session: Session
) -> None:
    """404, not 403: a 403 would confirm the repository id exists."""
    owner = sign_up(api_client, "riskowner")
    repository = make_repository(api_client, db_session, owner)
    add_finding(db_session, repository.id)

    intruder = sign_up(api_client, "riskintruder")
    response = api_client.get(f"/api/v1/repositories/{repository.id}/risk", headers=auth(intruder))
    assert response.status_code == 404


def test_risk_history_is_owner_scoped_too(api_client: TestClient, db_session: Session) -> None:
    owner = sign_up(api_client, "riskowner2")
    repository = make_repository(api_client, db_session, owner)

    intruder = sign_up(api_client, "riskintruder2")
    response = api_client.get(
        f"/api/v1/repositories/{repository.id}/risk/history", headers=auth(intruder)
    )
    assert response.status_code == 404


def test_risk_requires_authentication(api_client: TestClient, db_session: Session) -> None:
    token = sign_up(api_client, "riskanon")
    repository = make_repository(api_client, db_session, token)
    assert api_client.get(f"/api/v1/repositories/{repository.id}/risk").status_code == 401
