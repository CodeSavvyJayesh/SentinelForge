"""Reports through the API: who can have one, what is in it, and what is not.

The renderers are tested on their own in ``tests/unit/test_reports.py``. What
only these tests can show is the part around them: that a report cannot be had
for somebody else's repository or for one nobody has scanned, that every format
describes the same findings as the rest of the API, that taking one leaves a
record, and that a secret in the scanned code is in none of them.
"""

import io
import json
import zipfile
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import (
    AuditAction,
    AuditLog,
    Confidence,
    Finding,
    FindingStatus,
    Patch,
    PatchStatus,
    PatchValidation,
    PatchValidationStatus,
    Repository,
    RepositorySource,
    RepositoryStatus,
    Scan,
    ScanStatus,
    Severity,
)

pytestmark = pytest.mark.integration

PROJECTS = "/api/v1/projects"
PASSWORD = "a-long-enough-passphrase"
NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
FORMATS = ("json", "markdown", "html", "sarif")
# Invented for this test. Never a value from a real project.
SECRET = "s3cr3t_value_42"

VULNERABLE = {
    "app/main.py": (
        b"import os\nimport hashlib\n\n\n"
        b"def handle(command, cursor, user_id):\n"
        b"    os.system(command)\n"
        b'    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
        b"    return hashlib.md5(command.encode()).hexdigest()\n"
    ),
    ".env": f"PORT=3000\nJWT_SECRET={SECRET}\n".encode(),
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


def report_url(repository_id: int) -> str:
    return f"/api/v1/repositories/{repository_id}/report"


def export_url(repository_id: int, export_format: str, *, download: bool = False) -> str:
    suffix = "&download=true" if download else ""
    return f"{report_url(repository_id)}/export?format={export_format}{suffix}"


def make_repository(
    client: TestClient, db: Session, token: str, *, scanned: bool = True, name: str = "reports"
) -> Repository:
    project_id = client.post(PROJECTS, json={"name": name}, headers=auth(token)).json()["id"]
    repository = Repository(
        project_id=project_id,
        source=RepositorySource.UPLOAD,
        status=RepositoryStatus.READY,
        origin="payments.zip",
        workspace_path=f"project-{project_id}/repo-report",
        file_count=1,
        total_bytes=10,
    )
    db.add(repository)
    db.flush()
    if scanned:
        db.add(
            Scan(
                repository_id=repository.id,
                status=ScanStatus.COMPLETED,
                finished_at=NOW,
                files_scanned=4,
                total_findings=1,
            )
        )
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
        "fingerprint",
        f"fp-{repository_id}-{merged['rule_id']}-{merged['file_path']}-{merged['line_start']}",
    )
    finding = Finding(repository_id=repository_id, **merged)
    db.add(finding)
    db.flush()
    return finding


def add_patch(
    db: Session,
    finding: Finding,
    status: PatchStatus,
    *verdicts: PatchValidationStatus,
    minutes: int = 0,
) -> Patch:
    """A patch and its validations, oldest first — the last one is the latest."""
    patch = Patch(finding_id=finding.id, status=status, created_at=NOW + timedelta(minutes=minutes))
    db.add(patch)
    db.flush()
    for offset, verdict in enumerate(verdicts):
        db.add(
            PatchValidation(
                patch_id=patch.id, status=verdict, created_at=NOW + timedelta(minutes=offset)
            )
        )
    db.flush()
    return patch


def exports(db: Session) -> int:
    return db.scalar(
        select(func.count())
        .select_from(AuditLog)
        .where(AuditLog.action == str(AuditAction.REPORT_EXPORTED))
    )


# --- who can have one -------------------------------------------------------


def test_a_report_requires_a_signed_in_user(api_client: TestClient) -> None:
    assert api_client.get(report_url(1)).status_code == 401
    assert api_client.get(export_url(1, "markdown")).status_code == 401
    assert api_client.get(export_url(1, "html", download=True)).status_code == 401


def test_someone_elses_repository_has_no_report_and_leaves_no_record(
    api_client: TestClient, db_session: Session
) -> None:
    owner = sign_up(api_client, "reportowner")
    other = sign_up(api_client, "reportother")
    repository = make_repository(api_client, db_session, owner)
    add_finding(db_session, repository.id)
    before = exports(db_session)

    responses = [api_client.get(report_url(repository.id), headers=auth(other))]
    responses += [
        api_client.get(export_url(repository.id, export_format), headers=auth(other))
        for export_format in FORMATS
    ]
    responses.append(
        api_client.get(export_url(repository.id, "sarif", download=True), headers=auth(other))
    )

    for response in responses:
        # 404, not 403: whether the repository exists is not theirs to learn.
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "REPOSITORY_NOT_FOUND"
        assert "SQL query" not in response.text
    assert exports(db_session) == before
    # And the owner can, so the refusals above are about ownership.
    assert api_client.get(report_url(repository.id), headers=auth(owner)).status_code == 200


def test_a_repository_that_was_never_scanned_has_no_report(
    api_client: TestClient, db_session: Session
) -> None:
    """Refused, not answered with "0 findings": forwarded to somebody, an empty
    report about code nobody analysed reads as a clean bill of health."""
    token = sign_up(api_client, "reportunscanned")
    repository = make_repository(api_client, db_session, token, scanned=False)

    for url in (report_url(repository.id), export_url(repository.id, "html")):
        response = api_client.get(url, headers=auth(token))
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "REPORT_NOT_AVAILABLE"


def test_a_scan_that_did_not_complete_does_not_count(
    api_client: TestClient, db_session: Session
) -> None:
    token = sign_up(api_client, "reportfailed")
    repository = make_repository(api_client, db_session, token, scanned=False)
    db_session.add(Scan(repository_id=repository.id, status=ScanStatus.FAILED, finished_at=NOW))
    db_session.add(Scan(repository_id=repository.id, status=ScanStatus.RUNNING))
    db_session.flush()

    assert api_client.get(report_url(repository.id), headers=auth(token)).status_code == 409


def test_an_unknown_format_is_refused_rather_than_guessed(
    api_client: TestClient, db_session: Session
) -> None:
    token = sign_up(api_client, "reportformat")
    repository = make_repository(api_client, db_session, token)

    response = api_client.get(export_url(repository.id, "pdf"), headers=auth(token))

    assert response.status_code == 422
    assert exports(db_session) == 0


# --- what is in it ----------------------------------------------------------


def test_the_report_agrees_with_the_rest_of_the_api(
    api_client: TestClient, db_session: Session
) -> None:
    """Same score as the risk endpoint, same findings as the findings list. A
    report that disagreed with the screen it was exported from would be the
    less believed of the two."""
    token = sign_up(api_client, "reportagree")
    repository = make_repository(api_client, db_session, token, name="Payments")
    add_finding(db_session, repository.id)
    add_finding(db_session, repository.id, severity=Severity.MEDIUM, line_start=40,
                status=FindingStatus.NEW)  # fmt: skip
    add_finding(db_session, repository.id, severity=Severity.HIGH, line_start=90,
                status=FindingStatus.FIXED)  # fmt: skip

    body = api_client.get(report_url(repository.id), headers=auth(token)).json()
    risk = api_client.get(f"/api/v1/repositories/{repository.id}/risk", headers=auth(token)).json()

    assert body["score"] == risk["score"] > 0
    assert body["grade"] == risk["grade"]
    assert body["policy_version"] == risk["policy_version"]
    assert (body["open_count"], body["new_count"], body["fixed_count"]) == (2, 1, 1)
    assert body["counts_by_severity"] == {
        "CRITICAL": 1, "HIGH": 0, "MEDIUM": 1, "LOW": 0, "INFO": 0,
    }  # fmt: skip
    assert [item["severity"] for item in body["findings"]] == ["CRITICAL", "MEDIUM"]
    assert [item["line_start"] for item in body["fixed"]] == [90]
    assert body["project_name"] == "Payments"
    assert body["origin"] == "payments.zip"
    assert body["scan"]["files_scanned"] == 4
    assert body["rules"][0]["rule_id"] == "PY010"
    assert body["rules"][0]["count"] == 2
    assert body["rules"][0]["fix_note"]
    assert len(body["limitations"]) >= 4


@pytest.mark.parametrize(
    ("export_format", "extension", "media_type"),
    [
        ("json", "json", "application/json"),
        ("markdown", "md", "text/markdown; charset=utf-8"),
        ("html", "html", "text/html; charset=utf-8"),
        ("sarif", "sarif", "application/sarif+json"),
    ],
)
def test_each_format_is_an_envelope_with_a_name_a_type_and_the_document(
    api_client: TestClient, db_session: Session, export_format: str, extension: str, media_type: str
) -> None:
    token = sign_up(api_client, f"reportfmt{export_format}")
    repository = make_repository(api_client, db_session, token)
    add_finding(db_session, repository.id)

    response = api_client.get(export_url(repository.id, export_format), headers=auth(token))
    body = response.json()

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert body["format"] == export_format
    assert body["media_type"] == media_type
    assert body["filename"].startswith("sentinelforge-payments-")
    assert body["filename"].endswith(f".{extension}")
    assert "SQL query built by string formatting" in body["content"]


def test_markdown_is_the_default_format(api_client: TestClient, db_session: Session) -> None:
    token = sign_up(api_client, "reportdefault")
    repository = make_repository(api_client, db_session, token)

    body = api_client.get(f"{report_url(repository.id)}/export", headers=auth(token)).json()

    assert body["format"] == "markdown"
    assert body["content"].startswith("# Security report: ")


def test_every_format_lists_the_same_open_findings(
    api_client: TestClient, db_session: Session
) -> None:
    token = sign_up(api_client, "reportsame")
    repository = make_repository(api_client, db_session, token)
    add_finding(db_session, repository.id, file_path="app/alpha.py", line_start=11)
    add_finding(db_session, repository.id, file_path="app/beta.py", line_start=22,
                severity=Severity.LOW)  # fmt: skip
    add_finding(db_session, repository.id, file_path="app/gone.py", line_start=33,
                status=FindingStatus.FIXED)  # fmt: skip

    def content(export_format: str) -> str:
        return api_client.get(export_url(repository.id, export_format), headers=auth(token)).json()[
            "content"
        ]

    sarif = json.loads(content("sarif"))
    as_json = json.loads(content("json"))

    locations = [
        result["locations"][0]["physicalLocation"] for result in sarif["runs"][0]["results"]
    ]
    assert [
        (item["artifactLocation"]["uri"], item["region"]["startLine"]) for item in locations
    ] == [
        ("app/alpha.py", 11),
        ("app/beta.py", 22),
    ]
    assert [(item["file_path"], item["line_start"]) for item in as_json["findings"]] == [
        ("app/alpha.py", 11),
        ("app/beta.py", 22),
    ]
    for export_format in ("markdown", "html"):
        document = content(export_format)
        assert document.index("app/alpha.py:11") < document.index("app/beta.py:22")
        assert "app/gone.py:33" in document  # listed, under fixed findings


def test_a_fix_is_reported_by_the_latest_check_of_the_latest_patch(
    api_client: TestClient, db_session: Session
) -> None:
    token = sign_up(api_client, "reportfix")
    repository = make_repository(api_client, db_session, token)
    verdict = PatchValidationStatus
    first = add_finding(db_session, repository.id, line_start=1)
    second = add_finding(db_session, repository.id, line_start=2)
    third = add_finding(db_session, repository.id, line_start=3)
    untouched = add_finding(db_session, repository.id, line_start=4)
    # Rejected, then re-checked and passed: passed.
    add_patch(db_session, first, PatchStatus.PROPOSED, verdict.REJECTED, verdict.PASSED)
    # An older patch passed; a newer one was refused: refused.
    add_patch(db_session, second, PatchStatus.PROPOSED, verdict.PASSED)
    add_patch(db_session, second, PatchStatus.FAILED, minutes=5)
    # A check that could not run is not a rejection.
    add_patch(db_session, third, PatchStatus.PROPOSED, verdict.PASSED, verdict.FAILED)

    body = api_client.get(report_url(repository.id), headers=auth(token)).json()
    states = {item["id"]: item["fix_state"] for item in body["findings"]}

    assert states == {
        first.id: "passed",
        second.id: "refused",
        third.id: "not_judged",
        untouched.id: "none",
    }
    labels = {item["id"]: item["fix_label"] for item in body["findings"]}
    assert "not been applied" in labels[first.id]


def test_another_repositorys_patches_do_not_leak_into_this_report(
    api_client: TestClient, db_session: Session
) -> None:
    token = sign_up(api_client, "reportscope")
    mine = make_repository(api_client, db_session, token, name="mine")
    other = make_repository(api_client, db_session, token, name="other")
    add_finding(db_session, mine.id)
    theirs = add_finding(db_session, other.id)
    add_patch(db_session, theirs, PatchStatus.PROPOSED, PatchValidationStatus.PASSED)

    body = api_client.get(report_url(mine.id), headers=auth(token)).json()

    assert [item["fix_state"] for item in body["findings"]] == ["none"]
    assert len(body["findings"]) == 1


def test_only_this_repositorys_patches_are_read_at_all(
    api_client: TestClient, db_session: Session
) -> None:
    """The report could not show another repository's patch even if it were
    loaded — it looks patches up by its own findings. This is about not reading
    other people's rows into memory in the first place."""
    from app.repositories.report_repository import ReportRepository

    token = sign_up(api_client, "reportrows")
    mine = make_repository(api_client, db_session, token, name="mine")
    other = make_repository(api_client, db_session, sign_up(api_client, "reportrows2"))
    my_finding = add_finding(db_session, mine.id)
    their_finding = add_finding(db_session, other.id)
    add_patch(db_session, my_finding, PatchStatus.PROPOSED, PatchValidationStatus.REJECTED)
    add_patch(db_session, their_finding, PatchStatus.PROPOSED, PatchValidationStatus.PASSED)

    states = ReportRepository(db_session).patch_states(mine.id)

    assert states == {my_finding.id: (PatchStatus.PROPOSED, PatchValidationStatus.REJECTED)}


# --- the file itself --------------------------------------------------------


@pytest.mark.parametrize("export_format", FORMATS)
def test_a_download_is_the_same_document_served_as_a_file(
    api_client: TestClient, db_session: Session, export_format: str
) -> None:
    token = sign_up(api_client, f"reportdl{export_format}")
    repository = make_repository(api_client, db_session, token)
    add_finding(db_session, repository.id)

    envelope = api_client.get(export_url(repository.id, export_format), headers=auth(token)).json()
    download = api_client.get(
        export_url(repository.id, export_format, download=True), headers=auth(token)
    )

    assert download.status_code == 200
    assert download.headers["content-type"] == envelope["media_type"]
    assert download.headers["content-disposition"] == (
        f'attachment; filename="{envelope["filename"]}"'
    )
    assert download.headers["cache-control"] == "no-store"
    assert download.headers["x-content-type-options"] == "nosniff"

    # Identical apart from the moment each was generated.
    def without_time(document: str) -> list[str]:
        return [
            line for line in document.splitlines()
            if "Generated" not in line and "generated_at" not in line and " = " not in line
        ]  # fmt: skip

    assert without_time(download.text) == without_time(envelope["content"])


def test_downloaded_html_is_an_attachment_under_a_sandbox_never_a_page(
    api_client: TestClient, db_session: Session
) -> None:
    """User-influenced markup served by the API must not render on the API's
    origin. Two locks: it is a download, and if a browser shows it anyway the
    sandbox gives it a unique origin and no scripts."""
    token = sign_up(api_client, "reportsandbox")
    repository = make_repository(api_client, db_session, token)
    add_finding(db_session, repository.id, title="<script>alert(1)</script>")

    response = api_client.get(export_url(repository.id, "html", download=True), headers=auth(token))

    assert response.headers["content-disposition"].startswith("attachment;")
    policy = response.headers["content-security-policy"]
    assert policy.startswith("sandbox;")
    assert "default-src 'none'" in policy
    assert "<script" not in response.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in response.text


def test_a_hostile_repository_name_cannot_reach_the_response_headers(
    api_client: TestClient, db_session: Session
) -> None:
    token = sign_up(api_client, "reportheader")
    repository = make_repository(api_client, db_session, token)
    repository.origin = 'evil".zip\r\nSet-Cookie: stolen=1'
    db_session.flush()

    response = api_client.get(
        export_url(repository.id, "markdown", download=True), headers=auth(token)
    )

    assert response.status_code == 200
    assert "set-cookie" not in response.headers
    assert response.headers["content-disposition"].count('"') == 2
    assert "\r" not in response.headers["content-disposition"]


# --- the record -------------------------------------------------------------


def test_taking_a_report_is_recorded_with_who_what_and_which_format(
    api_client: TestClient, db_session: Session
) -> None:
    token = sign_up(api_client, "reportaudit")
    repository = make_repository(api_client, db_session, token)
    add_finding(db_session, repository.id)

    api_client.get(export_url(repository.id, "sarif"), headers=auth(token))
    api_client.get(export_url(repository.id, "html", download=True), headers=auth(token))

    entries = list(
        db_session.scalars(
            select(AuditLog)
            .where(AuditLog.action == str(AuditAction.REPORT_EXPORTED))
            .order_by(AuditLog.id)
        )
    )
    assert [entry.details["format"] for entry in entries] == ["sarif", "html"]
    assert {entry.entity_type for entry in entries} == {"repository"}
    assert {entry.entity_id for entry in entries} == {str(repository.id)}
    assert all(entry.user_id is not None for entry in entries)
    assert entries[0].details["open_findings"] == 1
    # Counts and ids only: the record of an export is not a copy of the report.
    assert "SQL" not in json.dumps([entry.details for entry in entries])


def test_the_audit_record_is_committed_not_just_flushed(
    api_client: TestClient, db_session: Session
) -> None:
    """A GET that writes is unusual, and easy to leave uncommitted: the row
    would be rolled back with the request and the shared-session fixture would
    never show it."""
    token = sign_up(api_client, "reportcommit")
    repository = make_repository(api_client, db_session, token)
    commits: list[int] = []
    original = db_session.commit
    db_session.commit = lambda: (commits.append(1), original())[1]  # type: ignore[method-assign]
    try:
        api_client.get(export_url(repository.id, "markdown"), headers=auth(token))
    finally:
        db_session.commit = original  # type: ignore[method-assign]

    assert commits, "the export was returned without committing its audit record"


def test_reading_the_report_as_data_is_a_read_and_writes_nothing(
    api_client: TestClient, db_session: Session
) -> None:
    token = sign_up(api_client, "reportread")
    repository = make_repository(api_client, db_session, token)

    assert api_client.get(report_url(repository.id), headers=auth(token)).status_code == 200
    assert exports(db_session) == 0


# --- end to end -------------------------------------------------------------


def test_a_real_scan_produces_a_report_in_every_format_with_no_secret_in_any(
    api_client: TestClient, db_session: Session, scan_worker
) -> None:  # noqa: ANN001
    """Everything above builds rows by hand. This uploads code with a secret in
    it and scans it, so the report is checked against what the pipeline writes."""
    token = sign_up(api_client, "reportreal")
    project_id = api_client.post(PROJECTS, json={"name": "real"}, headers=auth(token)).json()["id"]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in VULNERABLE.items():
            archive.writestr(name, content)
    upload = api_client.post(
        f"{PROJECTS}/{project_id}/repositories/upload",
        files={"file": ("real.zip", buffer.getvalue(), "application/zip")},
        headers=auth(token),
    )
    repository_id = upload.json()["id"]
    api_client.post(f"/api/v1/repositories/{repository_id}/scans", headers=auth(token))
    scan_worker.drain()

    body = api_client.get(report_url(repository_id), headers=auth(token)).json()
    documents = {
        export_format: api_client.get(
            export_url(repository_id, export_format), headers=auth(token)
        ).json()["content"]
        for export_format in FORMATS
    }

    credential = next(item for item in body["findings"] if item["is_credential"])
    assert credential["fix_state"] == "rotate"
    assert body["open_count"] == len(body["findings"]) >= 4
    assert {rule["rule_id"] for rule in body["rules"]} >= {"PY010", "PY007"}
    # Every rule the analyser has carries this project's own note.
    assert all(rule["fix_note"] and rule["risk_note"] for rule in body["rules"])
    for export_format, document in documents.items():
        assert SECRET not in document, export_format
        assert "app/main.py" in document, export_format
    sarif = json.loads(documents["sarif"])
    assert len(sarif["runs"][0]["results"]) == body["open_count"]
    assert "Rotate this credential" in documents["markdown"]
    assert "Rotate this credential" in documents["html"]
