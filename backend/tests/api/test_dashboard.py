"""The dashboard: what it counts, and whose rows it counts.

This is the first endpoint that reads across projects, so the test that matters
most here is the one with two users in it. The rest pin down the claims the page
makes that would be easy to get plausibly wrong: that a repository nobody has
scanned is not shown as clean, that a patch is counted once by its latest
verdict, and that the totals are sums of the rows shown beneath them.
"""

import io
import zipfile
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import (
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

DASHBOARD = "/api/v1/dashboard"
PROJECTS = "/api/v1/projects"
PASSWORD = "a-long-enough-passphrase"
NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)

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


def read(client: TestClient, token: str) -> dict:
    response = client.get(DASHBOARD, headers=auth(token))
    assert response.status_code == 200, response.text
    return response.json()


def make_project(client: TestClient, token: str, name: str) -> int:
    return client.post(PROJECTS, json={"name": name}, headers=auth(token)).json()["id"]


def make_repository(db: Session, project_id: int, origin: str) -> Repository:
    repository = Repository(
        project_id=project_id,
        source=RepositorySource.UPLOAD,
        status=RepositoryStatus.READY,
        origin=origin,
        workspace_path=f"project-{project_id}/{origin}",
        file_count=1,
        total_bytes=10,
    )
    db.add(repository)
    db.flush()
    return repository


def add_scan(db: Session, repository_id: int, **overrides) -> Scan:  # noqa: ANN003
    defaults = {
        "status": ScanStatus.COMPLETED,
        "finished_at": NOW,
        "risk_score": 40.0,
        "risk_grade": "C",
        "risk_policy_version": 1,
        "total_findings": 1,
    }
    scan = Scan(repository_id=repository_id, **{**defaults, **overrides})
    db.add(scan)
    db.flush()
    return scan


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
) -> Patch:
    """A patch and its validations, oldest first — the last one is the latest."""
    patch = Patch(finding_id=finding.id, status=status)
    db.add(patch)
    db.flush()
    for offset, verdict in enumerate(verdicts):
        db.add(
            PatchValidation(
                patch_id=patch.id,
                status=verdict,
                created_at=NOW + timedelta(minutes=offset),
            )
        )
    db.flush()
    return patch


# --- an empty account -------------------------------------------------------


def test_an_empty_account_gets_zeros_not_examples(api_client: TestClient) -> None:
    """No sample data. Nothing scanned means nothing to show, and the response
    says exactly that — every severity present as zero, every list empty."""
    body = read(api_client, sign_up(api_client, "dashempty"))

    assert body["totals"] == {
        "projects": 0,
        "repositories": 0,
        "repositories_scanned": 0,
        "scans_completed": 0,
        "open_findings": 0,
        "fixed_findings": 0,
    }
    assert body["open_by_severity"] == {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }
    assert body["repositories"] == []
    assert body["top_findings"] == []
    assert body["weaknesses"] == []
    assert body["fixes"]["requested"] == 0
    assert body["fixes"]["labelled"] == 0


def test_the_dashboard_requires_a_signed_in_user(api_client: TestClient) -> None:
    assert api_client.get(DASHBOARD).status_code == 401


# --- ownership --------------------------------------------------------------


def test_nothing_belonging_to_another_user_is_counted_or_listed(
    api_client: TestClient, db_session: Session
) -> None:
    """Every section, not just the first. The endpoint takes no id, so the only
    way to leak is a query that forgot its join — and there are five of them."""
    mine = sign_up(api_client, "dashmine")
    theirs = sign_up(api_client, "dashtheirs")

    their_repository = make_repository(
        db_session, make_project(api_client, theirs, "theirs"), "theirs.zip"
    )
    add_scan(db_session, their_repository.id)
    their_finding = add_finding(db_session, their_repository.id)
    add_patch(db_session, their_finding, PatchStatus.PROPOSED, PatchValidationStatus.PASSED)

    body = read(api_client, mine)

    assert body["totals"] == {
        "projects": 0,
        "repositories": 0,
        "repositories_scanned": 0,
        "scans_completed": 0,
        "open_findings": 0,
        "fixed_findings": 0,
    }
    assert sum(body["open_by_severity"].values()) == 0
    assert body["repositories"] == []
    assert body["top_findings"] == []
    assert body["weaknesses"] == []
    assert body["fixes"]["requested"] == 0
    assert body["fixes"]["passed"] == 0

    # And the owner does see it, so the assertions above are not vacuous.
    their_view = read(api_client, theirs)
    assert their_view["totals"]["open_findings"] == 1
    assert their_view["fixes"]["passed"] == 1
    assert their_view["top_findings"][0]["finding_id"] == their_finding.id


# --- repositories -----------------------------------------------------------


def test_a_repository_that_was_never_scanned_has_no_score(
    api_client: TestClient, db_session: Session
) -> None:
    """Not zero and not an A. "Nothing found" and "never looked" are different
    facts, and a page that drew them the same would reward not scanning."""
    token = sign_up(api_client, "dashunscanned")
    project_id = make_project(api_client, token, "unscanned")
    make_repository(db_session, project_id, "never.zip")
    clean = make_repository(db_session, project_id, "clean.zip")
    add_scan(db_session, clean.id, risk_score=0.0, risk_grade="A", total_findings=0)

    body = read(api_client, token)
    by_origin = {item["origin"]: item for item in body["repositories"]}

    assert by_origin["never.zip"]["score"] is None
    assert by_origin["never.zip"]["grade"] is None
    assert by_origin["never.zip"]["last_scan_at"] is None
    assert by_origin["clean.zip"]["score"] == 0.0
    assert by_origin["clean.zip"]["grade"] == "A"
    assert body["totals"]["repositories"] == 2
    assert body["totals"]["repositories_scanned"] == 1


def test_repositories_are_listed_worst_first_with_unscanned_last(
    api_client: TestClient, db_session: Session
) -> None:
    token = sign_up(api_client, "dashorder")
    project_id = make_project(api_client, token, "order")
    # Created in an order that is neither the answer nor its reverse.
    never = make_repository(db_session, project_id, "never.zip")
    mild = make_repository(db_session, project_id, "mild.zip")
    severe = make_repository(db_session, project_id, "severe.zip")
    # Scanned and clean, and created after `never`: a score of zero must still
    # rank above no score at all.
    clean = make_repository(db_session, project_id, "clean.zip")
    add_scan(db_session, mild.id)
    add_scan(db_session, severe.id)
    add_scan(db_session, clean.id, risk_score=0.0, risk_grade="A", total_findings=0)
    add_finding(db_session, mild.id, severity=Severity.LOW)
    add_finding(db_session, severe.id, severity=Severity.CRITICAL)

    body = read(api_client, token)

    assert [item["origin"] for item in body["repositories"]] == [
        "severe.zip",
        "mild.zip",
        "clean.zip",
        "never.zip",
    ]
    assert body["repositories"][0]["score"] > body["repositories"][1]["score"] > 0
    assert body["repositories"][2]["score"] == 0.0
    assert body["repositories"][3]["repository_id"] == never.id


def test_the_current_score_matches_the_repository_page(
    api_client: TestClient, db_session: Session
) -> None:
    """Two pages showing two different numbers for the same repository is the
    fastest way to make both distrusted."""
    token = sign_up(api_client, "dashsame")
    repository = make_repository(db_session, make_project(api_client, token, "same"), "same.zip")
    add_scan(db_session, repository.id)
    add_finding(db_session, repository.id, severity=Severity.CRITICAL)
    add_finding(db_session, repository.id, severity=Severity.MEDIUM, line_start=40)
    add_finding(db_session, repository.id, severity=Severity.HIGH, file_path="tests/test_a.py")

    listed = read(api_client, token)["repositories"][0]
    page = api_client.get(f"/api/v1/repositories/{repository.id}/risk", headers=auth(token)).json()

    assert listed["score"] == page["score"]
    assert listed["grade"] == page["grade"]
    assert listed["score"] > 0


def test_the_trend_is_what_each_scan_recorded_oldest_first(
    api_client: TestClient, db_session: Session
) -> None:
    token = sign_up(api_client, "dashtrend")
    repository = make_repository(db_session, make_project(api_client, token, "trend"), "t.zip")
    # Inserted newest first, so insertion order cannot be what sorts them.
    add_scan(db_session, repository.id, finished_at=NOW, risk_score=10.0, risk_grade="A")
    add_scan(
        db_session,
        repository.id,
        finished_at=NOW - timedelta(days=2),
        risk_score=70.0,
        risk_grade="D",
    )
    # A scan from before scores existed: skipped, never drawn as zero.
    add_scan(
        db_session,
        repository.id,
        finished_at=NOW - timedelta(days=1),
        risk_score=None,
        risk_grade=None,
    )
    # A scan that did not finish is not a point at all.
    add_scan(db_session, repository.id, status=ScanStatus.FAILED, risk_score=None, risk_grade=None)

    body = read(api_client, token)
    listed = body["repositories"][0]

    assert [point["score"] for point in listed["trend"]] == [70.0, 10.0]
    assert [point["grade"] for point in listed["trend"]] == ["D", "A"]
    # Compared as an instant, not as text: the database hands a timestamp back
    # in its session's time zone, so the same moment is "12:00+00:00" on one
    # machine and "17:30+05:30" on another.
    assert datetime.fromisoformat(listed["last_scan_at"]) == NOW
    assert body["totals"]["scans_completed"] == 3


def test_the_trend_keeps_only_the_most_recent_scans(
    api_client: TestClient, db_session: Session
) -> None:
    token = sign_up(api_client, "dashlong")
    repository = make_repository(db_session, make_project(api_client, token, "long"), "l.zip")
    for day in range(15):
        add_scan(
            db_session,
            repository.id,
            finished_at=NOW - timedelta(days=15 - day),
            risk_score=float(day),
        )

    trend = read(api_client, token)["repositories"][0]["trend"]

    assert [point["score"] for point in trend] == [float(day) for day in range(3, 15)]


# --- findings ---------------------------------------------------------------


def test_fixed_findings_are_counted_as_fixed_and_nowhere_else(
    api_client: TestClient, db_session: Session
) -> None:
    token = sign_up(api_client, "dashfixed")
    repository = make_repository(db_session, make_project(api_client, token, "fixed"), "f.zip")
    add_scan(db_session, repository.id)
    add_finding(db_session, repository.id, severity=Severity.HIGH, status=FindingStatus.NEW)
    add_finding(
        db_session,
        repository.id,
        severity=Severity.CRITICAL,
        status=FindingStatus.FIXED,
        line_start=90,
        cwe_id="CWE-78",
    )

    body = read(api_client, token)

    assert body["totals"]["open_findings"] == 1
    assert body["totals"]["fixed_findings"] == 1
    assert body["open_by_severity"]["CRITICAL"] == 0
    assert body["open_by_severity"]["HIGH"] == 1
    assert [item["severity"] for item in body["top_findings"]] == ["HIGH"]
    assert [item["cwe_id"] for item in body["weaknesses"]] == ["CWE-89"]
    assert body["repositories"][0]["open_findings"] == 1
    assert body["repositories"][0]["fixed_findings"] == 1


def test_the_totals_are_the_sum_of_the_rows_beneath_them(
    api_client: TestClient, db_session: Session
) -> None:
    token = sign_up(api_client, "dashsum")
    first = make_repository(db_session, make_project(api_client, token, "one"), "one.zip")
    second = make_repository(db_session, make_project(api_client, token, "two"), "two.zip")
    add_scan(db_session, first.id)
    add_scan(db_session, second.id)
    add_finding(db_session, first.id, severity=Severity.CRITICAL)
    add_finding(db_session, first.id, severity=Severity.INFO, line_start=3)
    add_finding(db_session, second.id, severity=Severity.MEDIUM)
    add_finding(db_session, second.id, severity=Severity.MEDIUM, line_start=9)

    body = read(api_client, token)

    assert body["totals"]["projects"] == 2
    assert body["totals"]["open_findings"] == 4
    assert sum(item["open_findings"] for item in body["repositories"]) == 4
    assert sum(body["open_by_severity"].values()) == 4
    assert body["open_by_severity"] == {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 2, "LOW": 0, "INFO": 1}
    for item in body["repositories"]:
        assert sum(item["counts_by_severity"].values()) == item["open_findings"]
        assert list(item["counts_by_severity"]) == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def test_top_findings_rank_across_repositories_and_say_where_they_are(
    api_client: TestClient, db_session: Session
) -> None:
    token = sign_up(api_client, "dashtop")
    alpha = make_repository(db_session, make_project(api_client, token, "alpha"), "alpha.zip")
    beta = make_repository(db_session, make_project(api_client, token, "beta"), "beta.zip")
    add_scan(db_session, alpha.id)
    add_scan(db_session, beta.id)
    low = add_finding(db_session, alpha.id, severity=Severity.LOW)
    worst = add_finding(db_session, beta.id, severity=Severity.CRITICAL)
    # Same severity as `worst`, discounted for sitting in test code.
    discounted = add_finding(
        db_session, alpha.id, severity=Severity.CRITICAL, file_path="tests/test_users.py"
    )

    top = read(api_client, token)["top_findings"]

    assert [item["finding_id"] for item in top] == [worst.id, discounted.id, low.id]
    assert top[0]["project_name"] == "beta"
    assert top[0]["origin"] == "beta.zip"
    assert top[0]["repository_id"] == beta.id
    assert top[0]["score"] > top[1]["score"] > top[2]["score"]
    assert "40 base" in top[0]["explanation"]


def test_top_findings_are_capped(api_client: TestClient, db_session: Session) -> None:
    token = sign_up(api_client, "dashcap")
    repository = make_repository(db_session, make_project(api_client, token, "cap"), "cap.zip")
    add_scan(db_session, repository.id)
    for line in range(1, 12):
        add_finding(db_session, repository.id, line_start=line)

    body = read(api_client, token)

    assert len(body["top_findings"]) == 8
    assert body["totals"]["open_findings"] == 11


def test_weaknesses_are_grouped_by_cwe_commonest_first(
    api_client: TestClient, db_session: Session
) -> None:
    token = sign_up(api_client, "dashcwe")
    repository = make_repository(db_session, make_project(api_client, token, "cwe"), "cwe.zip")
    add_scan(db_session, repository.id)
    weak_hash = {
        "rule_id": "PY030",
        "title": "Weak hash function",
        "cwe_id": "CWE-327",
        "owasp_category": "A02:2021 Cryptographic Failures",
    }
    add_finding(db_session, repository.id, severity=Severity.MEDIUM, line_start=1, **weak_hash)
    add_finding(db_session, repository.id, severity=Severity.HIGH, line_start=2, **weak_hash)
    add_finding(db_session, repository.id, severity=Severity.LOW, line_start=3, **weak_hash)
    add_finding(db_session, repository.id, severity=Severity.CRITICAL)

    weaknesses = read(api_client, token)["weaknesses"]

    assert weaknesses == [
        {
            "cwe_id": "CWE-327",
            "owasp_category": "A02:2021 Cryptographic Failures",
            "title": "Weak hash function",
            "count": 3,
            "worst_severity": "HIGH",
        },
        {
            "cwe_id": "CWE-89",
            "owasp_category": "A03:2021 Injection",
            "title": "SQL query built by string formatting",
            "count": 1,
            "worst_severity": "CRITICAL",
        },
    ]


# --- the fix pipeline -------------------------------------------------------


def test_every_patch_is_counted_once_by_its_latest_verdict(
    api_client: TestClient, db_session: Session
) -> None:
    """A proposal rejected and later passed is one passed proposal. Counting
    validations instead of patches would report it as one of each, and the
    number of labelled examples would be larger than the number of patches."""
    token = sign_up(api_client, "dashfixes")
    repository = make_repository(db_session, make_project(api_client, token, "fixes"), "p.zip")
    finding = add_finding(db_session, repository.id)
    verdict = PatchValidationStatus

    add_patch(db_session, finding, PatchStatus.QUEUED)
    add_patch(db_session, finding, PatchStatus.RUNNING)
    add_patch(db_session, finding, PatchStatus.FAILED)
    add_patch(db_session, finding, PatchStatus.PROPOSED)  # predates validation
    add_patch(db_session, finding, PatchStatus.PROPOSED, verdict.QUEUED)
    add_patch(db_session, finding, PatchStatus.PROPOSED, verdict.PASSED)
    add_patch(db_session, finding, PatchStatus.PROPOSED, verdict.REJECTED, verdict.PASSED)
    add_patch(db_session, finding, PatchStatus.PROPOSED, verdict.PASSED, verdict.REJECTED)
    add_patch(db_session, finding, PatchStatus.PROPOSED, verdict.REJECTED, verdict.FAILED)
    add_patch(db_session, finding, PatchStatus.PROPOSED, verdict.PASSED, verdict.RUNNING)

    fixes = read(api_client, token)["fixes"]

    assert fixes == {
        "requested": 10,
        "generating": 2,
        "refused": 1,
        "proposed": 7,
        "passed": 2,
        "rejected": 1,
        "not_judged": 1,
        "checking": 2,
        "unchecked": 1,
        "labelled": 3,
    }
    assert fixes["requested"] == fixes["generating"] + fixes["refused"] + fixes["proposed"]
    assert fixes["proposed"] == (
        fixes["passed"]
        + fixes["rejected"]
        + fixes["not_judged"]
        + fixes["checking"]
        + fixes["unchecked"]
    )


def test_a_check_that_could_not_run_is_never_a_label(
    api_client: TestClient, db_session: Session
) -> None:
    """FAILED means the stored code had moved, which says nothing about the
    change. Counting it as a verdict would train a classifier on noise."""
    token = sign_up(api_client, "dashlabel")
    repository = make_repository(db_session, make_project(api_client, token, "label"), "l.zip")
    finding = add_finding(db_session, repository.id)
    add_patch(db_session, finding, PatchStatus.PROPOSED, PatchValidationStatus.FAILED)

    fixes = read(api_client, token)["fixes"]

    assert fixes["not_judged"] == 1
    assert fixes["labelled"] == 0


# --- end to end -------------------------------------------------------------


def test_a_real_scan_shows_up_on_the_dashboard(
    api_client: TestClient, db_session: Session, scan_worker
) -> None:  # noqa: ANN001
    """Everything above builds rows by hand. This one uploads code and scans it,
    so the dashboard is checked against what the pipeline actually writes."""
    token = sign_up(api_client, "dashreal")
    project_id = make_project(api_client, token, "real")
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

    body = read(api_client, token)
    page = api_client.get(f"/api/v1/repositories/{repository_id}/risk", headers=auth(token)).json()
    listed = body["repositories"][0]

    assert body["totals"]["scans_completed"] == 1
    assert body["totals"]["open_findings"] == page["finding_count"] >= 3
    assert listed["repository_id"] == repository_id
    assert listed["score"] == page["score"] > 0
    assert len(listed["trend"]) == 1
    assert listed["trend"][0]["score"] == page["score"]
    assert body["top_findings"][0]["file_path"] == "app/main.py"
    assert {item["cwe_id"] for item in body["weaknesses"]} >= {"CWE-89", "CWE-78"}
