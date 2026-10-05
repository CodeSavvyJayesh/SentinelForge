"""The classifier's data: which rows are examples, and how more are asked for.

The arithmetic is tested without a database in ``tests/unit/test_learning.py``.
What needs real rows is everything about *which* rows: that a fix nobody could
judge is not a rejection, that the latest check is the verdict, that asking for
more fixes goes through the same queue as a click in the browser, and that the
command refuses — and writes nothing — when there is too little to learn from.
"""

import io
import json
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.learning import collection, crossval
from app.learning.commands import (
    EXIT_ERROR,
    EXIT_NOT_ENOUGH,
    EXIT_OK,
    collect_command,
    train_command,
)
from app.learning.dataset import collect
from app.models import (
    AuditLog,
    Explanation,
    ExplanationStatus,
    Finding,
    FindingStatus,
    Patch,
    PatchStatus,
    PatchValidation,
    PatchValidationStatus,
)
from tests.api.test_dashboard import (
    NOW,
    add_finding,
    add_patch,
    make_project,
    make_repository,
    sign_up,
)

pytestmark = pytest.mark.integration

PASSED, REJECTED, FAILED = (
    PatchValidationStatus.PASSED,
    PatchValidationStatus.REJECTED,
    PatchValidationStatus.FAILED,
)


@pytest.fixture
def repository(api_client: TestClient, db_session: Session):  # noqa: ANN201
    token = sign_up(api_client, "learner")
    return make_repository(db_session, make_project(api_client, token, "Learning"), "app")


def finding_at(db: Session, repository_id: int, line: int, **overrides) -> Finding:  # noqa: ANN003
    return add_finding(db, repository_id, line_start=line, line_end=line, **overrides)


def proposal(db: Session, finding: Finding, *verdicts: PatchValidationStatus, **fields) -> Patch:  # noqa: ANN003
    patch = add_patch(db, finding, PatchStatus.PROPOSED, *verdicts)
    defaults = {
        "diff": "--- a/app/users.py\n+++ b/app/users.py\n@@ -1 +1 @@\n-old\n+new\n",
        "rationale": "Use a bound parameter.",
        "first_line": 20,
        "last_line": 28,
        "lines_added": 1,
        "lines_removed": 1,
    }
    for name, value in {**defaults, **fields}.items():
        setattr(patch, name, value)
    db.flush()
    return patch


def fill(db: Session, repository_id: int, passed: int, rejected: int, first: int = 100) -> None:
    """Judged fixes, one finding each. Rows for a test, not results."""
    for number in range(passed + rejected):
        finding = finding_at(db, repository_id, first + number)
        proposal(
            db,
            finding,
            PASSED if number < passed else REJECTED,
            lines_added=1 + number % 9,
            prompt_tokens=800 + number,
        )


def run_training(db: Session, tmp_path: Path, **options) -> tuple[int, str]:  # noqa: ANN003
    out = io.StringIO()
    code = train_command(
        db,
        model_path=tmp_path / "models" / "patch_outcome.json",
        report_path=tmp_path / "report" / "report.md",
        tool_version="0.1.0",
        out=out,
        now=NOW,
        **options,
    )
    return code, out.getvalue()


# --- which rows are examples ----------------------------------------------------


def test_only_a_fix_with_a_verdict_is_an_example(db_session: Session, repository) -> None:  # noqa: ANN001
    findings = [finding_at(db_session, repository.id, line) for line in range(1, 8)]
    passed = proposal(db_session, findings[0], PASSED)
    rejected = proposal(db_session, findings[1], REJECTED)
    proposal(db_session, findings[2], FAILED)  # could not be judged
    proposal(db_session, findings[3])  # never checked
    proposal(db_session, findings[4], PatchValidationStatus.RUNNING)
    add_patch(db_session, findings[5], PatchStatus.FAILED)  # refused
    add_patch(db_session, findings[6], PatchStatus.QUEUED)

    collected = collect(db_session)

    assert {item.patch_id: item.passed for item in collected.examples} == {
        passed.id: True,
        rejected.id: False,
    }
    assert collected.requested == 7
    assert (collected.passed, collected.rejected) == (1, 1)
    assert collected.not_judged == 1
    assert collected.unchecked == 1
    assert collected.checking == 1
    assert collected.refused == 1
    assert collected.generating == 1


def test_the_latest_check_is_the_verdict(db_session: Session, repository) -> None:  # noqa: ANN001
    finding = finding_at(db_session, repository.id, 1)
    patch = proposal(db_session, finding, REJECTED, PASSED)

    assert [(item.patch_id, item.passed) for item in collect(db_session).examples] == [
        (patch.id, True)
    ]


def test_a_check_that_could_not_be_completed_does_not_replace_a_verdict_with_a_rejection(
    db_session: Session,
    repository,  # noqa: ANN001
) -> None:
    """Passed, then re-checked after the code moved: not an example of anything now."""
    finding = finding_at(db_session, repository.id, 1)
    proposal(db_session, finding, PASSED, FAILED)

    collected = collect(db_session)

    assert collected.examples == []
    assert collected.not_judged == 1


def test_an_example_holds_what_was_known_before_the_check(db_session: Session, repository) -> None:  # noqa: ANN001
    finding = finding_at(db_session, repository.id, 24, rule_id="JV003", file_path="src/A.java")
    patch = proposal(
        db_session,
        finding,
        PASSED,
        lines_added=3,
        lines_removed=2,
        first_line=20,
        last_line=28,
        fences_stripped=True,
        gutters_stripped=4,
        reindented=True,
        attempts=2,
        passage_chunk_ids=[5, 6, 7],
        prompt_tokens=900,
        completion_tokens=None,
        duration_ms=15000,
        temperature=0.2,
    )

    (item,) = collect(db_session).examples

    assert item.patch_id == patch.id
    assert item.finding_id == finding.id
    assert (item.rule_id, item.suffix) == ("JV003", ".java")
    assert (item.severity, item.confidence) == ("CRITICAL", "HIGH")
    assert (item.lines_added, item.lines_removed, item.region_lines) == (3, 2, 9)
    assert item.diff_characters == len(patch.diff)
    assert item.rationale_characters == len("Use a bound parameter.")
    assert (item.fences_stripped, item.gutters_stripped, item.reindented) == (True, 4, True)
    assert (item.attempts, item.passages, item.had_explanation) == (2, 3, False)
    assert (item.prompt_tokens, item.completion_tokens) == (900, None)
    assert (item.duration_ms, item.temperature) == (15000, 0.2)


def test_the_outcomes_are_summarised_rule_by_rule(db_session: Session, repository) -> None:  # noqa: ANN001
    for line, (rule, verdict) in enumerate(
        [("PY010", PASSED), ("PY010", REJECTED), ("PY010", PASSED), ("JV003", REJECTED)], start=1
    ):
        proposal(db_session, finding_at(db_session, repository.id, line, rule_id=rule), verdict)

    assert collect(db_session).by_rule() == [("PY010", 2, 1), ("JV003", 0, 1)]


# --- training -----------------------------------------------------------------------


def test_with_too_little_data_nothing_is_trained_and_nothing_is_written(
    db_session: Session,
    repository,
    tmp_path: Path,  # noqa: ANN001
) -> None:
    fill(db_session, repository.id, passed=12, rejected=8)

    code, out = run_training(db_session, tmp_path)

    assert code == EXIT_NOT_ENOUGH
    assert "Not trained." in out
    assert "20 judged fixes (12 passed, 8 rejected)" in out
    assert f"{crossval.MIN_EXAMPLES - 20} more judged fixes" in out
    assert "No model and no report were written." in out
    assert not (tmp_path / "models").exists()
    assert not (tmp_path / "report").exists()


def test_an_empty_database_is_too_little_data_not_an_error(
    db_session: Session, tmp_path: Path
) -> None:
    code, out = run_training(db_session, tmp_path)

    assert code == EXIT_NOT_ENOUGH
    assert "Fixes requested:             0" in out


def test_with_enough_data_a_model_and_its_report_are_written(
    db_session: Session,
    repository,
    tmp_path: Path,  # noqa: ANN001
) -> None:
    fill(db_session, repository.id, passed=40, rejected=30)

    code, out = run_training(db_session, tmp_path, repeats=2)

    assert code == EXIT_OK
    assert "Trained on 70 judged fixes for 70 findings." in out
    assert "against the rule-only baseline:" in out
    model = json.loads((tmp_path / "models" / "patch_outcome.json").read_text(encoding="utf-8"))
    assert model["data"] == {
        "examples": 70,
        "passed": 40,
        "rejected": 30,
        "findings": 70,
        "fingerprint": model["data"]["fingerprint"],
    }
    assert model["trained_at"].startswith("2026-03-01T12:00:00")
    report = (tmp_path / "report" / "report.md").read_text(encoding="utf-8")
    assert "| Judged fixes used | 70 |" in report
    assert "| PY010 | 40 | 30 | 57 % |" in report


def test_status_says_whether_there_is_enough_and_writes_nothing(
    db_session: Session,
    repository,
    tmp_path: Path,  # noqa: ANN001
) -> None:
    fill(db_session, repository.id, passed=10, rejected=10)
    code, out = run_training(db_session, tmp_path, status_only=True)
    assert code == EXIT_NOT_ENOUGH
    assert "Not enough to train on yet." in out

    fill(db_session, repository.id, passed=40, rejected=20, first=500)
    code, out = run_training(db_session, tmp_path, status_only=True)
    assert code == EXIT_OK
    assert "Enough to train on." in out
    assert not (tmp_path / "models").exists()


def test_a_report_that_cannot_be_written_is_an_error(
    db_session: Session,
    repository,
    tmp_path: Path,  # noqa: ANN001
) -> None:
    fill(db_session, repository.id, passed=40, rejected=30)
    (tmp_path / "models").write_text("a file where the folder should be", encoding="utf-8")

    code, out = run_training(db_session, tmp_path, repeats=1)

    assert code == EXIT_ERROR
    assert "could not write" in out


def test_options_that_make_no_sense_are_an_error(db_session: Session, repository, tmp_path) -> None:  # noqa: ANN001
    fill(db_session, repository.id, passed=40, rejected=30)

    code, out = run_training(db_session, tmp_path, folds=1)

    assert code == EXIT_ERROR
    assert "at least two folds" in out


# --- asking for more -------------------------------------------------------------------


def queued_patches(db: Session) -> list[Patch]:
    return list(db.scalars(select(Patch).where(Patch.status == PatchStatus.QUEUED)))


def test_a_fix_is_asked_for_where_there_is_none_with_a_verdict(
    db_session: Session,
    repository,  # noqa: ANN001
) -> None:
    bare = finding_at(db_session, repository.id, 1)
    refused = finding_at(db_session, repository.id, 2)
    add_patch(db_session, refused, PatchStatus.FAILED)
    judged = finding_at(db_session, repository.id, 3)
    proposal(db_session, judged, REJECTED)
    waiting = finding_at(db_session, repository.id, 4)
    proposal(db_session, waiting)  # proposed, not checked: needs a check, not another fix
    running = finding_at(db_session, repository.id, 5)
    add_patch(db_session, running, PatchStatus.RUNNING)
    fixed = finding_at(db_session, repository.id, 6, status=FindingStatus.FIXED)
    secret = finding_at(db_session, repository.id, 7, rule_id="SEC005", cwe_id="CWE-798")

    result = collection.queue_fixes(db_session, limit=10)

    assert result == collection.Queued(added=2, left=0)
    assert {patch.finding_id for patch in queued_patches(db_session)} == {bare.id, refused.id}
    assert fixed.id and secret.id  # neither was asked for


def test_asking_again_includes_findings_whose_last_fix_was_rejected(
    db_session: Session,
    repository,  # noqa: ANN001
) -> None:
    rejected = finding_at(db_session, repository.id, 1)
    proposal(db_session, rejected, REJECTED)
    passed = finding_at(db_session, repository.id, 2)
    proposal(db_session, passed, PASSED)
    improved = finding_at(db_session, repository.id, 3)
    proposal(db_session, improved, REJECTED)
    later = proposal(db_session, improved, PASSED)
    later.created_at = NOW + timedelta(hours=1)

    result = collection.queue_fixes(db_session, limit=10, again=True)

    assert result.added == 1
    assert [patch.finding_id for patch in queued_patches(db_session)] == [rejected.id]


def test_the_limit_is_kept_and_the_rest_are_counted(db_session: Session, repository) -> None:  # noqa: ANN001
    for line in range(1, 6):
        finding_at(db_session, repository.id, line)

    result = collection.queue_fixes(db_session, limit=2)

    assert result == collection.Queued(added=2, left=3)
    assert len(queued_patches(db_session)) == 2


def test_a_queued_fix_is_the_same_request_a_click_would_have_made(
    db_session: Session,
    repository,  # noqa: ANN001
) -> None:
    finding = finding_at(db_session, repository.id, 1)
    explanation = Explanation(finding_id=finding.id, status=ExplanationStatus.COMPLETED)
    db_session.add(explanation)
    db_session.flush()

    collection.queue_fixes(db_session, limit=1)

    (patch,) = queued_patches(db_session)
    owner = repository.project.owner_id
    assert patch.requested_by_id == owner
    assert patch.explanation_id == explanation.id
    entry = db_session.scalars(
        select(AuditLog).where(AuditLog.entity_type == "patch", AuditLog.entity_id == str(patch.id))
    ).one()
    assert entry.action == "patch.requested"
    assert entry.user_id == owner
    assert entry.details == {
        "finding_id": finding.id,
        "rule_id": "PY010",
        "source": "collection script",
    }


def test_a_check_is_asked_for_every_proposal_that_has_none(db_session: Session, repository) -> None:  # noqa: ANN001
    unchecked = proposal(db_session, finding_at(db_session, repository.id, 1))
    proposal(db_session, finding_at(db_session, repository.id, 2), PASSED)
    proposal(db_session, finding_at(db_session, repository.id, 3), FAILED)
    add_patch(db_session, finding_at(db_session, repository.id, 4), PatchStatus.FAILED)
    proposal(db_session, finding_at(db_session, repository.id, 5), diff=None)
    # Not a proposal, whatever else is in the row.
    stale = add_patch(db_session, finding_at(db_session, repository.id, 6), PatchStatus.FAILED)
    stale.diff = "--- a\n+++ b\n"
    db_session.flush()

    result = collection.queue_checks(db_session, limit=10)

    assert result == collection.Queued(added=1, left=0)
    queued = list(
        db_session.scalars(
            select(PatchValidation).where(PatchValidation.status == PatchValidationStatus.QUEUED)
        )
    )
    assert [validation.patch_id for validation in queued] == [unchecked.id]
    assert queued[0].requested_by_id == repository.project.owner_id
    entry = db_session.scalars(
        select(AuditLog).where(AuditLog.entity_type == "patch_validation")
    ).one()
    assert entry.action == "patch.validation_requested"
    assert entry.details["source"] == "collection script"


def test_asking_twice_does_not_ask_for_the_same_thing_twice(
    db_session: Session, repository
) -> None:  # noqa: ANN001
    finding_at(db_session, repository.id, 1)
    proposal(db_session, finding_at(db_session, repository.id, 2))

    assert collection.queue_fixes(db_session, limit=10).added == 1
    assert collection.queue_fixes(db_session, limit=10).added == 0
    assert collection.queue_checks(db_session, limit=10).added == 1
    assert collection.queue_checks(db_session, limit=10).added == 0


# --- the collection command ---------------------------------------------------------------


def run_collection(db: Session, action: str, **options) -> tuple[int, str]:  # noqa: ANN003
    out = io.StringIO()
    code = collect_command(
        db,
        action=action,
        limit=options.get("limit", 25),
        again=options.get("again", False),
        out=out,
    )
    return code, out.getvalue()


def test_status_changes_nothing(db_session: Session, repository) -> None:  # noqa: ANN001
    finding_at(db_session, repository.id, 1)

    code, out = run_collection(db_session, "status")

    assert code == EXIT_OK
    assert "Fixes requested:             0" in out
    assert queued_patches(db_session) == []


def test_the_command_says_what_it_asked_for_and_who_does_the_work(
    db_session: Session,
    repository,  # noqa: ANN001
) -> None:
    for line in range(1, 4):
        finding_at(db_session, repository.id, line)

    code, out = run_collection(db_session, "fixes", limit=2)

    assert code == EXIT_OK
    assert "Asked for 2 fix(es); 1 more qualify." in out
    assert "The running application does the work" in out
    assert "still being generated:     2" in out


def test_a_limit_below_one_and_an_unknown_action_are_errors(db_session: Session) -> None:
    assert run_collection(db_session, "fixes", limit=0)[0] == EXIT_ERROR
    assert run_collection(db_session, "everything")[0] == EXIT_ERROR
