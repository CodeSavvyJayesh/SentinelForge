"""Judging a proposed change by scanning it — with the real analyser.

Nothing here is faked. Each test writes a real workspace, lets the Phase 5
engine find a real finding in it, builds a real diff, and asks for a verdict.

The tests worth reading are the ones where the finding *disappears and the
verdict is still no*. "The scanner stopped complaining" is what a naive
validator checks, and there are several ways to make a scanner stop complaining
that are not fixing the code.
"""

import tempfile
from pathlib import Path

import pytest

from app.analysis.engine import analyze_workspace
from app.core.config import get_settings
from app.patching import diffing
from app.patching.validation import (
    FAILED,
    PASSED,
    SKIPPED,
    CannotValidate,
    Outcome,
    validate,
)

PYTHON = """\
import hashlib
import os


def digest(value):
    return hashlib.md5(value).hexdigest()


def lookup(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()
"""

JAVA = """\
public class Report {
    public String digest(String password) throws Exception {
        return MessageDigest.getInstance("MD5").digest(password.getBytes()).toString();
    }
}
"""

MD5_LINE = "    return hashlib.md5(value).hexdigest()\n"


def workspace(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "ws"
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))
    return root


def fingerprint_of(root: Path, rule_id: str, *, occurrence: int = 0) -> str:
    """The real fingerprint the real engine gives this finding."""
    matches = [
        finding
        for finding in analyze_workspace(root, get_settings()).findings
        if finding.rule_id == rule_id and finding.occurrence == occurrence
    ]
    assert matches, f"the engine found no {rule_id}"
    return matches[0].fingerprint


def diff_for(root: Path, name: str, old: str, new: str, *, count: int = 1) -> str:
    before = (root / name).read_text(encoding="utf-8")
    assert old in before
    after = before.replace(old, new, count)
    return diffing.build(
        name, before.splitlines(keepends=True), after.splitlines(keepends=True)
    ).text


def outcome_of(check_key: str, outcome: Outcome) -> str:
    return next(check.outcome for check in outcome.checks if check.key == check_key)


def run(root: Path, name: str, diff: str, rule_id: str, **kwargs) -> Outcome:  # noqa: ANN003
    return validate(root, name, diff, fingerprint_of(root, rule_id, **kwargs), get_settings())


# --- a fix that is a fix ---------------------------------------------------


def test_a_real_fix_passes_every_check(tmp_path: Path) -> None:
    root = workspace(tmp_path, {"app.py": PYTHON})
    diff = diff_for(root, "app.py", "hashlib.md5", "hashlib.sha256")

    outcome = run(root, "app.py", diff, "PY007")

    assert outcome.passed
    assert [check.key for check in outcome.checks] == [
        "target_resolved",
        "no_new_findings",
        "not_a_deletion",
        "still_parses",
    ]
    assert all(check.outcome == PASSED for check in outcome.checks)
    assert outcome.findings_before == 2
    assert outcome.findings_after == 1
    assert outcome.new_findings == []


def test_the_stored_workspace_is_never_written(tmp_path: Path) -> None:
    """The promise of the phase. The patch is applied to a copy, and the copy
    is the only thing that changes."""
    root = workspace(tmp_path, {"app.py": PYTHON, "srv/Report.java": JAVA})
    snapshot = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}
    diff = diff_for(root, "app.py", "hashlib.md5", "hashlib.sha256")

    assert run(root, "app.py", diff, "PY007").passed

    assert {path: path.read_bytes() for path in root.rglob("*") if path.is_file()} == snapshot


def test_the_throwaway_copy_is_thrown_away(tmp_path: Path) -> None:
    root = workspace(tmp_path, {"app.py": PYTHON})
    diff = diff_for(root, "app.py", "hashlib.md5", "hashlib.sha256")
    scratch = Path(tempfile.gettempdir())
    before = set(scratch.glob("sentinelforge-validate-*"))

    run(root, "app.py", diff, "PY007")

    assert set(scratch.glob("sentinelforge-validate-*")) == before


def test_the_copy_is_removed_even_when_validation_cannot_finish(tmp_path: Path) -> None:
    root = workspace(tmp_path, {"app.py": PYTHON})
    diff = diff_for(root, "app.py", "hashlib.md5", "hashlib.sha256")
    target = fingerprint_of(root, "PY007")
    (root / "app.py").write_text(PYTHON.replace("def digest(value):", "def digest(v):"))
    scratch = Path(tempfile.gettempdir())
    before = set(scratch.glob("sentinelforge-validate-*"))

    with pytest.raises(CannotValidate):
        validate(root, "app.py", diff, target, get_settings())

    assert set(scratch.glob("sentinelforge-validate-*")) == before


def test_nothing_from_the_repository_is_executed(tmp_path: Path) -> None:
    """Validation is the analyser run twice, and the analyser only reads.

    The repository contains a module that writes a file the moment it is
    imported or run. If validation executed anything — a test suite, an import,
    a build — the marker would exist.
    """
    marker = tmp_path / "executed.txt"
    trap = f"import pathlib\npathlib.Path({str(marker)!r}).write_text('ran')\n"
    root = workspace(
        tmp_path,
        {"app.py": PYTHON, "conftest.py": trap, "setup.py": trap, "tests/test_app.py": trap},
    )
    diff = diff_for(root, "app.py", "hashlib.md5", "hashlib.sha256")

    assert run(root, "app.py", diff, "PY007").passed

    assert not marker.exists()


def test_a_language_with_no_parser_says_the_syntax_check_was_skipped(tmp_path: Path) -> None:
    """Skipped is reported, not passed. "We did not check this" and "we checked
    and it was fine" are different statements and the row keeps them apart."""
    root = workspace(tmp_path, {"srv/Report.java": JAVA})
    diff = diff_for(root, "srv/Report.java", '"MD5"', '"SHA-256"')

    outcome = run(root, "srv/Report.java", diff, "JV003")

    assert outcome.passed
    assert outcome_of("still_parses", outcome) == SKIPPED


# --- the finding disappears, and the answer is still no --------------------


def test_swapping_one_broken_algorithm_for_another_is_rejected(tmp_path: Path) -> None:
    """MD5 becomes SHA-1. The old finding is gone — its text no longer exists —
    and the same rule fires on the new text. A validator that only asks "is the
    original finding still there?" calls this fixed."""
    root = workspace(tmp_path, {"app.py": PYTHON})
    diff = diff_for(root, "app.py", "hashlib.md5", "hashlib.sha1")

    outcome = run(root, "app.py", diff, "PY007")

    assert not outcome.passed
    assert outcome_of("target_resolved", outcome) == PASSED  # gone, as text
    assert outcome_of("no_new_findings", outcome) == FAILED  # and back, as a rule
    detail = next(check.detail for check in outcome.checks if check.key == "no_new_findings")
    assert "reworded" in detail
    assert outcome.new_findings[0]["rule_id"] == "PY007"


def test_breaking_the_file_is_rejected_even_though_every_finding_vanishes(
    tmp_path: Path,
) -> None:
    """The most instructive failure in the phase.

    A Python file that does not parse yields no AST findings at all. So a patch
    that introduces a syntax error "resolves" the finding it was written for —
    and every other one in the file. The re-scan comes back cleaner than a real
    fix would make it.
    """
    root = workspace(tmp_path, {"app.py": PYTHON})
    diff = diff_for(root, "app.py", MD5_LINE, "    return hashlib.sha256(value.hexdigest()\n")

    outcome = run(root, "app.py", diff, "PY007")

    assert outcome_of("target_resolved", outcome) == PASSED
    assert outcome_of("no_new_findings", outcome) == PASSED
    assert outcome.findings_after == 0, "the broken file should look spotless to the scanner"
    assert outcome_of("still_parses", outcome) == FAILED
    assert not outcome.passed


@pytest.mark.parametrize(
    "replacement",
    ["    pass\n", "    # removed: insecure hash\n", "    ...\n"],
)
def test_replacing_the_code_with_nothing_that_runs_is_rejected(
    tmp_path: Path, replacement: str
) -> None:
    """One line out, one line in. Phase 10's size check sees a net change of
    zero and lets it through; the finding is gone; and nothing was fixed."""
    root = workspace(tmp_path, {"app.py": PYTHON})
    diff = diff_for(root, "app.py", MD5_LINE, replacement)

    outcome = run(root, "app.py", diff, "PY007")

    assert outcome_of("target_resolved", outcome) == PASSED
    assert outcome_of("not_a_deletion", outcome) == FAILED
    assert not outcome.passed


def test_deleting_the_surrounding_code_is_rejected(tmp_path: Path) -> None:
    padded = PYTHON + "".join(f"\n\ndef helper_{n}():\n    return {n}\n" for n in range(4))
    root = workspace(tmp_path, {"app.py": padded})
    before = padded.splitlines(keepends=True)
    after = [*before[:4], *before[12:]]  # the whole of digest() and lookup(), gone
    diff = diffing.build("app.py", before, after).text

    outcome = run(root, "app.py", diff, "PY007")

    assert outcome_of("target_resolved", outcome) == PASSED
    assert outcome_of("not_a_deletion", outcome) == FAILED
    assert outcome.also_resolved == 1, "the SQL finding went with it, and that is reported"


def test_a_fix_that_introduces_a_different_weakness_is_rejected(tmp_path: Path) -> None:
    root = workspace(tmp_path, {"app.py": PYTHON})
    diff = diff_for(
        root,
        "app.py",
        MD5_LINE,
        '    os.system("sha256sum " + value)\n    return hashlib.sha256(value).hexdigest()\n',
    )

    outcome = run(root, "app.py", diff, "PY007")

    assert outcome_of("target_resolved", outcome) == PASSED
    assert outcome_of("no_new_findings", outcome) == FAILED
    assert outcome.new_findings, "what appeared has to be named, not just counted"
    assert outcome.new_findings[0]["rule_id"] != "PY007"
    assert outcome.findings_after == 2


def test_a_change_that_leaves_the_finding_in_place_is_rejected(tmp_path: Path) -> None:
    """The patch applies and changes something — just not the vulnerability."""
    root = workspace(tmp_path, {"app.py": PYTHON})
    diff = diff_for(root, "app.py", "def digest(value):", "def digest(value: bytes):")

    outcome = run(root, "app.py", diff, "PY007")

    assert outcome_of("target_resolved", outcome) == FAILED
    assert not outcome.passed


# --- identity, not fingerprint ---------------------------------------------


def test_fixing_the_first_of_two_identical_lines_counts_as_fixing_it(tmp_path: Path) -> None:
    """A fingerprint includes an occurrence number.

    Two identical vulnerable lines are occurrences 0 and 1. Fix the first, and
    the second is renumbered to 0 — so the *fixed* finding's fingerprint is
    still present in the re-scan, now belonging to the other line. Comparing
    fingerprints would report a correct fix as having done nothing. The
    comparison counts what a finding is instead.
    """
    twice = PYTHON + "\n\ndef digest_again(value):\n" + MD5_LINE
    root = workspace(tmp_path, {"app.py": twice})
    diff = diff_for(root, "app.py", "hashlib.md5", "hashlib.sha256", count=1)

    outcome = run(root, "app.py", diff, "PY007", occurrence=0)

    assert outcome_of("target_resolved", outcome) == PASSED
    assert outcome.passed
    assert outcome.findings_before == 3
    assert outcome.findings_after == 2


def test_fixing_the_other_identical_line_does_not_count_twice(tmp_path: Path) -> None:
    """And the count has to drop — a patch that touches neither is not a fix
    of either."""
    twice = PYTHON + "\n\ndef digest_again(value):\n" + MD5_LINE
    root = workspace(tmp_path, {"app.py": twice})
    diff = diff_for(root, "app.py", "def digest_again(value):", "def digest_again(value: bytes):")

    outcome = run(root, "app.py", diff, "PY007", occurrence=1)

    assert outcome_of("target_resolved", outcome) == FAILED


# --- could not be judged at all --------------------------------------------


def test_code_that_moved_after_the_proposal_cannot_be_validated(tmp_path: Path) -> None:
    """Not a rejection. The patch may be perfectly good; the code it was
    written against is simply not there any more."""
    root = workspace(tmp_path, {"app.py": PYTHON})
    diff = diff_for(root, "app.py", "hashlib.md5", "hashlib.sha256")
    target = fingerprint_of(root, "PY007")
    (root / "app.py").write_text(PYTHON.replace("def digest(value):", "def digest(v):"))

    with pytest.raises(CannotValidate, match="changed since"):
        validate(root, "app.py", diff, target, get_settings())


def test_a_finding_no_longer_in_the_code_cannot_be_validated(tmp_path: Path) -> None:
    root = workspace(tmp_path, {"app.py": PYTHON})
    diff = diff_for(root, "app.py", "hashlib.md5", "hashlib.sha256")

    with pytest.raises(CannotValidate, match="Scan again"):
        validate(root, "app.py", diff, "0" * 64, get_settings())


def test_a_diff_for_a_different_file_cannot_be_validated(tmp_path: Path) -> None:
    """The diff may only touch the file the finding is in — whatever its own
    header claims."""
    root = workspace(tmp_path, {"app.py": PYTHON, "other.py": PYTHON})
    diff = diff_for(root, "other.py", "hashlib.md5", "hashlib.sha256")

    with pytest.raises(CannotValidate, match="different file"):
        validate(root, "app.py", diff, fingerprint_of(root, "PY007"), get_settings())


def test_a_path_escaping_the_workspace_cannot_be_validated(tmp_path: Path) -> None:
    root = workspace(tmp_path, {"app.py": PYTHON})
    (tmp_path / "secret.py").write_text(PYTHON, encoding="utf-8")
    before = PYTHON.splitlines(keepends=True)
    after = PYTHON.replace("md5", "sha256").splitlines(keepends=True)
    diff = diffing.build("../secret.py", before, after).text

    with pytest.raises(CannotValidate, match="outside its repository workspace"):
        validate(root, "../secret.py", diff, "0" * 64, get_settings())

    assert "md5" in (tmp_path / "secret.py").read_text(encoding="utf-8")


def test_a_missing_workspace_cannot_be_validated(tmp_path: Path) -> None:
    root = workspace(tmp_path, {"app.py": PYTHON})
    diff = diff_for(root, "app.py", "hashlib.md5", "hashlib.sha256")

    with pytest.raises(CannotValidate, match="missing"):
        validate(tmp_path / "gone", "app.py", diff, "0" * 64, get_settings())


def test_a_file_that_is_not_utf8_cannot_be_validated(tmp_path: Path) -> None:
    """Rewriting it in a guessed encoding would change bytes the patch never
    touched, and those lines would show up as findings coming and going."""
    root = workspace(tmp_path, {"app.py": PYTHON})
    diff = diff_for(root, "app.py", "hashlib.md5", "hashlib.sha256")
    target = fingerprint_of(root, "PY007")
    (root / "app.py").write_bytes(PYTHON.encode() + "# caf\xe9\n".encode("latin-1"))

    with pytest.raises(CannotValidate, match="not UTF-8"):
        validate(root, "app.py", diff, target, get_settings())


def test_an_unreadable_diff_cannot_be_validated(tmp_path: Path) -> None:
    root = workspace(tmp_path, {"app.py": PYTHON})

    with pytest.raises(CannotValidate):
        validate(root, "app.py", "not a diff", fingerprint_of(root, "PY007"), get_settings())


# --- the copy ---------------------------------------------------------------


def test_files_the_analyser_never_reads_are_not_copied(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    """Copying a dependency folder to check a one-line fix is waste, and those
    files cannot change a verdict because no analysis opens them."""
    import app.patching.validation as module

    root = workspace(
        tmp_path,
        {"app.py": PYTHON, "node_modules/lib/index.js": "eval(x)\n", "logo.png": "not really"},
    )
    diff = diff_for(root, "app.py", "hashlib.md5", "hashlib.sha256")
    copied: list[str] = []
    real_copy = module.shutil.copyfile

    def recording_copy(source, target, **kwargs):  # noqa: ANN001, ANN003, ANN202
        copied.append(Path(source).relative_to(root).as_posix())
        return real_copy(source, target, **kwargs)

    monkeypatch.setattr(module.shutil, "copyfile", recording_copy)

    assert run(root, "app.py", diff, "PY007").passed
    assert copied == ["app.py"]


def test_a_symlink_in_the_workspace_is_not_followed(tmp_path: Path) -> None:
    root = workspace(tmp_path, {"app.py": PYTHON})
    outside = tmp_path / "outside.py"
    outside.write_text(PYTHON, encoding="utf-8")
    try:
        (root / "link.py").symlink_to(outside)
    except (OSError, NotImplementedError):  # pragma: no cover - Windows without privilege
        pytest.skip("symlinks not permitted here")
    diff = diff_for(root, "app.py", "hashlib.md5", "hashlib.sha256")

    outcome = run(root, "app.py", diff, "PY007")

    # Two findings in app.py and none from the linked file: it was never read.
    assert outcome.findings_before == 2


def test_removing_most_of_a_block_is_rejected_even_with_real_code_added(tmp_path: Path) -> None:
    """Ten lines out, one real line in. The added line is code, so the
    "nothing that runs" check has no objection — the size of the removal is
    what gives it away."""
    padded = PYTHON + "\n\nVALUE = 1\n"
    root = workspace(tmp_path, {"app.py": padded})
    before = padded.splitlines(keepends=True)
    after = [*before[:4], "DIGEST = None\n"]
    diff = diffing.build("app.py", before, after).text

    outcome = run(root, "app.py", diff, "PY007")

    assert outcome_of("target_resolved", outcome) == PASSED
    assert outcome_of("not_a_deletion", outcome) == FAILED
    detail = next(check.detail for check in outcome.checks if check.key == "not_a_deletion")
    assert "removes 10 lines and adds 1" in detail


def test_a_scan_that_hit_its_findings_limit_cannot_be_compared(tmp_path: Path) -> None:
    """A truncated analysis is a partial list. Comparing two partial lists
    reports findings as resolved that merely fell off the end."""
    root = workspace(tmp_path, {"app.py": PYTHON})
    diff = diff_for(root, "app.py", "hashlib.md5", "hashlib.sha256")
    target = fingerprint_of(root, "PY007")
    # Two findings and a cap of two: the baseline is cut off, while the patched
    # copy — one finding fewer — is not. Only the baseline check can refuse.
    capped = get_settings().model_copy(update={"ANALYSIS_MAX_FINDINGS": 2})
    assert analyze_workspace(root, capped).truncated

    with pytest.raises(CannotValidate, match="incomplete"):
        validate(root, "app.py", diff, target, capped)


def test_a_rescan_that_hits_the_limit_cannot_be_compared_either(tmp_path: Path) -> None:
    """The limit can be reached by the patch itself adding findings: two before,
    under a cap of three, and three after."""
    root = workspace(tmp_path, {"app.py": PYTHON})
    diff = diff_for(
        root,
        "app.py",
        MD5_LINE,
        '    os.system("a " + value)\n    return hashlib.sha1(value).hexdigest()\n',
    )
    target = fingerprint_of(root, "PY007")
    capped = get_settings().model_copy(update={"ANALYSIS_MAX_FINDINGS": 3})
    assert not analyze_workspace(root, capped).truncated, "the baseline must be complete"

    with pytest.raises(CannotValidate, match="incomplete"):
        validate(root, "app.py", diff, target, capped)


def test_files_too_large_to_analyse_are_not_copied(tmp_path: Path) -> None:
    from app.analysis.engine import analysable_files

    root = workspace(tmp_path, {"app.py": PYTHON, "big.py": "x = 1\n" * 400})
    small_limit = get_settings().model_copy(update={"ANALYSIS_MAX_FILE_BYTES": 1024})

    names = [path.name for path in analysable_files(root, small_limit)]

    assert names == ["app.py"]
