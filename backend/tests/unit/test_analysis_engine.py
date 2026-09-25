"""The engine: what it walks, what it refuses, and what it promises."""

from pathlib import Path

import pytest

from app.analysis.engine import analyze_workspace
from app.core.config import Settings, get_settings


@pytest.fixture
def settings() -> Settings:
    return get_settings()


def write(root: Path, relative: str, content: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def test_it_finds_issues_across_languages(tmp_path: Path, settings: Settings) -> None:
    write(tmp_path, "app/main.py", "import os\nos.system(command)\n")
    write(tmp_path, "web/app.js", "const out = eval(userInput);\n")
    write(tmp_path, "srv/Main.java", 'MessageDigest.getInstance("MD5");\n')
    write(tmp_path, ".env", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")

    result = analyze_workspace(tmp_path, settings)

    assert {finding.rule_id for finding in result.findings} == {"PY003", "JS001", "JV003", "SEC001"}
    assert result.files_scanned == 4
    assert all(not Path(finding.file_path).is_absolute() for finding in result.findings)


def test_findings_are_ordered_worst_first(tmp_path: Path, settings: Settings) -> None:
    write(tmp_path, "a.py", "import hashlib\nhashlib.md5(data)\n")  # MEDIUM
    write(tmp_path, "b.py", "eval(payload)\n")  # CRITICAL

    result = analyze_workspace(tmp_path, settings)

    severities = [str(finding.severity) for finding in result.findings]
    assert severities == sorted(
        severities, key=lambda value: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(value)
    )
    assert str(result.findings[0].severity) == "CRITICAL"


def test_the_same_workspace_analyses_identically(tmp_path: Path, settings: Settings) -> None:
    write(tmp_path, "app.py", "import os\nos.system(cmd)\nPASSWORD = 'a-real-secret-value'\n")
    write(tmp_path, "web.js", "el.innerHTML = comment;\n")

    first = analyze_workspace(tmp_path, settings)
    second = analyze_workspace(tmp_path, settings)

    assert [f.fingerprint for f in first.findings] == [f.fingerprint for f in second.findings]


def test_ignored_directories_are_not_analysed(tmp_path: Path, settings: Settings) -> None:
    write(tmp_path, "node_modules/left-pad/index.js", "eval(x);\n")
    write(tmp_path, ".git/hooks/pre-commit", "eval(x);\n")
    write(tmp_path, "app.js", "const a = 1;\n")

    result = analyze_workspace(tmp_path, settings)

    assert result.findings == []
    assert result.files_scanned == 1


def test_binary_files_are_skipped(tmp_path: Path, settings: Settings) -> None:
    (tmp_path / "logo.dat").write_bytes(b"\x89PNG\x00\x00binary eval(x)\x00")
    write(tmp_path, "app.js", "const a = 1;\n")

    result = analyze_workspace(tmp_path, settings)

    assert result.files_scanned == 1
    assert result.files_skipped == 1


def test_oversized_files_are_skipped(tmp_path: Path, settings: Settings) -> None:
    small = settings.model_copy(update={"ANALYSIS_MAX_FILE_BYTES": 1024})
    write(tmp_path, "huge.py", "# padding\n" * 500 + "eval(payload)\n")

    result = analyze_workspace(tmp_path, small)

    assert result.files_scanned == 0
    assert result.files_skipped == 1
    assert result.findings == []


def test_a_file_that_does_not_parse_is_counted_not_guessed(
    tmp_path: Path, settings: Settings
) -> None:
    write(tmp_path, "broken.py", "def broken(:\n    os.system(cmd)\n")

    result = analyze_workspace(tmp_path, settings)

    assert result.unparsable_files == 1
    # No AST findings from a file we could not parse...
    assert not any(finding.analyzer == "python-ast" for finding in result.findings)


def test_secrets_are_still_found_in_a_file_that_does_not_parse(
    tmp_path: Path, settings: Settings
) -> None:
    """A committed key is a committed key whether or not the file compiles."""
    write(tmp_path, "broken.py", "def broken(:\nAWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")

    result = analyze_workspace(tmp_path, settings)

    assert "SEC001" in {finding.rule_id for finding in result.findings}


def test_the_finding_cap_truncates_and_says_so(tmp_path: Path, settings: Settings) -> None:
    capped = settings.model_copy(update={"ANALYSIS_MAX_FINDINGS": 5})
    write(tmp_path, "many.py", "eval(payload)\n" * 50)

    result = analyze_workspace(tmp_path, capped)

    assert result.truncated is True
    assert len(result.findings) == 5


def test_a_clean_repository_produces_nothing_and_is_not_an_error(
    tmp_path: Path, settings: Settings
) -> None:
    write(
        tmp_path,
        "app.py",
        "import secrets\n\n\ndef token() -> str:\n    return secrets.token_urlsafe(32)\n",
    )
    write(tmp_path, "README.md", "# A clean project\n")

    result = analyze_workspace(tmp_path, settings)

    assert result.findings == []
    assert result.files_scanned == 2


def test_an_empty_workspace_is_handled(tmp_path: Path, settings: Settings) -> None:
    result = analyze_workspace(tmp_path, settings)
    assert (result.findings, result.files_scanned) == ([], 0)


def test_symlinks_are_not_followed(tmp_path: Path, settings: Settings) -> None:
    import os

    write(tmp_path, "app.py", "x = 1\n")
    target = write(tmp_path, "real/secret.py", "PASSWORD = 'a-real-secret-value'\n")
    try:
        os.symlink(target, tmp_path / "link.py")
    except (OSError, NotImplementedError):  # pragma: no cover - Windows
        pytest.skip("creating a symlink needs a privilege this account does not have")

    result = analyze_workspace(tmp_path, settings)

    # The real file is analysed once; the link is not a second copy of it.
    assert [f.file_path for f in result.findings] == ["real/secret.py"]


def test_duplicate_findings_are_collapsed(tmp_path: Path, settings: Settings) -> None:
    """The same line, found by two analysers, is one finding."""
    write(tmp_path, "config.py", "API_KEY = 'ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'\n")

    result = analyze_workspace(tmp_path, settings)

    fingerprints = [finding.fingerprint for finding in result.findings]
    assert len(fingerprints) == len(set(fingerprints))


def test_two_identical_vulnerable_lines_are_two_findings(
    tmp_path: Path, settings: Settings
) -> None:
    """os.system(cmd) on line 3 and line 9 are two things to fix.

    The fingerprint deliberately ignores line numbers so that findings survive
    code moving, which means repeats have to be numbered explicitly or the
    second one silently disappears.
    """
    write(tmp_path, "app.py", "import os\n\nos.system(cmd)\n\n\ndef later():\n    os.system(cmd)\n")

    result = analyze_workspace(tmp_path, settings)

    system_findings = [f for f in result.findings if f.rule_id == "PY003"]
    assert len(system_findings) == 2
    assert {f.line_start for f in system_findings} == {3, 7}
    assert len({f.fingerprint for f in system_findings}) == 2


def test_one_issue_found_by_two_analysers_is_reported_once(
    tmp_path: Path, settings: Settings
) -> None:
    """The AST secret rule and the generic secret rule see the same line."""
    write(tmp_path, "config.py", "DB_PASSWORD = 'a-real-looking-secret-value'\n")

    result = analyze_workspace(tmp_path, settings)

    at_that_line = [f for f in result.findings if f.line_start == 1]
    assert len(at_that_line) == 1, [f.rule_id for f in at_that_line]
    # The stronger claim survives: the AST rule knows it is an assignment.
    assert at_that_line[0].rule_id == "PY006"
    assert "a-real-looking-secret-value" not in at_that_line[0].snippet


def test_two_different_issues_on_one_line_are_both_kept(tmp_path: Path, settings: Settings) -> None:
    write(tmp_path, "app.py", "import subprocess\nsubprocess.run(eval(payload), shell=True)\n")

    result = analyze_workspace(tmp_path, settings)

    assert {f.rule_id for f in result.findings if f.line_start == 2} == {"PY001", "PY002"}


def test_a_huge_nested_literal_does_not_crash_the_run(tmp_path: Path, settings: Settings) -> None:
    """Deeply nested code can exhaust the parser; that is a skip, not a 500."""
    write(tmp_path, "deep.py", "x = " + "[" * 200 + "]" * 200 + "\n")
    write(tmp_path, "app.py", "import os\nos.system(cmd)\n")

    result = analyze_workspace(tmp_path, settings)

    assert "PY003" in {finding.rule_id for finding in result.findings}
