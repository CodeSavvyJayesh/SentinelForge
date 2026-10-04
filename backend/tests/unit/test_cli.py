"""The command-line scanner: what it finds, what it prints, and how it exits.

A pipeline reads one thing from this tool — the exit code — so most of these
tests are about that number: that 1 means the code and 2 means the invocation,
that a baseline turns "is this perfect?" into "did this get worse?", and that
nothing a scanned repository contains can change the answer or the log.
"""

import io
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from app.cli import baseline as baseline_file
from app.cli import gate as gate_module
from app.cli.gate import Gate, evaluate
from app.cli.main import EXIT_ERROR, EXIT_GATE_FAILED, EXIT_PASSED, main, plain
from app.cli.scan import ScanOptions, is_excluded, scan
from app.core.config import BACKEND_DIR, Settings, get_settings
from tests.helpers import GITHUB_TOKEN

VULNERABLE = (
    "import os\nimport hashlib\n\n\n"
    "def handle(command, cursor, user_id):\n"
    "    os.system(command)\n"
    '    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
    "    return hashlib.md5(command.encode()).hexdigest()\n"
)
CLEAN = "def add(a, b):\n    return a + b\n"
WEAK_HASH_ONLY = (
    "import hashlib\n\n\ndef digest(value):\n    return hashlib.md5(value).hexdigest()\n"
)


def project(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "project"
    for name, content in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content.encode("utf-8"))
    root.mkdir(exist_ok=True)
    return root


def run(*arguments: object, environ: dict[str, str] | None = None) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main([str(item) for item in arguments], stdout=out, stderr=err, environ=environ or {})
    return code, out.getvalue(), err.getvalue()


# --- exit codes -------------------------------------------------------------


def test_clean_code_passes(tmp_path: Path) -> None:
    code, out, err = run("scan", project(tmp_path, {"app/math.py": CLEAN}))

    assert code == EXIT_PASSED
    assert "PASSED: nothing at HIGH or above." in out
    assert "0 findings" in out
    assert err == ""


def test_vulnerable_code_fails_and_says_why(tmp_path: Path) -> None:
    code, out, _err = run("scan", project(tmp_path, {"app/main.py": VULNERABLE}))

    assert code == EXIT_GATE_FAILED
    assert "FAILED" in out
    assert "findings at HIGH severity or above." in out
    assert "app/main.py:7" in out  # the SQL query
    assert "PASSED" not in out


def test_a_folder_that_does_not_exist_is_an_error_not_a_pass(tmp_path: Path) -> None:
    code, out, err = run("scan", tmp_path / "missing")

    assert code == EXIT_ERROR
    assert "not a folder" in err
    assert out == ""


def test_a_file_is_not_a_folder(tmp_path: Path) -> None:
    target = tmp_path / "one.py"
    target.write_text(CLEAN, encoding="utf-8")

    assert run("scan", target)[0] == EXIT_ERROR


@pytest.mark.parametrize(
    "arguments",
    [
        ["scan"],
        ["scan", ".", "--fail-on", "severe"],
        ["scan", ".", "--max-score", "lots"],
        ["frobnicate"],
        [],
    ],
)
def test_a_bad_invocation_exits_two(arguments: list[str], capsys: pytest.CaptureFixture) -> None:
    assert main(arguments, environ={}) == EXIT_ERROR
    capsys.readouterr()


@pytest.mark.parametrize(
    "arguments",
    [
        ["--max-score", "101"],
        ["--max-score", "-1"],
        ["--max-findings", "0"],
        ["--max-file-bytes", "0"],
    ],
)
def test_a_limit_outside_its_range_is_an_error(tmp_path: Path, arguments: list[str]) -> None:
    code, out, err = run("scan", project(tmp_path, {"a.py": CLEAN}), *arguments)

    assert code == EXIT_ERROR
    assert err.startswith("error: ")
    assert out == ""


def test_help_is_not_a_failure(capsys: pytest.CaptureFixture) -> None:
    assert main(["scan", "--help"], environ={}) == 0
    assert "Exit code 0: passed" in capsys.readouterr().out


# --- the gate ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("fail_on", "expected"),
    [
        ("critical", EXIT_PASSED),
        ("high", EXIT_PASSED),
        ("medium", EXIT_GATE_FAILED),
        ("low", EXIT_GATE_FAILED),
        ("info", EXIT_GATE_FAILED),
        ("none", EXIT_PASSED),
    ],
)
def test_the_threshold_decides_which_severities_fail(
    tmp_path: Path, fail_on: str, expected: int
) -> None:
    """One MEDIUM finding: it fails at medium and below, and passes above."""
    root = project(tmp_path, {"app/digest.py": WEAK_HASH_ONLY})

    code, out, _err = run("scan", root, "--fail-on", fail_on)

    assert "1 finding," in out and "1 medium" in out
    assert code == expected


def test_high_is_the_default_threshold() -> None:
    assert gate_module.DEFAULT_FAIL_ON == "high"
    assert Gate().fail_on == "high"


def test_the_score_ceiling_applies_on_its_own(tmp_path: Path) -> None:
    root = project(tmp_path, {"app/digest.py": WEAK_HASH_ONLY})

    passed = run("scan", root, "--fail-on", "none", "--max-score", "50")
    failed = run("scan", root, "--fail-on", "none", "--max-score", "5")

    assert passed[0] == EXIT_PASSED
    assert "PASSED: the severity check is off." in passed[1]
    assert failed[0] == EXIT_GATE_FAILED
    assert "above the allowed 5." in failed[1]


def test_both_reasons_are_given_when_both_apply(tmp_path: Path) -> None:
    code, out, _err = run(
        "scan", project(tmp_path, {"app/main.py": VULNERABLE}), "--max-score", "10"
    )

    assert code == EXIT_GATE_FAILED
    assert "at HIGH severity or above." in out
    assert "above the allowed 10." in out


def test_a_score_exactly_at_the_ceiling_passes(tmp_path: Path) -> None:
    root = project(tmp_path, {"app/digest.py": WEAK_HASH_ONLY})
    outcome = scan(root, ScanOptions(name="p", origin="p"))

    assert evaluate(outcome.report, Gate("none", outcome.report.score)).passed
    assert not evaluate(outcome.report, Gate("none", outcome.report.score - 0.1)).passed


# --- the baseline -----------------------------------------------------------


def test_a_baseline_turns_the_question_into_did_this_get_worse(tmp_path: Path) -> None:
    root = project(tmp_path, {"app/main.py": VULNERABLE})
    sarif = tmp_path / "out" / "baseline.sarif"

    first = run("scan", root, "--sarif", sarif)
    second = run("scan", root, "--baseline", sarif)

    assert first[0] == EXIT_GATE_FAILED
    assert second[0] == EXIT_PASSED
    assert "0 new since the baseline, 3 already known" in second[1]
    assert "PASSED: no new findings at HIGH or above." in second[1]
    assert second[1].count("[known]") == 3 and "[new]" not in second[1]


def test_a_finding_the_baseline_does_not_have_fails_the_build(tmp_path: Path) -> None:
    root = project(tmp_path, {"app/main.py": VULNERABLE})
    sarif = tmp_path / "baseline.sarif"
    run("scan", root, "--sarif", sarif)
    (root / "app" / "admin.py").write_bytes(b"import os\n\n\ndef run(cmd):\n    os.system(cmd)\n")
    after = tmp_path / "after.sarif"

    code, out, _err = run("scan", root, "--baseline", sarif, "--sarif", after)

    assert code == EXIT_GATE_FAILED
    assert "1 new since the baseline, 3 already known" in out
    assert "1 new finding at HIGH severity or above." in out
    assert "app/admin.py:5" in out.split("FAILED")[1]
    assert "app/main.py" not in out.split("FAILED")[1]
    states = [
        result["baselineState"] for result in json.loads(after.read_text())["runs"][0]["results"]
    ]
    assert sorted(states) == ["new", "unchanged", "unchanged", "unchanged"]


def test_moving_code_down_a_file_does_not_make_it_new(tmp_path: Path) -> None:
    """Fingerprints are built from the code, not the line number, so an import
    added at the top of a file does not fail the build."""
    root = project(tmp_path, {"app/main.py": VULNERABLE})
    sarif = tmp_path / "baseline.sarif"
    run("scan", root, "--sarif", sarif)
    (root / "app" / "main.py").write_bytes(("import sys\nimport json\n" + VULNERABLE).encode())

    code, out, _err = run("scan", root, "--baseline", sarif)

    assert code == EXIT_PASSED
    assert "0 new since the baseline" in out
    assert "app/main.py:9" in out  # it did move


def test_without_a_baseline_sarif_makes_no_claim_about_what_is_new(tmp_path: Path) -> None:
    sarif = tmp_path / "plain.sarif"
    run("scan", project(tmp_path, {"app/main.py": VULNERABLE}), "--sarif", sarif)

    assert all(
        "baselineState" not in result
        for result in json.loads(sarif.read_text())["runs"][0]["results"]
    )


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (None, "cannot be read"),
        ("{not json", "not valid JSON"),
        ("[]", "has no runs"),
        ('{"runs": "many"}', "has no runs"),
        ('"just a string"', "has no runs"),
    ],
)
def test_an_unusable_baseline_is_an_error_never_an_empty_one(
    tmp_path: Path, content: str | None, message: str
) -> None:
    """Read as empty, every finding would be "new". Read as complete, every
    finding would be waved through. Neither is what was asked for."""
    path = tmp_path / "baseline.sarif"
    if content is not None:
        path.write_text(content, encoding="utf-8")

    code, out, err = run("scan", project(tmp_path, {"app/main.py": VULNERABLE}), "--baseline", path)

    assert code == EXIT_ERROR
    assert message in err
    assert out == ""


def test_a_baseline_is_read_defensively(tmp_path: Path) -> None:
    path = tmp_path / "odd.sarif"
    path.write_text(
        json.dumps(
            {
                "runs": [
                    "not a run",
                    {"results": "not a list"},
                    {
                        "results": [
                            "not a result",
                            {"partialFingerprints": "not a dict"},
                            {"partialFingerprints": {"sentinelforge/v1": 42}},
                            {"partialFingerprints": {"sentinelforge/v1": ""}},
                            {"partialFingerprints": {"other/v1": "ignored"}},
                            {"partialFingerprints": {"sentinelforge/v1": "abc"}},
                        ]
                    },
                    {"results": [{"partialFingerprints": {"sentinelforge/v1": "def"}}]},
                ]
            }
        ),
        encoding="utf-8",
    )

    assert baseline_file.load(path) == frozenset({"abc", "def"})


def test_an_oversized_baseline_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "big.sarif"
    path.write_text('{"runs": []}', encoding="utf-8")
    monkeypatch.setattr(baseline_file, "MAX_BASELINE_BYTES", 5)

    with pytest.raises(baseline_file.BaselineError, match="larger than"):
        baseline_file.load(path)


# --- exclusions -------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "pattern", "expected"),
    [
        ("tests/test_a.py", "tests", True),
        ("tests/unit/test_a.py", "tests/", True),
        ("tests/unit/test_a.py", "./tests", True),
        ("src/tests/test_a.py", "tests", False),  # a prefix, not a substring
        ("testsuite/a.py", "tests", False),
        ("src/tests/test_a.py", "*/tests", True),
        ("static/js/app.min.js", "*.min.js", True),
        ("static/js/app.js", "*.min.js", False),
        ("docs/examples/a.py", "docs/*/a.py", True),
        ("backend\\tests\\a.py", "backend/tests", False),  # paths are always posix
        ("backend/tests/a.py", "backend\\tests", True),  # a Windows-style pattern is accepted
        ("Tests/a.py", "tests", False),
        ("a.py", "", False),
        ("a.py", "  ", False),
    ],
)
def test_exclusion_patterns(path: str, pattern: str, expected: bool) -> None:
    assert is_excluded(path, (pattern,)) is expected


def test_excluded_findings_are_dropped_and_counted_out_loud(tmp_path: Path) -> None:
    root = project(tmp_path, {"app/main.py": VULNERABLE, "legacy/old.py": VULNERABLE})

    code, out, _err = run("scan", root, "--exclude", "legacy", "--fail-on", "none")

    assert code == EXIT_PASSED
    assert "3 findings" in out
    assert "3 left out by --exclude" in out
    assert "legacy/old.py" not in out


def test_excluding_everything_passes_but_cannot_do_so_silently(tmp_path: Path) -> None:
    code, out, _err = run(
        "scan", project(tmp_path, {"app/main.py": VULNERABLE}), "--exclude", "app"
    )

    assert code == EXIT_PASSED
    assert "3 left out by --exclude" in out


# --- the files it writes ----------------------------------------------------


def test_every_format_is_written_from_one_scan(tmp_path: Path) -> None:
    root = project(tmp_path, {"app/main.py": VULNERABLE})
    out_dir = tmp_path / "reports" / "nested"

    run(
        "scan", root, "--name", "Payments",
        "--sarif", out_dir / "r.sarif", "--markdown", out_dir / "r.md",
        "--html", out_dir / "r.html", "--json", out_dir / "r.json",
    )  # fmt: skip

    sarif = json.loads((out_dir / "r.sarif").read_text(encoding="utf-8"))
    data = json.loads((out_dir / "r.json").read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == data["open_count"] == 3
    assert (
        (out_dir / "r.md").read_text(encoding="utf-8").startswith("# Security report: Payments\n")
    )
    assert "<title>Security report: Payments</title>" in (out_dir / "r.html").read_text("utf-8")
    assert data["new_count"] == 3
    assert {item["fix_state"] for item in data["findings"]} == {"none"}
    # A command-line scan is not a stored row: no "scan 0", no "repository 0".
    for name in ("r.md", "r.html"):
        document = (out_dir / name).read_text(encoding="utf-8")
        assert "scan 0" not in document and "repository 0" not in document


def test_written_files_have_the_same_bytes_on_every_platform(tmp_path: Path) -> None:
    root = project(tmp_path, {"app/main.py": VULNERABLE})
    paths = {name: tmp_path / f"r.{name}" for name in ("sarif", "markdown", "html", "json")}

    run("scan", root, *[item for name, path in paths.items() for item in (f"--{name}", path)])

    for path in paths.values():
        content = path.read_bytes()
        assert content and b"\r" not in content, path.name
        assert content.endswith(b"\n")


def test_a_report_that_cannot_be_written_is_an_error(tmp_path: Path) -> None:
    root = project(tmp_path, {"app/math.py": CLEAN})
    blocker = tmp_path / "blocker"
    blocker.write_text("a file, not a folder", encoding="utf-8")

    code, _out, err = run("scan", root, "--sarif", blocker / "r.sarif")

    assert code == EXIT_ERROR
    assert "could not write a report" in err


def test_github_describes_the_checkout_and_the_sarif_carries_it(tmp_path: Path) -> None:
    root = project(tmp_path, {"app/main.py": VULNERABLE})
    sarif = tmp_path / "r.sarif"
    environ = {
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_REPOSITORY": "acme/payments",
        "GITHUB_SHA": "0123abc",
        "GITHUB_REF_NAME": "main",
    }

    code, out, _err = run("scan", root, "--sarif", sarif, environ=environ)

    run_ = json.loads(sarif.read_text(encoding="utf-8"))["runs"][0]
    assert code == EXIT_GATE_FAILED
    assert "SentinelForge 0.1.0: acme/payments" in out
    assert run_["versionControlProvenance"] == [
        {"repositoryUri": "https://github.com/acme/payments", "revisionId": "0123abc",
         "branch": "main"}
    ]  # fmt: skip


def test_a_local_folder_has_a_name_but_no_address(tmp_path: Path) -> None:
    root = project(tmp_path, {"app/main.py": VULNERABLE})
    sarif = tmp_path / "r.sarif"

    _code, out, _err = run("scan", root, "--sarif", sarif, environ={"GITHUB_SHA": "0123abc"})

    assert "SentinelForge 0.1.0: project" in out
    assert "versionControlProvenance" not in json.loads(sarif.read_text("utf-8"))["runs"][0]


# --- what a scanned repository cannot do ------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("plain.py", "plain.py"),
        ("a\x1b[2Jb", "a?[2Jb"),  # an escape sequence that clears the screen
        ("a\nb\rc", "a?b?c"),
        ("a\x00b\x7fc", "a?b?c"),
        ("‮gnp.exe", "?gnp.exe"),  # right-to-left override
        ("a b", "a?b"),
        ("naïve — ok ✓", "naïve — ok ✓"),
        (42, "42"),
    ],
)
def test_text_from_a_repository_is_made_safe_to_print(raw: object, expected: str) -> None:
    assert plain(raw) == expected


def test_a_file_name_cannot_write_to_the_terminal_or_the_runner(tmp_path: Path) -> None:
    """A file can be named with an escape sequence, or with a line break
    followed by `::` — which a GitHub Actions runner reads as a command."""
    hostile = "a\n::error title=pwned::x\x1b[2J.py"
    try:
        root = project(tmp_path, {f"app/{hostile}": VULNERABLE})
    except OSError:
        pytest.skip("this filesystem does not allow such a file name")

    code, out, _err = run("scan", root)

    assert code == EXIT_GATE_FAILED
    assert "\x1b" not in out
    assert not [line for line in out.splitlines() if line.lstrip().startswith("::")]
    assert "a?::error title=pwned::x?[2J.py:7" in out


def test_a_secret_in_the_code_is_in_nothing_this_tool_produces(tmp_path: Path) -> None:
    root = project(tmp_path, {".env": f"PORT=3000\nGITHUB_TOKEN={GITHUB_TOKEN}\n"})
    paths = {name: tmp_path / f"r.{name}" for name in ("sarif", "markdown", "html", "json")}

    code, out, err = run(
        "scan", root, *[item for name, path in paths.items() for item in (f"--{name}", path)]
    )

    assert code == EXIT_GATE_FAILED
    assert "SEC003" in out
    for text in (out, err, *[path.read_text(encoding="utf-8") for path in paths.values()]):
        assert GITHUB_TOKEN not in text
        assert GITHUB_TOKEN[8:] not in text


def test_nothing_in_the_scanned_folder_is_executed(tmp_path: Path) -> None:
    marker = tmp_path / "executed"
    payload = f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n"
    root = project(
        tmp_path,
        {
            "setup.py": payload,
            "conftest.py": payload,
            "sitecustomize.py": payload,
            "app/__init__.py": payload,
            "app/cli/__init__.py": payload,
            "Makefile": f"all:\n\ttouch {marker}\n",
        },
    )

    run("scan", root)

    assert not marker.exists()


def test_a_link_out_of_the_folder_is_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside.py"
    outside.write_text(VULNERABLE, encoding="utf-8")
    root = project(tmp_path, {"app/math.py": CLEAN})
    try:
        (root / "app" / "linked.py").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks not permitted here")

    code, out, _err = run("scan", root)

    assert code == EXIT_PASSED
    assert "0 findings" in out


# --- output -----------------------------------------------------------------


def test_quiet_prints_the_verdict_and_the_reasons_only(tmp_path: Path) -> None:
    root = project(tmp_path, {"app/main.py": VULNERABLE})

    loud = run("scan", root, "--fail-on", "none")[1]
    quiet = run("scan", root, "--fail-on", "none", "--quiet")[1]

    assert "app/main.py:7" in loud
    assert "app/main.py" not in quiet
    assert "3 findings" in quiet and "PASSED" in quiet


def test_a_long_list_of_blocking_findings_is_cut_short_and_says_so(tmp_path: Path) -> None:
    body = "import os\n\n\ndef run(a):\n" + "".join(
        f"    os.system(a + '{n}')\n" for n in range(14)
    )
    code, out, _err = run("scan", project(tmp_path, {"app/many.py": body}), "--quiet")

    assert code == EXIT_GATE_FAILED
    assert "14 findings at HIGH severity or above." in out
    assert "… and 4 more" in out
    listed = [line for line in out.split("FAILED")[1].splitlines() if "app/many.py:" in line]
    assert len(listed) == 10


def test_an_incomplete_scan_says_it_is_a_lower_bound(tmp_path: Path) -> None:
    body = "import os\n\n\ndef run(a):\n" + "".join(f"    os.system(a + '{n}')\n" for n in range(6))
    code, out, _err = run(
        "scan", project(tmp_path, {"app/many.py": body}), "--max-findings", "2", "--quiet"
    )

    assert code == EXIT_GATE_FAILED
    assert "INCOMPLETE" in out


# --- no database, no configuration ------------------------------------------


def test_a_scan_never_builds_the_applications_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The application's settings need a database URL and a signing key. A
    pipeline has neither, so the scanner must not ask for them — and the test
    machine having both would hide it if it did."""

    def refuse(self: Settings, **_values: object) -> None:
        raise AssertionError("the scanner built the application's settings")

    get_settings.cache_clear()
    monkeypatch.setattr(Settings, "__init__", refuse)
    try:
        code, out, _err = run("scan", project(tmp_path, {"app/main.py": VULNERABLE}))
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()

    assert code == EXIT_GATE_FAILED
    assert "3 findings" in out


def clean_environment() -> dict[str, str]:
    """What a pipeline has: a PATH, and none of the application's settings."""
    keep = ("PATH", "SYSTEMROOT", "SYSTEMDRIVE", "TEMP", "TMP", "PATHEXT", "COMSPEC", "LANG")
    return {name: os.environ[name] for name in keep if name in os.environ}


def copy_of_the_application(tmp_path: Path) -> Path:
    """`app/` on its own, with no `.env` beside it — a clean checkout."""
    home = tmp_path / "checkout"
    shutil.copytree(BACKEND_DIR / "app", home / "app", ignore=shutil.ignore_patterns("__pycache__"))
    return home


def shell(home: Path, *arguments: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - our own interpreter and module
        [sys.executable, "-m", "app.cli", *[str(item) for item in arguments]],
        cwd=home,
        env=clean_environment(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
        check=False,
    )


def test_it_runs_from_a_shell_in_a_checkout_with_no_configuration_at_all(tmp_path: Path) -> None:
    """The test above cannot see an import-time dependency, because by the
    time it runs everything is imported. And on a developer's machine a `.env`
    file hides it. This runs the real command the way a pipeline does: a fresh
    process, a copy of the code with no `.env`, and an environment without a
    database URL or a signing key. It crashed the first time it was tried."""
    root = project(tmp_path, {"app/main.py": VULNERABLE})

    completed = shell(copy_of_the_application(tmp_path), "scan", root, "--quiet")

    assert completed.returncode == EXIT_GATE_FAILED, completed.stderr
    assert "3 findings" in completed.stdout
    assert "FAILED" in completed.stdout
    assert completed.stderr == ""


def test_a_clean_folder_passes_from_a_shell(tmp_path: Path) -> None:
    completed = shell(copy_of_the_application(tmp_path), "scan", project(tmp_path, {"a.py": CLEAN}))

    assert completed.returncode == EXIT_PASSED, completed.stderr
    assert "PASSED" in completed.stdout


def test_a_crash_exits_two_never_one(tmp_path: Path) -> None:
    """An uncaught exception exits 1 by default, and 1 is how this tool says
    the code failed the gate. A scanner that cannot start must not look like a
    scanner that found something."""
    home = copy_of_the_application(tmp_path)
    (home / "app" / "cli" / "main.py").write_text("raise RuntimeError('broken')\n", "utf-8")

    completed = shell(home, "scan", project(tmp_path, {"a.py": CLEAN}))

    assert completed.returncode == EXIT_ERROR
    assert "the scan could not be run: RuntimeError: broken" in completed.stderr
    assert completed.stdout == ""


def test_a_character_the_console_cannot_encode_costs_a_question_mark_not_a_crash(
    tmp_path: Path,
) -> None:
    """A console in a legacy code page cannot print every file name. That must
    not turn a finding into a traceback and the wrong exit code."""
    root = project(tmp_path, {"app/日本語.py": VULNERABLE})
    raw = io.BytesIO()
    out = io.TextIOWrapper(raw, encoding="ascii", errors="strict")

    code = main(["scan", str(root)], stdout=out, stderr=io.StringIO(), environ={})
    out.flush()

    assert code == EXIT_GATE_FAILED
    assert b"app/???.py:7" in raw.getvalue()
