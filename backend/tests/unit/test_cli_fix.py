"""``python -m app.cli fix`` — what it prints, what it writes, and how it exits.

Three numbers, as for the scanner: 0 a change the re-scan supports, 1 no
change to offer, 2 the command could not be run. And one rule about the folder
it is given: nothing in it changes unless ``--apply`` was asked for *and* the
change passed.
"""

import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from app.cli import fix as fix_command
from app.cli.fix import EXIT_ERROR, EXIT_NO_FIX, EXIT_VERIFIED, _write_change
from app.cli.main import main
from app.cli.scan import ScanOptions, analysis_settings
from app.core.config import BACKEND_DIR
from app.fixing import builtin, local
from app.llm.client import LlmUnavailableError
from tests.helpers import FakeOllama

PYTHON = """\
import hashlib
import os


def digest(value):
    return hashlib.md5(value).hexdigest()


def lookup(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()
"""
FIXED = PYTHON.replace("hashlib.md5", "hashlib.sha256")
SQL_FIXED = '    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
TWO_ON_ONE_LINE = (
    "import hashlib\nimport os\n\n\ndef run(command):\n"
    "    return hashlib.md5(os.popen(command).read().encode()).hexdigest()\n"
)
SETTINGS = analysis_settings(ScanOptions(name="t", origin="t"))


def project(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "project"
    for name, content in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content.encode("utf-8"))
    return root


def run(*arguments: object) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main([str(item) for item in arguments], stdout=out, stderr=err, environ={})
    return code, out.getvalue(), err.getvalue()


def snapshot(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def model_answer(replacement: str = SQL_FIXED, rationale: str = "Uses a parameter.") -> str:
    return json.dumps({"replacement": replacement, "rationale": rationale})


@pytest.fixture
def model(monkeypatch: pytest.MonkeyPatch) -> FakeOllama:
    """The command's model client, replaced by a stand-in that records its use."""
    fake = FakeOllama(model_answer())
    built: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def build(*arguments: object, **options: object) -> FakeOllama:
        built.append((arguments, options))
        return fake

    monkeypatch.setattr(fix_command, "OllamaClient", build)
    fake.built = built  # type: ignore[attr-defined]
    return fake


# --- exit codes and what is printed -----------------------------------------


def test_a_built_in_fix_that_passes_the_re_scan_exits_zero(tmp_path: Path) -> None:
    root = project(tmp_path, {"app/main.py": PYTHON})

    code, out, err = run("fix", root, "--at", "app/main.py:6")

    assert code == EXIT_VERIFIED
    assert err == ""
    assert "SentinelForge fix: PY007 app/main.py:6" in out
    assert "built-in: Use SHA-256 instead of a broken hash" in out
    assert "  -    return hashlib.md5(value).hexdigest()" in out
    assert "  +    return hashlib.sha256(value).hexdigest()" in out
    assert "[passed] The original PY007 finding is gone." in out
    assert "Before you accept it: Values hashed before this change" in out
    assert "VERIFIED" in out and "Nothing was written." in out
    # The claim is stated at its real size, every time.
    assert "It does not say the program behaves the same" in out


def test_no_built_in_fix_for_the_rule_exits_one_and_says_what_to_do(tmp_path: Path) -> None:
    root = project(tmp_path, {"app/main.py": PYTHON})

    code, out, err = run("fix", root, "--at", "app/main.py:10")

    assert code == EXIT_NO_FIX
    assert err == ""
    assert "NO FIX: There is no built-in fix for this rule" in out
    assert "VERIFIED" not in out


def test_a_credential_exits_one_with_the_advice_to_rotate_it(tmp_path: Path) -> None:
    root = project(tmp_path, {"settings.py": 'DB_PASSWORD = "s3cr3t_value_42_long_enough"\n'})

    code, out, _err = run("fix", root, "--at", "settings.py:1")

    assert code == EXIT_NO_FIX
    assert "NO FIX: A leaked credential cannot be fixed by editing the file" in out
    assert "s3cr3t_value_42" not in out


def test_a_change_the_re_scan_rejects_exits_one_and_shows_why(
    tmp_path: Path, model: FakeOllama
) -> None:
    root = project(tmp_path, {"app/main.py": PYTHON})
    model.response = model_answer("    return hashlib.sha1(value).hexdigest()", "Uses SHA-1.")

    code, out, _err = run("fix", root, "--at", "app/main.py:6", "--mode", "model")

    assert code == EXIT_NO_FIX
    assert "local model (test-model:1b)" in out
    assert "[failed] PY007 still fires on the changed code" in out
    assert "REJECTED:" in out and "VERIFIED" not in out


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (["--at", "app/main.py"], "--at takes FILE:LINE"),
        (["--at", "app/main.py:six"], "--at takes FILE:LINE"),
        (["--at", "app/main.py:2"], "No finding at app/main.py:2"),
        (["--at", "app/other.py:6"], "No finding at app/other.py:6"),
        (["--fingerprint", "0" * 64], "That finding is not in the code as it is now"),
    ],
)
def test_a_finding_that_cannot_be_found_exits_two(
    tmp_path: Path, arguments: list[str], message: str
) -> None:
    root = project(tmp_path, {"app/main.py": PYTHON})

    code, out, err = run("fix", root, *arguments)

    assert code == EXIT_ERROR
    assert out == ""
    assert message in err


def test_a_path_that_is_not_a_folder_exits_two(tmp_path: Path) -> None:
    code, _out, err = run("fix", tmp_path / "missing", "--at", "a.py:1")

    assert code == EXIT_ERROR
    assert "not a folder" in err


def test_one_of_fingerprint_or_at_is_required(tmp_path: Path) -> None:
    root = project(tmp_path, {"app/main.py": PYTHON})

    code, out, _err = run("fix", root)

    # argparse's own refusal: it prints the usage and exits 2.
    assert code == EXIT_ERROR
    assert out == ""


# --- choosing the finding ---------------------------------------------------


def test_a_fingerprint_from_a_report_selects_the_finding(tmp_path: Path) -> None:
    root = project(tmp_path, {"app/main.py": PYTHON})
    report = tmp_path / "report.json"
    run("scan", root, "--fail-on", "none", "--json", report)
    findings = json.loads(report.read_text(encoding="utf-8"))["findings"]
    fingerprint = next(item["fingerprint"] for item in findings if item["rule_id"] == "PY007")

    code, out, _err = run("fix", root, "--fingerprint", fingerprint)

    assert code == EXIT_VERIFIED
    assert "PY007 app/main.py:6" in out


def test_a_line_with_several_findings_needs_a_rule(tmp_path: Path) -> None:
    root = project(tmp_path, {"app/main.py": TWO_ON_ONE_LINE})

    code, _out, err = run("fix", root, "--at", "app/main.py:6")

    assert code == EXIT_ERROR
    assert "Several findings are on that line (PY003, PY007). Choose one with --rule." in err

    code, out, _err = run("fix", root, "--at", "app/main.py:6", "--rule", "PY007")

    assert code == EXIT_VERIFIED
    assert "hashlib.sha256(os.popen(command)" in out


@pytest.mark.parametrize("spelling", ["app\\main.py:6", "./app/main.py:6", ".\\app\\main.py:6"])
def test_a_path_typed_the_windows_way_finds_the_same_file(tmp_path: Path, spelling: str) -> None:
    root = project(tmp_path, {"app/main.py": PYTHON})

    code, _out, err = run("fix", root, "--at", spelling)

    assert (code, err) == (EXIT_VERIFIED, "")


# --- what is written, and when ----------------------------------------------


def test_nothing_is_written_without_apply(tmp_path: Path) -> None:
    root = project(tmp_path, {"app/main.py": PYTHON, "notes.txt": "keep\n"})
    before = snapshot(root)

    code, _out, _err = run("fix", root, "--at", "app/main.py:6")

    assert code == EXIT_VERIFIED
    assert snapshot(root) == before


def test_apply_writes_the_change_that_was_checked_and_only_that(tmp_path: Path) -> None:
    root = project(tmp_path, {"app/main.py": PYTHON, "notes.txt": "keep\n"})

    code, out, _err = run("fix", root, "--at", "app/main.py:6", "--apply")

    assert code == EXIT_VERIFIED
    assert "The file was changed." in out
    assert (root / "app/main.py").read_bytes() == FIXED.encode()
    assert sorted(path.name for path in root.rglob("*") if path.is_file()) == [
        "main.py",
        "notes.txt",
    ]
    # And the scanner agrees with what it was told would happen.
    rescanned = tmp_path / "after.json"
    run("scan", root, "--fail-on", "none", "--json", rescanned)
    rules = [item["rule_id"] for item in json.loads(rescanned.read_text("utf-8"))["findings"]]
    assert rules == ["PY010"]


def test_apply_does_not_write_a_change_that_was_rejected(tmp_path: Path, model: FakeOllama) -> None:
    root = project(tmp_path, {"app/main.py": PYTHON})
    before = snapshot(root)
    model.response = model_answer("    return hashlib.sha1(value).hexdigest()")

    code, out, _err = run("fix", root, "--at", "app/main.py:6", "--mode", "model", "--apply")

    assert code == EXIT_NO_FIX
    assert "The file was changed." not in out
    assert snapshot(root) == before


def test_apply_keeps_windows_line_endings_and_the_files_permissions(tmp_path: Path) -> None:
    root = project(tmp_path, {"app/main.py": PYTHON.replace("\n", "\r\n")})
    target = root / "app/main.py"
    target.chmod(0o640)

    code, _out, _err = run("fix", root, "--at", "app/main.py:6", "--apply")

    assert code == EXIT_VERIFIED
    assert target.read_bytes() == FIXED.replace("\n", "\r\n").encode()
    if os.name != "nt":
        assert stat.S_IMODE(target.stat().st_mode) == 0o640


def test_a_file_edited_while_the_fix_was_being_checked_is_not_overwritten(tmp_path: Path) -> None:
    root = project(tmp_path, {"app/main.py": PYTHON})
    fingerprint = next(
        item.fingerprint
        for item in local.analyze_workspace(root, SETTINGS).findings
        if item.rule_id == "PY007"
    )
    result = local.fix(root, fingerprint, mode=local.BUILTIN, settings=SETTINGS)
    assert result.verified
    edited = PYTHON + "\n# saved by somebody else a moment ago\n"
    (root / "app/main.py").write_text(edited, encoding="utf-8")

    with pytest.raises(local.FixError, match="changed while the fix was being checked"):
        _write_change(root, result)

    assert (root / "app/main.py").read_text(encoding="utf-8") == edited
    assert [path.name for path in (root / "app").iterdir()] == ["main.py"]


# --- the result as data -----------------------------------------------------


def test_the_json_result_carries_the_change_as_an_editor_needs_it(tmp_path: Path) -> None:
    root = project(tmp_path, {"app/main.py": PYTHON})
    result_file = tmp_path / "out" / "fix.json"

    code, _out, _err = run("fix", root, "--at", "app/main.py:6", "--json", result_file)

    data = json.loads(result_file.read_text(encoding="utf-8"))
    assert code == EXIT_VERIFIED
    assert data["schema"] == 1
    assert (data["status"], data["source"], data["applied"]) == ("verified", "builtin", False)
    assert data["finding"]["rule_id"] == "PY007"
    assert data["finding"]["file_path"] == "app/main.py"
    assert len(data["finding"]["fingerprint"]) == 64
    assert data["title"] == builtin.FIXES["PY007"].title
    assert data["caution"] == builtin.FIXES["PY007"].caution
    assert data["reason"] is None
    assert data["edits"] == [
        {
            "first_line": 6,
            "last_line": 6,
            "old": ["    return hashlib.md5(value).hexdigest()\n"],
            "new": ["    return hashlib.sha256(value).hexdigest()\n"],
        }
    ]
    assert data["validation"]["passed"] is True
    assert [check["key"] for check in data["validation"]["checks"]] == [
        "target_resolved",
        "no_new_findings",
        "not_a_deletion",
        "still_parses",
    ]
    assert data["model"] is None
    assert data["diff"].startswith("--- a/app/main.py\n+++ b/app/main.py\n")


def test_a_rejected_result_has_a_reason_and_no_edits(tmp_path: Path, model: FakeOllama) -> None:
    root = project(tmp_path, {"app/main.py": PYTHON})
    result_file = tmp_path / "fix.json"
    model.response = model_answer("    return hashlib.sha1(value).hexdigest()")

    run("fix", root, "--at", "app/main.py:6", "--mode", "model", "--json", result_file)

    data = json.loads(result_file.read_text(encoding="utf-8"))
    assert data["status"] == "rejected"
    assert data["edits"] == []
    assert "reworded rather than removed" in data["reason"]
    assert data["validation"]["passed"] is False
    assert data["model"]["model"] == "test-model:1b"
    assert data["applied"] is False


def test_a_result_that_cannot_be_written_exits_two(tmp_path: Path) -> None:
    root = project(tmp_path, {"app/main.py": PYTHON})
    blocker = tmp_path / "blocker"
    blocker.write_text("a file, not a folder", encoding="utf-8")

    code, _out, err = run("fix", root, "--at", "app/main.py:6", "--json", blocker / "fix.json")

    assert code == EXIT_ERROR
    assert "could not write the result" in err


def test_a_scan_report_says_which_rules_have_a_one_click_fix(tmp_path: Path) -> None:
    root = project(tmp_path, {"app/main.py": PYTHON})
    report = tmp_path / "report.json"

    run("scan", root, "--fail-on", "none", "--json", report)

    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["quick_fixes"] == builtin.titles()
    assert "PY007" in data["quick_fixes"] and "PY010" not in data["quick_fixes"]


# --- the local model --------------------------------------------------------


def test_the_model_is_asked_and_its_verified_change_reported(
    tmp_path: Path, model: FakeOllama
) -> None:
    root = project(tmp_path, {"app/main.py": PYTHON})

    code, out, _err = run("fix", root, "--at", "app/main.py:10", "--mode", "model")

    assert code == EXIT_VERIFIED
    assert "local model (test-model:1b): SQL query built by string formatting" in out
    assert "Uses a parameter." in out
    assert f"  +{SQL_FIXED}" in out
    assert len(model.prompts) == 1


def test_the_model_client_is_built_from_the_options_given(
    tmp_path: Path, model: FakeOllama
) -> None:
    root = project(tmp_path, {"app/main.py": PYTHON})

    run(
        "fix", root, "--at", "app/main.py:10", "--mode", "model",
        "--ollama-url", "http://127.0.0.1:9999", "--model", "tiny:1b", "--timeout", "42",
    )  # fmt: skip

    ((arguments, options),) = model.built  # type: ignore[attr-defined]
    assert arguments == ("http://127.0.0.1:9999",)
    assert options["model"] == "tiny:1b"
    assert options["timeout_seconds"] == 42
    assert options["temperature"] == 0.0


def test_retry_is_passed_on_as_a_different_temperature(tmp_path: Path, model: FakeOllama) -> None:
    root = project(tmp_path, {"app/main.py": PYTHON})

    run("fix", root, "--at", "app/main.py:10", "--mode", "model", "--retry")

    assert model.temperatures == [0.3]


@pytest.mark.parametrize(
    "url",
    ["http://192.168.1.20:11434", "https://models.example.com", "http://127.0.0.1@evil.example"],
)
def test_code_is_not_sent_to_another_machine_unless_asked(
    tmp_path: Path, model: FakeOllama, url: str
) -> None:
    root = project(tmp_path, {"app/main.py": PYTHON})

    code, _out, err = run(
        "fix", root, "--at", "app/main.py:10", "--mode", "model", "--ollama-url", url
    )

    assert code == EXIT_ERROR
    assert "would send it your code" in err
    assert model.built == [] and model.prompts == []  # type: ignore[attr-defined]


def test_a_remote_model_is_used_when_it_is_asked_for_by_name(
    tmp_path: Path, model: FakeOllama
) -> None:
    root = project(tmp_path, {"app/main.py": PYTHON})

    code, _out, _err = run(
        "fix", root, "--at", "app/main.py:10", "--mode", "model",
        "--ollama-url", "http://192.168.1.20:11434", "--allow-remote-model",
    )  # fmt: skip

    assert code == EXIT_VERIFIED
    assert len(model.prompts) == 1


def test_the_built_in_mode_never_builds_a_model_client(tmp_path: Path, model: FakeOllama) -> None:
    root = project(tmp_path, {"app/main.py": PYTHON})

    run("fix", root, "--at", "app/main.py:6", "--ollama-url", "http://192.168.1.20:11434")

    assert model.built == []  # type: ignore[attr-defined]


def test_a_model_that_is_not_running_exits_two_with_the_command_that_starts_it(
    tmp_path: Path, model: FakeOllama
) -> None:
    root = project(tmp_path, {"app/main.py": PYTHON})
    model.ready_error = LlmUnavailableError("Ollama is not running. Start it with:  ollama serve")

    code, out, err = run("fix", root, "--at", "app/main.py:10", "--mode", "model")

    assert code == EXIT_ERROR
    assert out == ""
    assert "ollama serve" in err


def test_a_timeout_of_zero_is_refused(tmp_path: Path, model: FakeOllama) -> None:
    root = project(tmp_path, {"app/main.py": PYTHON})

    code, _out, err = run(
        "fix", root, "--at", "app/main.py:10", "--mode", "model", "--timeout", "0"
    )

    assert code == EXIT_ERROR
    assert "--timeout must be at least 1" in err


# --- what a scanned folder cannot do ----------------------------------------


def test_a_file_name_cannot_write_to_the_terminal(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("Windows does not allow this character in a file name")
    hostile = "app/\x1b[2J\x1b[31mmain.py"
    root = project(tmp_path, {hostile: PYTHON})
    fingerprint = next(
        item.fingerprint
        for item in local.analyze_workspace(root, SETTINGS).findings
        if item.rule_id == "PY007"
    )

    code, out, _err = run("fix", root, "--fingerprint", fingerprint)

    assert code == EXIT_VERIFIED
    assert "\x1b" not in out


def test_it_runs_from_a_shell_in_a_checkout_with_no_configuration_at_all(tmp_path: Path) -> None:
    """A fresh process, a copy of the code with no `.env`, and an environment
    with no database URL or signing key — which is where an editor runs it."""
    root = project(tmp_path, {"app/main.py": PYTHON})
    home = tmp_path / "checkout"
    shutil.copytree(BACKEND_DIR / "app", home / "app", ignore=shutil.ignore_patterns("__pycache__"))
    keep = ("PATH", "SYSTEMROOT", "PYTHONPATH", "TEMP", "TMP", "TMPDIR")
    environment = {name: os.environ[name] for name in keep if name in os.environ}

    completed = subprocess.run(  # noqa: S603 - our own interpreter and module
        [sys.executable, "-m", "app.cli", "fix", str(root), "--at", "app/main.py:6", "--apply"],
        cwd=home,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
        check=False,
    )

    assert completed.returncode == EXIT_VERIFIED, completed.stderr
    assert "VERIFIED" in completed.stdout
    assert (root / "app/main.py").read_bytes() == FIXED.encode()
