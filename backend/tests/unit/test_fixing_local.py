"""One finding in, one judged proposal out — without a database.

The model is faked at the boundary this project owns (the client's two
methods), exactly as in the web application's tests. Everything else is real:
the analyser finds the finding, the real prompt is built, the model's answer
goes through the real contract, and the verdict comes from scanning a copy
with the change applied.

The tests to read first are the ones where the change *looks* like a fix. A
fix command that reports whatever the model said is a chat window; what makes
this one worth running is that it says no.
"""

import hashlib
import json
from pathlib import Path

import pytest

from app.analysis.engine import analyze_workspace
from app.analysis.findings import Finding
from app.cli.scan import ScanOptions, analysis_settings
from app.fixing import local
from app.fixing.local import (
    BUILTIN,
    MODEL,
    NO_FIX,
    REJECTED,
    VERIFIED,
    Edit,
    FixError,
    edits_between,
    is_loopback,
)
from app.llm import patch_prompt
from app.llm.client import LlmTimeoutError, LlmUnavailableError
from app.patching import CREDENTIAL_MESSAGE, RETRY_TEMPERATURE, validation
from tests.helpers import FakeOllama

SETTINGS = analysis_settings(ScanOptions(name="t", origin="t"))

PYTHON = """\
import hashlib
import os


def digest(value):
    return hashlib.md5(value).hexdigest()


def lookup(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()
"""
SQL_FIXED = '    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
SECRET_FILE = 'DB_PASSWORD = "s3cr3t_value_42_long_enough"\n'


def workspace(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "ws"
    for name, text in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(text.encode("utf-8"))
    return root


def finding_for(root: Path, rule_id: str) -> Finding:
    return next(
        item for item in analyze_workspace(root, SETTINGS).findings if item.rule_id == rule_id
    )


def answer(replacement: str, rationale: str = "Passes the value as a parameter.") -> str:
    return json.dumps({"replacement": replacement, "rationale": rationale})


def snapshot(root: Path) -> dict[str, str]:
    """Every file under ``root`` and a hash of its bytes."""
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def apply_edits(before: list[str], edits: tuple[Edit, ...]) -> list[str]:
    """What an editor does with the edits: bottom up, checking ``old`` first."""
    lines = list(before)
    for edit in sorted(edits, key=lambda item: item.first_line, reverse=True):
        assert tuple(lines[edit.first_line - 1 : edit.last_line]) == edit.old
        lines[edit.first_line - 1 : edit.last_line] = list(edit.new)
    return lines


def ask_model(root: Path, rule_id: str, llm: FakeOllama, **options: object) -> local.FixResult:
    return local.fix(
        root,
        finding_for(root, rule_id).fingerprint,
        mode=MODEL,
        settings=SETTINGS,
        llm=llm,  # type: ignore[arg-type]
        **options,  # type: ignore[arg-type]
    )


# --- a change the re-scan supports ------------------------------------------


def test_a_model_fix_that_removes_the_finding_is_verified(tmp_path: Path) -> None:
    root = workspace(tmp_path, {"app/main.py": PYTHON})
    llm = FakeOllama(answer(SQL_FIXED))

    result = ask_model(root, "PY010", llm)

    assert result.status == VERIFIED and result.verified
    assert result.source == MODEL
    assert result.rationale == "Passes the value as a parameter."
    assert result.caution is None
    assert f"+{SQL_FIXED}" in result.diff.splitlines()
    assert (result.lines_added, result.lines_removed) == (1, 1)
    assert result.outcome is not None and result.outcome.passed
    assert [check.key for check in result.outcome.checks] == [
        "target_resolved",
        "no_new_findings",
        "not_a_deletion",
        "still_parses",
    ]


def test_the_edits_of_a_verified_fix_turn_the_file_into_the_checked_one(tmp_path: Path) -> None:
    root = workspace(tmp_path, {"app/main.py": PYTHON})

    result = ask_model(root, "PY010", FakeOllama(answer(SQL_FIXED)))

    assert result.edits == (
        Edit(
            10,
            10,
            ('    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n',),
            (SQL_FIXED + "\n",),
        ),
    )
    assert apply_edits(list(result.before), result.edits) == list(result.after)
    assert "".join(result.before) == PYTHON


def test_what_the_model_was_and_how_its_answer_was_tidied_is_recorded(tmp_path: Path) -> None:
    root = workspace(tmp_path, {"app/main.py": PYTHON})
    # No indentation, and wrapped in a code fence: both are repaired, and both
    # repairs are reported rather than hidden.
    llm = FakeOllama(answer("```python\n" + SQL_FIXED.strip() + "\n```"), model="qwen-test:7b")

    result = ask_model(root, "PY010", llm)

    assert result.status == VERIFIED
    assert result.model == local.ModelUse(
        model="qwen-test:7b",
        temperature=0.0,
        prompt_tokens=100,
        completion_tokens=50,
        duration_ms=1234,
        fences_stripped=True,
        gutters_stripped=0,
        reindented=True,
    )


def test_the_model_is_asked_the_web_applications_question(tmp_path: Path) -> None:
    root = workspace(tmp_path, {"app/main.py": PYTHON})
    llm = FakeOllama(answer(SQL_FIXED))

    ask_model(root, "PY010", llm)

    assert llm.systems == [patch_prompt.SYSTEM_PROMPT]
    assert llm.temperatures == [None]
    (prompt,) = llm.prompts
    assert "Rule: PY010" in prompt
    assert ">>>>>> REPLACE THESE LINES (10 to 10)" in prompt
    # With no knowledge base to search, the reference is this project's own
    # note for the rule — numbered, as the web application numbers passages.
    assert "[1] SENTINELFORGE PY010 — Risk" in prompt
    assert "[2] SENTINELFORGE PY010 — Fix" in prompt


def test_a_retry_asks_at_a_different_temperature_and_says_so(tmp_path: Path) -> None:
    root = workspace(tmp_path, {"app/main.py": PYTHON})
    llm = FakeOllama(answer(SQL_FIXED))

    result = ask_model(root, "PY010", llm, retry=True)

    assert llm.temperatures == [RETRY_TEMPERATURE]
    assert result.model is not None and result.model.temperature == RETRY_TEMPERATURE


def test_the_folder_is_scanned_once_before_and_once_after(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The first scan finds the finding and is also the "before" of the
    # comparison. A third pass over a large repository would buy nothing.
    root = workspace(tmp_path, {"app/main.py": PYTHON})
    fingerprint = finding_for(root, "PY010").fingerprint
    scans: list[Path] = []
    real = validation.analyze_workspace

    def counting(path: Path, settings: object) -> object:
        scans.append(path)
        return real(path, settings)  # type: ignore[arg-type]

    monkeypatch.setattr(validation, "analyze_workspace", counting)
    monkeypatch.setattr(local, "analyze_workspace", counting)

    result = local.fix(
        root,
        fingerprint,
        mode=MODEL,
        settings=SETTINGS,
        llm=FakeOllama(answer(SQL_FIXED)),  # type: ignore[arg-type]
    )

    assert result.verified
    assert len(scans) == 2
    assert scans[0] == root and scans[1] != root


def test_nothing_in_the_folder_is_written_whatever_the_verdict(tmp_path: Path) -> None:
    root = workspace(tmp_path, {"app/main.py": PYTHON, "README.md": "# demo\n"})
    before = snapshot(root)

    verified = ask_model(root, "PY010", FakeOllama(answer(SQL_FIXED)))
    rejected = ask_model(root, "PY010", FakeOllama(answer("    pass")))
    builtin_fix = local.fix(
        root, finding_for(root, "PY007").fingerprint, mode=BUILTIN, settings=SETTINGS
    )

    assert (verified.status, rejected.status, builtin_fix.status) == (VERIFIED, REJECTED, VERIFIED)
    assert snapshot(root) == before


# --- changes that look like fixes -------------------------------------------


def test_a_change_that_swaps_one_weak_hash_for_another_is_rejected(tmp_path: Path) -> None:
    root = workspace(tmp_path, {"app/main.py": PYTHON})
    llm = FakeOllama(answer("    return hashlib.sha1(value).hexdigest()", "Uses SHA-1."))

    result = ask_model(root, "PY007", llm)

    assert result.status == REJECTED and not result.verified
    assert result.outcome is not None and not result.outcome.passed
    assert "reworded rather than removed" in (result.reason or "")
    # The change is shown, so a person can see what was refused...
    assert "+    return hashlib.sha1(value).hexdigest()" in result.diff.splitlines()
    # ...and is not something this result offers to apply.
    assert result.edits == ()


def test_a_change_that_introduces_another_weakness_is_rejected(tmp_path: Path) -> None:
    root = workspace(tmp_path, {"app/main.py": PYTHON})
    llm = FakeOllama(
        answer("    return os.popen('md5sum ' + value).read()", "Uses the system tool.")
    )

    result = ask_model(root, "PY007", llm)

    assert result.status == REJECTED
    assert result.outcome is not None
    assert [item["rule_id"] for item in result.outcome.new_findings] == ["PY003"]
    assert "introduces 1 finding" in (result.reason or "")
    assert result.edits == ()


@pytest.mark.parametrize(
    ("replacement", "reason"),
    [
        ("    return hashlib.md5(value).hexdigest()", "returned the same code"),
        ("    pass", "nothing that runs"),
        ("    # removed: weak hash", "nothing that runs"),
        ("    return hashlib.sha256(value.hexdigest(", "does not parse"),
    ],
)
def test_a_change_not_worth_scanning_is_rejected_before_the_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, replacement: str, reason: str
) -> None:
    root = workspace(tmp_path, {"app/main.py": PYTHON})
    fingerprint = finding_for(root, "PY007").fingerprint

    def never(*_arguments: object, **_options: object) -> None:
        raise AssertionError("a change that failed the cheap checks was scanned anyway")

    monkeypatch.setattr(validation, "validate", never)

    result = local.fix(
        root,
        fingerprint,
        mode=MODEL,
        settings=SETTINGS,
        llm=FakeOllama(answer(replacement)),  # type: ignore[arg-type]
    )

    assert result.status == REJECTED
    assert reason in (result.reason or "")
    assert result.outcome is None and result.edits == ()


def test_an_answer_that_is_not_the_agreed_shape_is_rejected(tmp_path: Path) -> None:
    root = workspace(tmp_path, {"app/main.py": PYTHON})

    result = ask_model(root, "PY007", FakeOllama("Sure! Here is the fix: use sha256."))

    assert result.status == REJECTED
    assert result.reason
    assert result.diff == "" and result.edits == () and result.model is None


def test_a_change_that_mostly_deletes_is_rejected_before_the_scan(tmp_path: Path) -> None:
    # Nine lines of code replaced by one. The finding would be gone on the
    # next scan, which is exactly why a scan alone cannot be the judge.
    text = (
        "import hashlib\n\n\ndef digest(first, second, third):\n"
        "    return hashlib.md5(\n"
        "        b''.join(\n"
        "            [\n"
        "                first,\n"
        "                second,\n"
        "                third,\n"
        "            ]\n"
        "        )\n"
        "    ).hexdigest()\n"
    )
    root = workspace(tmp_path, {"app/main.py": text})

    result = ask_model(root, "PY007", FakeOllama(answer("    return None", "Removed the hash.")))

    assert result.status == REJECTED
    assert "mostly deletes" in (result.reason or "")
    assert result.outcome is None and result.edits == ()


# --- no change to offer -----------------------------------------------------


@pytest.mark.parametrize("mode", [BUILTIN, MODEL])
def test_a_credential_is_never_given_a_fix_and_the_model_is_not_asked(
    tmp_path: Path, mode: str
) -> None:
    root = workspace(tmp_path, {"settings.py": SECRET_FILE})
    llm = FakeOllama(answer('DB_PASSWORD = "another-literal-value-123"'))
    target = analyze_workspace(root, SETTINGS).findings[0]

    result = local.fix(
        root,
        target.fingerprint,
        mode=mode,
        settings=SETTINGS,
        llm=llm,  # type: ignore[arg-type]
    )

    assert result.status == NO_FIX
    assert result.reason == CREDENTIAL_MESSAGE
    assert result.diff == "" and result.edits == ()
    assert llm.prompts == []
    # Nothing that would let the value be read back out of the result.
    assert "s3cr3t_value_42" not in repr(result)


def test_a_rule_with_no_built_in_fix_says_what_to_do_instead(tmp_path: Path) -> None:
    root = workspace(tmp_path, {"app/main.py": PYTHON})

    result = local.fix(
        root, finding_for(root, "PY010").fingerprint, mode=BUILTIN, settings=SETTINGS
    )

    assert result.status == NO_FIX
    assert result.reason == local.NO_BUILTIN_FOR_RULE
    assert "local model" in result.reason
    assert result.title == "SQL query built by string formatting"


# --- a fix that could not be attempted --------------------------------------


def test_a_finding_that_is_no_longer_in_the_code_is_refused(tmp_path: Path) -> None:
    root = workspace(tmp_path, {"app/main.py": PYTHON})
    fingerprint = finding_for(root, "PY007").fingerprint
    (root / "app/main.py").write_text(PYTHON.replace("md5", "sha256"), encoding="utf-8")

    with pytest.raises(FixError) as raised:
        local.fix(root, fingerprint, mode=BUILTIN, settings=SETTINGS)

    assert str(raised.value) == local.STALE_FINDING


def test_a_scan_that_stopped_at_its_limit_cannot_judge_a_fix(tmp_path: Path) -> None:
    root = workspace(tmp_path, {"app/main.py": PYTHON})
    fingerprint = finding_for(root, "PY007").fingerprint
    limited = analysis_settings(ScanOptions(name="t", origin="t", max_findings=1))

    with pytest.raises(FixError) as raised:
        local.fix(root, fingerprint, mode=BUILTIN, settings=limited)

    assert str(raised.value) == validation.TRUNCATED_MESSAGE


@pytest.mark.parametrize(
    "llm",
    [
        FakeOllama(
            ready_error=LlmUnavailableError("Ollama is not running. Start it with: ollama serve")
        ),
        FakeOllama(error=LlmTimeoutError(300, "http://localhost:11434")),
    ],
)
def test_a_model_that_cannot_be_reached_is_an_error_not_a_verdict(
    tmp_path: Path, llm: FakeOllama
) -> None:
    root = workspace(tmp_path, {"app/main.py": PYTHON})

    with pytest.raises(FixError) as raised:
        ask_model(root, "PY007", llm)

    assert "ollama serve" in str(raised.value)


def test_asking_the_model_without_a_model_is_an_error(tmp_path: Path) -> None:
    root = workspace(tmp_path, {"app/main.py": PYTHON})

    with pytest.raises(FixError, match="No model was configured"):
        local.fix(root, finding_for(root, "PY007").fingerprint, mode=MODEL, settings=SETTINGS)


def test_an_unknown_mode_is_refused_before_anything_is_scanned(tmp_path: Path) -> None:
    with pytest.raises(FixError, match="Unknown mode"):
        local.fix(tmp_path / "missing", "0" * 64, mode="magic", settings=SETTINGS)


def test_a_file_that_is_not_utf8_is_not_rewritten(tmp_path: Path) -> None:
    root = tmp_path / "ws"
    root.mkdir()
    (root / "legacy.py").write_bytes(
        b"# caf\xe9\nimport hashlib\n\n\ndef digest(value):\n"
        b"    return hashlib.md5(value).hexdigest()\n"
    )

    with pytest.raises(FixError, match="not UTF-8"):
        local.fix(root, finding_for(root, "PY007").fingerprint, mode=BUILTIN, settings=SETTINGS)


def test_a_finding_on_a_long_line_can_still_be_fixed(tmp_path: Path) -> None:
    # The stored snippet of a long line is cut short; the line is not.
    padding = ", ".join(f'"{number:03d}"' for number in range(60))
    text = (
        "import hashlib\n\n\ndef digest(value):\n"
        f"    return hashlib.md5(value).hexdigest(), [{padding}]\n"
    )
    root = workspace(tmp_path, {"app/main.py": text})

    result = local.fix(
        root, finding_for(root, "PY007").fingerprint, mode=BUILTIN, settings=SETTINGS
    )

    assert result.status == VERIFIED
    assert result.after[4].startswith("    return hashlib.sha256(value).hexdigest(), [")


def test_lines_that_are_not_the_ones_reported_are_never_rewritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two tools that count lines differently must not edit on each other's count."""
    root = workspace(tmp_path, {"app/main.py": PYTHON})
    fingerprint = finding_for(root, "PY010").fingerprint
    llm = FakeOllama(answer(SQL_FIXED))
    real = local.read_region

    def one_line_early(folder: Path, file_path: str, first: int, last: int) -> object:
        return real(folder, file_path, first - 1, last - 1)

    monkeypatch.setattr(local, "read_region", one_line_early)

    with pytest.raises(FixError) as raised:
        local.fix(
            root,
            fingerprint,
            mode=MODEL,
            settings=SETTINGS,
            llm=llm,  # type: ignore[arg-type]
        )

    assert str(raised.value) == local.UNPLACEABLE
    assert llm.prompts == []


# --- edits, as an editor wants them -----------------------------------------


def test_identical_files_need_no_edits() -> None:
    lines = ["a\n", "b\n"]

    assert edits_between(lines, list(lines)) == ()


def test_one_changed_line_is_one_edit_naming_what_it_replaces() -> None:
    before = ["a\n", "b\n", "c\n"]
    after = ["a\n", "B\n", "c\n"]

    assert edits_between(before, after) == (Edit(2, 2, ("b\n",), ("B\n",)),)


def test_an_inserted_line_replaces_nothing() -> None:
    before = ["a\n", "c\n"]
    after = ["a\n", "b\n", "c\n"]

    (edit,) = edits_between(before, after)

    # "Before line 2": the range is empty, so last_line is first_line - 1.
    assert edit == Edit(2, 1, (), ("b\n",))


def test_a_removed_line_is_replaced_by_nothing() -> None:
    assert edits_between(["a\n", "b\n", "c\n"], ["a\n", "c\n"]) == (Edit(2, 2, ("b\n",), ()),)


def test_two_changes_far_apart_are_two_edits_not_one_big_one() -> None:
    before = [f"line {number}\n" for number in range(1, 41)]
    after = list(before)
    after.insert(2, "import secrets\n")
    after[30] = "changed\n"

    edits = edits_between(before, after)

    assert edits == (
        Edit(3, 2, (), ("import secrets\n",)),
        Edit(30, 30, ("line 30\n",), ("changed\n",)),
    )
    assert apply_edits(before, edits) == after


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ([], ["a\n"]),
        (["a\n"], []),
        (["a\n", "a\n", "a\n"], ["a\n", "a\n"]),
        (["a\n", "b\n"], ["b\n", "a\n"]),
        (["x\n"] * 5, ["x\n"] * 2 + ["y\n"] + ["x\n"] * 3),
        (["a\r\n", "b\r\n"], ["a\r\n", "c\r\n", "b\r\n"]),
        (["a\n", "b"], ["a\n", "b\n", "c"]),
    ],
)
def test_applying_the_edits_always_gives_the_other_file(
    before: list[str], after: list[str]
) -> None:
    assert apply_edits(before, edits_between(before, after)) == after


# --- where the model is -----------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:11434",
        "http://LOCALHOST:11434",
        "http://127.0.0.1:11434",
        "http://127.8.9.10",
        "http://[::1]:11434",
    ],
)
def test_this_machine_is_recognised(url: str) -> None:
    assert is_loopback(url) is True


@pytest.mark.parametrize(
    "url",
    [
        "http://192.168.1.20:11434",
        "http://10.0.0.5:11434",
        "https://models.example.com",
        "http://localhost.example.com:11434",
        # Everything before the @ is a user name; the host is what follows.
        "http://127.0.0.1@models.example.com:11434",
        "http://0.0.0.0:11434",
        "",
        "not a url",
    ],
)
def test_another_machine_is_not_mistaken_for_this_one(url: str) -> None:
    assert is_loopback(url) is False


def test_a_rule_without_a_note_gives_the_model_no_reference() -> None:
    assert local.reference("NOPE999") == []
