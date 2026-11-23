"""The fixes that need no model — what they rewrite, and what they leave alone.

Every test here goes through the real analyser twice: once to find the finding
the fix is for, and once more — inside ``local.fix`` — on a copy with the
change applied. A rewrite is only ever called "verified" by that second scan.

The second half of each group is the half that matters. A mechanical rewrite
is safe exactly as far as it refuses the code it was not written for, so most
of these tests are about a line that looks like the one the fix handles and
is not.
"""

from pathlib import Path

import pytest

from app.analysis.engine import analyze_workspace
from app.analysis.findings import Finding
from app.cli.scan import ScanOptions, analysis_settings
from app.fixing import builtin, local
from app.fixing.local import NO_FIX, VERIFIED, FixResult
from app.knowledge.rule_notes import NOTES_BY_RULE

SETTINGS = analysis_settings(ScanOptions(name="t", origin="t"))


def workspace(tmp_path: Path, text: str, name: str = "app/main.py") -> Path:
    root = tmp_path / "ws"
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(text.encode("utf-8"))
    return root


def finding_for(root: Path, rule_id: str) -> Finding:
    found = [item for item in analyze_workspace(root, SETTINGS).findings if item.rule_id == rule_id]
    assert found, f"the analyser did not report {rule_id}; the test's code is wrong"
    return found[0]


def fix(tmp_path: Path, text: str, rule_id: str, name: str = "app/main.py") -> FixResult:
    root = workspace(tmp_path, text, name)
    return local.fix(
        root, finding_for(root, rule_id).fingerprint, mode=local.BUILTIN, settings=SETTINGS
    )


def added(result: FixResult) -> list[str]:
    return [
        line[1:]
        for line in result.diff.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]


def removed(result: FixResult) -> list[str]:
    return [
        line[1:]
        for line in result.diff.splitlines()
        if line.startswith("-") and not line.startswith("---")
    ]


# --- the catalogue ----------------------------------------------------------

# One realistic vulnerable line per rule that has a built-in fix, and the line
# the fix must turn it into.
CANONICAL: dict[str, tuple[str, str, str, str]] = {
    "PY004": (
        "app/main.py",
        "import yaml\n\n\ndef load(handle):\n    return yaml.load(handle)\n",
        "    return yaml.load(handle)",
        "    return yaml.safe_load(handle)",
    ),
    "PY007": (
        "app/main.py",
        "import hashlib\n\n\ndef digest(value):\n    return hashlib.md5(value).hexdigest()\n",
        "    return hashlib.md5(value).hexdigest()",
        "    return hashlib.sha256(value).hexdigest()",
    ),
    "PY008": (
        "app/main.py",
        "import requests\n\n\ndef fetch(url):\n    return requests.get(url, verify=False)\n",
        "    return requests.get(url, verify=False)",
        "    return requests.get(url, verify=True)",
    ),
    "PY009": (
        "app/main.py",
        "from flask import Flask\n\napp = Flask(__name__)\napp.run(debug=True)\n",
        "app.run(debug=True)",
        "app.run(debug=False)",
    ),
    "PY011": (
        "app/main.py",
        "import random\n\n\ndef new_token(alphabet):\n    token = random.choice(alphabet)\n"
        "    return token\n",
        "    token = random.choice(alphabet)",
        "    token = secrets.choice(alphabet)",
    ),
    "PY014": (
        "app/main.py",
        "import ssl\n\ncontext = ssl._create_unverified_context()\n",
        "context = ssl._create_unverified_context()",
        "context = ssl.create_default_context()",
    ),
    "PY023": (
        "app/main.py",
        'def page(response):\n    response.set_cookie("sid", "1", secure=False)\n'
        "    return response\n",
        '    response.set_cookie("sid", "1", secure=False)',
        '    response.set_cookie("sid", "1", secure=True)',
    ),
    "JS005": (
        "web/hash.js",
        "const crypto = require('crypto')\n"
        "const digest = crypto.createHash('md5').update(input).digest('hex')\n",
        "const digest = crypto.createHash('md5').update(input).digest('hex')",
        "const digest = crypto.createHash('sha256').update(input).digest('hex')",
    ),
    "JS006": (
        "web/agent.js",
        "const agent = new https.Agent({ rejectUnauthorized: false })\n",
        "const agent = new https.Agent({ rejectUnauthorized: false })",
        "const agent = new https.Agent({ rejectUnauthorized: true })",
    ),
    "JV003": (
        "src/Report.java",
        "public class Report {\n"
        "    public byte[] digest(byte[] data) throws Exception {\n"
        '        return java.security.MessageDigest.getInstance("MD5").digest(data);\n'
        "    }\n}\n",
        '        return java.security.MessageDigest.getInstance("MD5").digest(data);',
        '        return java.security.MessageDigest.getInstance("SHA-256").digest(data);',
    ),
    "JV005": (
        "src/Tokens.java",
        "public class Tokens {\n"
        "    public String next() {\n"
        "        String token = Long.toString(new java.util.Random().nextLong());\n"
        "        return token;\n"
        "    }\n}\n",
        "        String token = Long.toString(new java.util.Random().nextLong());",
        "        String token = Long.toString(new java.security.SecureRandom().nextLong());",
    ),
    "JV006": (
        "src/Session.java",
        "public class Session {\n"
        "    public void mark(javax.servlet.http.Cookie cookie) {\n"
        "        cookie.setSecure(false);\n"
        "    }\n}\n",
        "        cookie.setSecure(false);",
        "        cookie.setSecure(true);",
    ),
}


def test_every_built_in_fix_has_a_canonical_case_here() -> None:
    # A fix added to the catalogue without a case in this file would ship
    # having never been through the re-scan.
    assert set(CANONICAL) == set(builtin.FIXES)


@pytest.mark.parametrize("rule_id", sorted(CANONICAL))
def test_each_built_in_fix_rewrites_its_line_and_survives_the_re_scan(
    tmp_path: Path, rule_id: str
) -> None:
    name, text, before, after = CANONICAL[rule_id]

    result = fix(tmp_path, text, rule_id, name)

    assert result.status == VERIFIED, result.reason
    assert result.source == local.BUILTIN
    assert before in removed(result)
    assert after in added(result)
    assert result.outcome is not None and result.outcome.passed
    assert result.title == builtin.FIXES[rule_id].title
    assert result.rationale == builtin.FIXES[rule_id].rationale
    assert result.caution == builtin.FIXES[rule_id].caution


def test_every_built_in_fix_says_what_it_does_and_what_else_changes() -> None:
    for fixer in builtin.FIXES.values():
        assert fixer.title and fixer.rationale and fixer.caution
        # The button text is short enough to be a button.
        assert len(fixer.title) <= 60
        # A fix exists only for a rule the project also explains.
        assert fixer.rule_id in NOTES_BY_RULE


def test_titles_lists_every_rule_with_a_fix_and_nothing_else() -> None:
    titles = builtin.titles()

    assert list(titles) == sorted(builtin.FIXES)
    assert titles["PY007"] == "Use SHA-256 instead of a broken hash"


def test_sql_injection_has_no_built_in_fix() -> None:
    # The placeholder is %s for one driver and ? for another. Choosing is a
    # decision about the code, not a rewrite of a line.
    assert "PY010" not in builtin.FIXES
    assert "SQL001" not in builtin.FIXES


# --- PY004: yaml.load -------------------------------------------------------

YAML = "import yaml\n\n\ndef load(handle):\n    return {call}\n"


@pytest.mark.parametrize(
    ("call", "expected"),
    [
        ("yaml.load(handle)", "yaml.safe_load(handle)"),
        ("yaml.load(handle, yaml.Loader)", "yaml.safe_load(handle)"),
        ("yaml.load(handle, Loader=yaml.Loader)", "yaml.load(handle, Loader=yaml.SafeLoader)"),
        (
            "yaml.load(handle, Loader=yaml.FullLoader)",
            "yaml.load(handle, Loader=yaml.SafeLoader)",
        ),
    ],
)
def test_yaml_load_is_given_the_safe_loader_however_it_was_called(
    tmp_path: Path, call: str, expected: str
) -> None:
    result = fix(tmp_path, YAML.format(call=call), "PY004")

    assert result.status == VERIFIED
    assert added(result) == [f"    return {expected}"]


def test_only_the_call_is_rewritten_not_the_same_words_in_a_string(tmp_path: Path) -> None:
    text = "import yaml\n\n\ndef load(handle):\n    return 'yaml.load(handle)', yaml.load(handle)\n"

    result = fix(tmp_path, text, "PY004")

    assert added(result) == ["    return 'yaml.load(handle)', yaml.safe_load(handle)"]


def test_a_call_after_non_ascii_text_is_edited_in_the_right_place(tmp_path: Path) -> None:
    # The syntax tree counts columns in bytes. An edit made by characters
    # would land two columns early here and corrupt the line.
    text = "import yaml\n\n\ndef load(handle):\n    return 'café ☕', yaml.load(handle)\n"

    result = fix(tmp_path, text, "PY004")

    assert result.status == VERIFIED
    assert added(result) == ["    return 'café ☕', yaml.safe_load(handle)"]


def test_a_call_spread_over_several_lines_is_renamed_where_it_starts(tmp_path: Path) -> None:
    text = "import yaml\n\n\ndef load(handle):\n    return yaml.load(\n        handle,\n    )\n"

    result = fix(tmp_path, text, "PY004")

    assert result.status == VERIFIED
    assert added(result) == ["    return yaml.safe_load("]
    assert result.lines_added == 1 and result.lines_removed == 1


# --- PY007: weak hashes -----------------------------------------------------

HASH = "import hashlib\n\n\ndef digest(value):\n    return {call}\n"


@pytest.mark.parametrize(
    ("call", "expected"),
    [
        ("hashlib.sha1(value).hexdigest()", "hashlib.sha256(value).hexdigest()"),
        ("hashlib.new('md5', value).hexdigest()", "hashlib.new('sha256', value).hexdigest()"),
        ('hashlib.new("sha1", value).hexdigest()', 'hashlib.new("sha256", value).hexdigest()'),
    ],
)
def test_a_weak_hash_becomes_sha256_keeping_the_way_it_was_written(
    tmp_path: Path, call: str, expected: str
) -> None:
    result = fix(tmp_path, HASH.format(call=call), "PY007")

    assert result.status == VERIFIED
    assert added(result) == [f"    return {expected}"]


def test_two_weak_hashes_on_one_line_are_both_rewritten(tmp_path: Path) -> None:
    # Fixing one of them would leave the rule firing on the same line, and the
    # re-scan would — correctly — call that a reworded weakness.
    text = HASH.format(call="hashlib.md5(value).hexdigest() + hashlib.sha1(value).hexdigest()")

    result = fix(tmp_path, text, "PY007")

    assert result.status == VERIFIED
    assert added(result) == [
        "    return hashlib.sha256(value).hexdigest() + hashlib.sha256(value).hexdigest()"
    ]


def test_a_hash_imported_by_name_is_left_for_a_person(tmp_path: Path) -> None:
    # `md5(value)` would have to become `sha256(value)` and the import line
    # changed to match, which may be shared with code this fix has not seen.
    text = "from hashlib import md5\n\n\ndef digest(value):\n    return md5(value).hexdigest()\n"

    result = fix(tmp_path, text, "PY007")

    assert result.status == NO_FIX
    assert result.reason == local.NO_BUILTIN_FOR_LINE
    assert result.diff == "" and result.edits == ()


# --- PY008 / PY009 / PY023: a keyword flipped -------------------------------


def test_only_the_reported_call_has_its_keyword_flipped(tmp_path: Path) -> None:
    # The inner call is somebody else's function with its own `verify`.
    text = (
        "import requests\n\n\ndef fetch(url, timeout_for):\n"
        "    return requests.get(url, verify=False, timeout=timeout_for(verify=False))\n"
    )

    result = fix(tmp_path, text, "PY008")

    assert result.status == VERIFIED
    assert added(result) == [
        "    return requests.get(url, verify=True, timeout=timeout_for(verify=False))"
    ]


def test_the_other_arguments_of_the_call_are_untouched(tmp_path: Path) -> None:
    text = (
        "def page(response):\n"
        '    response.set_cookie("sid", "1", httponly=True, secure=False, samesite="Lax")\n'
    )

    result = fix(tmp_path, text, "PY023")

    assert added(result) == [
        '    response.set_cookie("sid", "1", httponly=True, secure=True, samesite="Lax")'
    ]


def test_debug_is_turned_off_and_the_host_is_left_alone(tmp_path: Path) -> None:
    text = 'from flask import Flask\n\napp = Flask(__name__)\napp.run(host="0.0.0.0", debug=True)\n'

    result = fix(tmp_path, text, "PY009")

    assert added(result) == ['app.run(host="0.0.0.0", debug=False)']


# --- PY011: random -> secrets -----------------------------------------------

RANDOM = "import random\n\n\ndef new_code():\n    {line}\n    return token\n"


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("token = random.randrange(1000000)", "token = secrets.randbelow(1000000)"),
        ("token = random.randint(0, 9)", "token = secrets.randbelow(10)"),
        ("token = random.randint(100000, 999999)", "token = (secrets.randbelow(900000) + 100000)"),
    ],
)
def test_a_random_draw_becomes_the_same_draw_from_secrets(
    tmp_path: Path, line: str, expected: str
) -> None:
    result = fix(tmp_path, RANDOM.format(line=line), "PY011")

    assert result.status == VERIFIED
    assert added(result) == ["import secrets", f"    {expected}"]


def test_randint_keeps_both_ends_of_its_range() -> None:
    # randint(a, b) includes b; randbelow(n) excludes n. Off by one here is a
    # six-sided die that never rolls a six.
    lines = ["import random\n", "token = random.randint(1, 6)\n"]
    finding = Finding(
        rule_id="PY011",
        title="",
        message="",
        severity="MEDIUM",  # type: ignore[arg-type]
        confidence="MEDIUM",  # type: ignore[arg-type]
        cwe_id="CWE-330",
        owasp_category=None,
        file_path="a.py",
        line_start=2,
        line_end=2,
        snippet="token = random.randint(1, 6)",
        analyzer="python-ast",
    )

    after = builtin.FIXES["PY011"].rewrite(lines, finding)

    assert after is not None
    namespace: dict[str, object] = {}
    seen = set()
    for _ in range(400):
        exec("".join(after), namespace)  # noqa: S102 - the code is the two lines above
        seen.add(namespace["token"])
    assert seen == {1, 2, 3, 4, 5, 6}


def test_choices_becomes_a_comprehension_of_secrets_choice(tmp_path: Path) -> None:
    text = (
        "import random\nimport string\n\n\ndef new_password():\n"
        "    password = ''.join(random.choices(string.ascii_letters, k=16))\n"
        "    return password\n"
    )

    result = fix(tmp_path, text, "PY011")

    assert result.status == VERIFIED
    assert added(result) == [
        "import secrets",
        "    password = ''.join([secrets.choice(string.ascii_letters) for _ in range(16)])",
    ]


@pytest.mark.parametrize(
    "line",
    [
        "token = random.random()",  # a float; there is no one-line equivalent
        "token = random.randint(low, high)",  # the width of the range is not known here
        "token = random.randint(-5, 5)",  # only plain whole numbers are worked out
        "token = random.choices(make_alphabet(), k=8)",  # would call make_alphabet eight times
        "token = random.choice(alphabet) + str(random.random())",  # one of two cannot be done
    ],
)
def test_a_draw_with_no_exact_equivalent_is_refused_whole(tmp_path: Path, line: str) -> None:
    text = "import random\n\n\ndef new_code(low, high, alphabet):\n    " + line + "\n"

    result = fix(tmp_path, text, "PY011")

    assert result.status == NO_FIX
    assert result.reason == local.NO_BUILTIN_FOR_LINE
    assert result.diff == ""


def test_the_import_goes_after_the_imports_above_the_fix(tmp_path: Path) -> None:
    text = (
        '"""Codes."""\n'
        "from __future__ import annotations\n"
        "\n"
        "import os\n"
        "import random\n"
        "\n"
        "\n"
        "def new_code():\n"
        "    token = random.randint(0, 9)\n"
        "    return token\n"
    )

    result = fix(tmp_path, text, "PY011")

    assert result.status == VERIFIED
    assert list(result.after[:6]) == [
        '"""Codes."""\n',
        "from __future__ import annotations\n",
        "\n",
        "import os\n",
        "import random\n",
        "import secrets\n",
    ]


def test_with_no_imports_above_it_the_import_goes_under_the_docstring(tmp_path: Path) -> None:
    text = (
        '"""Codes."""\n\n\ndef new_code():\n    import random\n'
        "    token = random.randint(0, 9)\n    return token\n"
    )

    result = fix(tmp_path, text, "PY011")

    assert result.status == VERIFIED
    assert list(result.after[:2]) == ['"""Codes."""\n', "import secrets\n"]


def test_an_existing_import_of_secrets_is_not_repeated(tmp_path: Path) -> None:
    text = (
        "import random\nimport secrets\n\n\ndef new_code():\n"
        "    token = random.randint(0, 9)\n    return token\n"
    )

    result = fix(tmp_path, text, "PY011")

    assert result.status == VERIFIED
    assert added(result) == ["    token = secrets.randbelow(10)"]


@pytest.mark.parametrize(
    "taken",
    [
        "secrets = {}\n",
        "def secrets():\n    return 1\n",
        "import vault as secrets\n",
        "from vault import secrets\n",
    ],
)
def test_a_file_that_already_uses_the_name_secrets_is_left_alone(
    tmp_path: Path, taken: str
) -> None:
    # `import secrets` would shadow it, and `secrets.randbelow` would then be
    # an attribute of whatever the file meant by the name.
    text = (
        "import random\n" + taken + "\n\ndef new_code():\n"
        "    token = random.randint(0, 9)\n    return token\n"
    )

    result = fix(tmp_path, text, "PY011")

    assert result.status == NO_FIX
    assert result.reason == local.NO_BUILTIN_FOR_LINE


def test_a_file_with_windows_line_endings_keeps_them(tmp_path: Path) -> None:
    text = (
        "import random\r\n\r\n\r\ndef new_code():\r\n"
        "    token = random.randint(0, 9)\r\n    return token\r\n"
    )

    result = fix(tmp_path, text, "PY011")

    assert result.status == VERIFIED
    assert all(line.endswith("\r\n") for line in result.after)
    assert "import secrets\r\n" in result.after


# --- PY014 ------------------------------------------------------------------


def test_an_unverified_context_with_arguments_is_left_for_a_person(tmp_path: Path) -> None:
    # The two functions do not take the same arguments.
    text = "import ssl\n\ncontext = ssl._create_unverified_context(cafile='ca.pem')\n"

    result = fix(tmp_path, text, "PY014")

    assert result.status == NO_FIX
    assert result.reason == local.NO_BUILTIN_FOR_LINE


# --- the rewrites that work on text -----------------------------------------


def test_a_text_rewrite_touches_only_the_lines_of_its_finding(tmp_path: Path) -> None:
    text = (
        "public class Report {\n"
        "    public byte[] first(byte[] data) throws Exception {\n"
        '        return java.security.MessageDigest.getInstance("MD5").digest(data);\n'
        "    }\n"
        "    public byte[] second(byte[] data) throws Exception {\n"
        '        return java.security.MessageDigest.getInstance("MD5").digest(data);\n'
        "    }\n}\n"
    )

    result = fix(tmp_path, text, "JV003", "src/Report.java")

    assert result.status == VERIFIED
    assert result.lines_added == 1 and result.lines_removed == 1
    assert result.after[2].count("SHA-256") == 1
    assert '"MD5"' in result.after[5]


def test_math_random_has_no_drop_in_replacement(tmp_path: Path) -> None:
    text = (
        "public class Tokens {\n    public String next() {\n"
        '        String sessionId = "" + Math.random();\n        return sessionId;\n    }\n}\n'
    )

    result = fix(tmp_path, text, "JV005", "src/Tokens.java")

    assert result.status == NO_FIX
    assert result.reason == local.NO_BUILTIN_FOR_LINE


def test_a_random_declared_by_its_short_name_still_compiles_after_the_fix(tmp_path: Path) -> None:
    # SecureRandom extends Random, so the declared type on the left can stay.
    text = (
        "import java.util.Random;\n\npublic class Tokens {\n    public String next() {\n"
        "        Random generator = new Random();\n"
        '        String password = "" + generator.nextInt();\n        return password;\n    }\n}\n'
    )

    result = fix(tmp_path, text, "JV005", "src/Tokens.java")

    assert result.status == VERIFIED
    assert added(result) == ["        Random generator = new java.security.SecureRandom();"]


def test_a_class_whose_name_only_ends_in_random_is_not_rewritten() -> None:
    lines = ["Object source = new MyRandom();\n", "String token = source.toString();\n"]
    finding = Finding(
        rule_id="JV005",
        title="",
        message="",
        severity="MEDIUM",  # type: ignore[arg-type]
        confidence="MEDIUM",  # type: ignore[arg-type]
        cwe_id="CWE-338",
        owasp_category=None,
        file_path="A.java",
        line_start=1,
        line_end=1,
        snippet="",
        analyzer="patterns",
    )

    assert builtin.FIXES["JV005"].rewrite(lines, finding) is None


# --- a rewrite never edits what it did not look at --------------------------


def test_a_finding_whose_line_is_past_the_end_of_the_file_changes_nothing() -> None:
    lines = ["import hashlib\n"]
    finding = Finding(
        rule_id="PY007",
        title="",
        message="",
        severity="MEDIUM",  # type: ignore[arg-type]
        confidence="HIGH",  # type: ignore[arg-type]
        cwe_id="CWE-327",
        owasp_category=None,
        file_path="a.py",
        line_start=40,
        line_end=40,
        snippet="",
        analyzer="python-ast",
    )

    for fixer in builtin.FIXES.values():
        assert fixer.rewrite(lines, finding) is None
    assert lines == ["import hashlib\n"]


def test_a_line_the_parser_and_the_line_list_number_differently_is_not_edited() -> None:
    # A form feed ends a line for str.splitlines but not for Python's parser,
    # so here the tree's line 3 is the list's line 4. The edit must find the
    # words it expects at that position, and they are not there.
    text = "import hashlib\n# section\x0cbreak\nvalue = hashlib.md5(b'').hexdigest()\nother = 1\n"
    lines = text.splitlines(keepends=True)
    assert len(lines) == 5  # the parser counts four
    finding = Finding(
        rule_id="PY007",
        title="",
        message="",
        severity="MEDIUM",  # type: ignore[arg-type]
        confidence="HIGH",  # type: ignore[arg-type]
        cwe_id="CWE-327",
        owasp_category=None,
        file_path="a.py",
        line_start=3,
        line_end=3,
        snippet="",
        analyzer="python-ast",
    )

    assert builtin.FIXES["PY007"].rewrite(lines, finding) is None


def test_a_python_file_that_does_not_parse_is_not_rewritten() -> None:
    lines = ["import hashlib\n", "def broken(:\n", "    return hashlib.md5(b'').hexdigest()\n"]
    finding = Finding(
        rule_id="PY007",
        title="",
        message="",
        severity="MEDIUM",  # type: ignore[arg-type]
        confidence="HIGH",  # type: ignore[arg-type]
        cwe_id="CWE-327",
        owasp_category=None,
        file_path="a.py",
        line_start=3,
        line_end=3,
        snippet="",
        analyzer="python-ast",
    )

    assert builtin.FIXES["PY007"].rewrite(lines, finding) is None


def test_a_rewrite_returns_new_lines_and_leaves_the_ones_it_was_given(tmp_path: Path) -> None:
    root = workspace(tmp_path, CANONICAL["PY007"][1])
    finding = finding_for(root, "PY007")
    lines = (root / "app/main.py").read_text(encoding="utf-8").splitlines(keepends=True)
    original = list(lines)

    after = builtin.FIXES["PY007"].rewrite(lines, finding)

    assert after is not None and after != original
    assert lines == original
