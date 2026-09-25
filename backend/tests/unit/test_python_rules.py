"""Every Python rule, twice: code that must trigger it, and code that must not.

The second half is the half that matters. A rule that fires on safe code trains
people to ignore the tool, and a tool that gets ignored finds nothing — so each
counterexample here is a realistic line that a regex-based scanner would flag
and this one must not.
"""

import pytest

from app.analysis.python_ast import analyze_python_source


def rules_for(source: str) -> set[str]:
    return {finding.rule_id for finding in analyze_python_source(source, "sample.py")}


# --- PY001 eval / exec ----------------------------------------------------


def test_eval_on_a_variable_is_reported() -> None:
    assert "PY001" in rules_for("def run(payload):\n    return eval(payload)\n")


def test_eval_on_a_literal_is_not_reported() -> None:
    # eval("2 + 2") is silly, not dangerous. Flagging it is noise.
    assert "PY001" not in rules_for("value = eval('2 + 2')\n")


def test_a_function_named_eval_elsewhere_is_not_reported() -> None:
    assert "PY001" not in rules_for("model.evaluate(dataset)\nresults = evaluate(dataset)\n")


def test_the_word_eval_in_a_comment_or_string_is_not_reported() -> None:
    source = "# do not use eval(user_input) here\nmessage = 'eval(payload) is unsafe'\n"
    assert "PY001" not in rules_for(source)


# --- PY002 shell=True -----------------------------------------------------


def test_subprocess_with_shell_true_is_reported() -> None:
    assert "PY002" in rules_for("import subprocess\nsubprocess.run(cmd, shell=True)\n")


def test_subprocess_with_an_argument_list_is_not_reported() -> None:
    assert "PY002" not in rules_for("import subprocess\nsubprocess.run(['ls', '-la'])\n")


def test_shell_false_is_not_reported() -> None:
    assert "PY002" not in rules_for("import subprocess\nsubprocess.run(cmd, shell=False)\n")


# --- PY003 os.system ------------------------------------------------------


def test_os_system_is_reported() -> None:
    assert "PY003" in rules_for("import os\nos.system('ls ' + directory)\n")


def test_a_method_called_system_on_another_object_is_not_reported() -> None:
    assert "PY003" not in rules_for("monitor.system('status')\nsystem_name = 'linux'\n")


# --- PY004 yaml.load ------------------------------------------------------


def test_yaml_load_without_a_loader_is_reported() -> None:
    assert "PY004" in rules_for("import yaml\nconfig = yaml.load(stream)\n")


def test_yaml_safe_load_is_not_reported() -> None:
    assert "PY004" not in rules_for("import yaml\nconfig = yaml.safe_load(stream)\n")


def test_yaml_load_with_an_explicit_safe_loader_is_not_reported() -> None:
    source = "import yaml\nconfig = yaml.load(stream, Loader=yaml.SafeLoader)\n"
    assert "PY004" not in rules_for(source)


# --- PY005 pickle ---------------------------------------------------------


def test_pickle_loads_is_reported() -> None:
    assert "PY005" in rules_for("import pickle\nvalue = pickle.loads(payload)\n")


def test_pickle_dumps_is_not_reported() -> None:
    # Writing a pickle is not the dangerous half.
    assert "PY005" not in rules_for("import pickle\nblob = pickle.dumps(value)\n")


# --- PY006 hardcoded secrets ---------------------------------------------


def test_a_hardcoded_password_is_reported() -> None:
    assert "PY006" in rules_for("DB_PASSWORD = 'sup3rs3cret-value-123'\n")


def test_the_secret_value_is_never_stored() -> None:
    findings = analyze_python_source("API_TOKEN = 'ghp_realtokenvalue1234567890'\n", "s.py")
    secret_findings = [f for f in findings if f.rule_id == "PY006"]
    assert secret_findings, "the finding must exist"
    for finding in secret_findings:
        assert "ghp_realtokenvalue1234567890" not in finding.snippet
        assert "redacted" in finding.snippet


def test_a_password_read_from_the_environment_is_not_reported() -> None:
    source = "import os\nDB_PASSWORD = os.environ['DB_PASSWORD']\n"
    assert "PY006" not in rules_for(source)


def test_an_obvious_placeholder_is_not_reported() -> None:
    assert "PY006" not in rules_for("PASSWORD = 'changeme'\nSECRET = 'your_password_here'\n")


def test_a_template_reference_is_not_reported() -> None:
    assert "PY006" not in rules_for("PASSWORD = '${DB_PASSWORD}'\n")


def test_a_short_value_is_not_reported() -> None:
    assert "PY006" not in rules_for("PASSWORD = 'abc'\n")


# --- PY007 weak hashes ----------------------------------------------------


def test_md5_is_reported() -> None:
    assert "PY007" in rules_for("import hashlib\ndigest = hashlib.md5(data).hexdigest()\n")


def test_hashlib_new_md5_is_reported() -> None:
    assert "PY007" in rules_for("import hashlib\ndigest = hashlib.new('md5')\n")


def test_sha256_is_not_reported() -> None:
    assert "PY007" not in rules_for("import hashlib\ndigest = hashlib.sha256(data)\n")


# --- PY008 / PY014 TLS ----------------------------------------------------


def test_requests_with_verify_false_is_reported() -> None:
    assert "PY008" in rules_for("import requests\nrequests.get(url, verify=False)\n")


def test_requests_with_a_ca_bundle_is_not_reported() -> None:
    assert "PY008" not in rules_for("import requests\nrequests.get(url, verify='/ca.pem')\n")


def test_an_unverified_ssl_context_is_reported() -> None:
    assert "PY014" in rules_for("import ssl\nctx = ssl._create_unverified_context()\n")


def test_a_default_ssl_context_is_not_reported() -> None:
    assert "PY014" not in rules_for("import ssl\nctx = ssl.create_default_context()\n")


# --- PY009 Flask debug ----------------------------------------------------


def test_flask_debug_true_is_reported() -> None:
    assert "PY009" in rules_for("app.run(host='0.0.0.0', debug=True)\n")


def test_debug_from_configuration_is_not_reported() -> None:
    assert "PY009" not in rules_for("app.run(host='127.0.0.1', debug=settings.DEBUG)\n")


# --- PY010 SQL ------------------------------------------------------------


def test_an_f_string_query_is_reported() -> None:
    source = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
    assert "PY010" in rules_for(source)


def test_a_concatenated_query_is_reported() -> None:
    source = 'cursor.execute("SELECT * FROM users WHERE name = \'" + name + "\'")\n'
    assert "PY010" in rules_for(source)


def test_a_percent_formatted_query_is_reported() -> None:
    source = 'cursor.execute("DELETE FROM sessions WHERE id = %s" % session_id)\n'
    assert "PY010" in rules_for(source)


def test_a_parameterised_query_is_not_reported() -> None:
    source = 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
    assert "PY010" not in rules_for(source)


def test_an_f_string_that_is_not_sql_is_not_reported() -> None:
    # execute() on something that is not a database, with no SQL keywords.
    assert "PY010" not in rules_for('runner.execute(f"job-{job_id}")\n')


# --- PY011 weak randomness ------------------------------------------------


def test_random_used_for_a_token_is_reported() -> None:
    source = "import random\nsession_token = random.choice(alphabet)\n"
    assert "PY011" in rules_for(source)


def test_random_used_for_something_harmless_is_not_reported() -> None:
    source = "import random\ncolour = random.choice(['red', 'green'])\n"
    assert "PY011" not in rules_for(source)


# --- PY012 mktemp ---------------------------------------------------------


def test_mktemp_is_reported() -> None:
    assert "PY012" in rules_for("import tempfile\npath = tempfile.mktemp()\n")


def test_mkstemp_is_not_reported() -> None:
    assert "PY012" not in rules_for("import tempfile\nhandle, path = tempfile.mkstemp()\n")


# --- PY013 JWT ------------------------------------------------------------


def test_jwt_decoded_without_verification_is_reported() -> None:
    source = 'import jwt\nclaims = jwt.decode(token, options={"verify_signature": False})\n'
    assert "PY013" in rules_for(source)


def test_jwt_decode_with_verify_false_is_reported() -> None:
    assert "PY013" in rules_for("import jwt\nclaims = jwt.decode(token, verify=False)\n")


def test_a_verified_jwt_decode_is_not_reported() -> None:
    source = 'import jwt\nclaims = jwt.decode(token, key, algorithms=["HS256"])\n'
    assert "PY013" not in rules_for(source)


# --- PY015 XML ------------------------------------------------------------


def test_stdlib_xml_parsing_is_reported() -> None:
    source = "from xml.etree import ElementTree\ntree = ElementTree.parse(path)\n"
    assert "PY015" in rules_for(source)


def test_defusedxml_is_not_reported() -> None:
    source = "from defusedxml import ElementTree\ntree = ElementTree.parse(path)\n"
    assert "PY015" not in rules_for(source)


# --- general behaviour ----------------------------------------------------


def test_clean_code_produces_nothing() -> None:
    source = (
        "import hashlib\n"
        "import os\n"
        "import secrets\n"
        "import subprocess\n"
        "\n"
        "PASSWORD = os.environ['PASSWORD']\n"
        "\n"
        "def run(user_id, cursor):\n"
        "    token = secrets.token_urlsafe(32)\n"
        "    digest = hashlib.sha256(token.encode()).hexdigest()\n"
        "    subprocess.run(['git', 'status'], check=True)\n"
        "    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
        "    return digest\n"
    )
    assert rules_for(source) == set(), "well-written code must produce no findings at all"


def test_line_numbers_point_at_the_problem() -> None:
    source = "import os\n\n\nos.system(command)\n"
    finding = next(f for f in analyze_python_source(source, "s.py") if f.rule_id == "PY003")
    assert finding.line_start == 4


def test_findings_are_deterministic() -> None:
    source = "import os\nos.system(cmd)\nPASSWORD = 'a-real-looking-secret'\n"
    first = analyze_python_source(source, "s.py")
    second = analyze_python_source(source, "s.py")
    assert [f.fingerprint for f in first] == [f.fingerprint for f in second]


def test_a_fingerprint_survives_a_line_moving() -> None:
    """Adding an import must not turn every finding below it into a new one."""
    before = analyze_python_source("import os\nos.system(cmd)\n", "s.py")
    after = analyze_python_source("import os\nimport sys\nos.system(cmd)\n", "s.py")
    assert before[0].fingerprint == after[0].fingerprint


def test_a_file_that_does_not_parse_raises_for_the_engine_to_handle() -> None:
    with pytest.raises(SyntaxError):
        analyze_python_source("def broken(:\n", "s.py")
