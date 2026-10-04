"""Every Python rule, twice: code that must trigger it, and code that must not.

The second half is the half that matters. A rule that fires on safe code trains
people to ignore the tool, and a tool that gets ignored finds nothing — so each
counterexample here is a realistic line that a regex-based scanner would flag
and this one must not.
"""

import pytest

from app.analysis.python_ast import analyze_python_source
from tests.helpers import GITHUB_TOKEN


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
    findings = analyze_python_source(f"API_TOKEN = '{GITHUB_TOKEN}'\n", "s.py")
    secret_findings = [f for f in findings if f.rule_id == "PY006"]
    assert secret_findings, "the finding must exist"
    for finding in secret_findings:
        assert GITHUB_TOKEN not in finding.snippet
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


def test_a_query_built_with_format_on_a_literal_is_reported() -> None:
    """The form the rule's own docstring promised and did not deliver.

    `"SELECT …".format(x)` is a call on a literal, and a literal has no dotted
    name, so the check that looked for a name ending in `.format` never matched
    the commonest way it is written. Found in Phase 11, when a model's "fix"
    that swapped an f-string for `.format()` would have been validated: a
    re-scan is only as good as the rules it re-runs.
    """
    source = 'cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))\n'
    assert "PY010" in rules_for(source)


def test_a_query_built_with_format_on_a_variable_is_reported() -> None:
    source = 'cursor.execute("SELECT * FROM {} WHERE id = 1".format(table).format(x))\n'
    assert "PY010" in rules_for(source)


def test_format_on_something_that_is_not_sql_is_not_reported() -> None:
    assert "PY010" not in rules_for('runner.execute("job-{}".format(job_id))\n')


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


# =============================================================================
# What reaches the call (Phase 16)
#
# The rules above recognise a call by its shape. Measured against a benchmark
# with known answers, shape alone reported safe code as often as vulnerable
# code. The tests below are about the other half: a rule for a call that is
# dangerous by nature stays silent when its argument is *shown* to be built
# from literals, and a rule for an ordinary call speaks only when request data
# is *shown* to reach it.
# =============================================================================

FLASK = "from flask import Flask, request\nimport os\nimport subprocess\napp = Flask(__name__)\n\n"


def route(body: str, rule: str = "/x") -> str:
    lines = "".join(f"    {line}\n" for line in body.strip("\n").splitlines())
    return f"{FLASK}@app.route({rule!r})\ndef view():\n{lines}"


def findings_for(source: str) -> list:  # type: ignore[type-arg]
    return analyze_python_source(source, "sample.py")


def one(source: str, rule_id: str):  # type: ignore[no-untyped-def]
    matching = [finding for finding in findings_for(source) if finding.rule_id == rule_id]
    assert len(matching) == 1, [finding.rule_id for finding in findings_for(source)]
    return matching[0]


# --- calls that are dangerous by nature ---------------------------------------


@pytest.mark.parametrize(
    ("rule_id", "call"),
    [
        ("PY003", "os.system({})"),
        ("PY003", "os.popen({})"),
        ("PY002", "subprocess.run({}, shell=True)"),
        ("PY001", "eval({})"),
        ("PY001", "exec({})"),
        ("PY005", "pickle.loads({})"),
        ("PY004", "yaml.load({})"),
    ],
)
def test_a_dangerous_call_is_reported_for_request_data_and_for_the_unknown_and_not_for_literals(
    rule_id: str, call: str
) -> None:
    prefix = "import pickle\nimport yaml\n"
    tainted = prefix + route(f"value = request.args['q']\n{call.format('value')}")
    unknown = prefix + route(call.format("value_from_elsewhere"))
    literal = prefix + route(f"value = 'fixed ' + 'text'\n{call.format('value')}")

    assert rule_id in rules_for(tainted)
    assert rule_id in rules_for(unknown)
    assert rule_id not in rules_for(literal)


def test_a_finding_that_was_shown_says_where_the_value_came_from() -> None:
    source = route("command = request.args['q']\nos.system('ping ' + command)")
    finding = one(source, "PY003")

    assert finding.confidence == "HIGH"
    assert "comes from the request, read on line 8" in finding.message
    assert finding.line_start == 9


def test_a_finding_that_was_not_shown_keeps_the_rules_own_wording() -> None:
    finding = one("import os\nos.system(command)\n", "PY003")

    assert "comes from the request" not in finding.message


def test_a_command_that_a_check_made_safe_is_not_reported() -> None:
    body = """
action = request.args['q']
if action not in ('start', 'stop'):
    return 'bad'
os.system('service app ' + action)
"""
    assert "PY003" not in rules_for(route(body))


def test_a_command_on_a_branch_that_never_runs_is_not_reported() -> None:
    source = "import os\nENABLED = False\nif ENABLED:\n    os.system(command)\n"
    assert "PY003" not in rules_for(source)


def test_a_command_inside_a_lambda_is_still_reported() -> None:
    """The walk does not look inside a lambda. Not looked at is not safe."""
    assert "PY003" in rules_for("import os\nrun = lambda command: os.system(command)\n")


def test_a_file_the_walk_gives_up_on_is_reported_as_before(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.analysis import python_flow

    monkeypatch.setattr(python_flow, "MAX_STEPS", 1)

    # Even the literal: with nothing known, the rule is back to judging by shape.
    assert "PY003" in rules_for("import os\nos.system('ls')\n")
    assert "PY017" not in rules_for(route("open(request.args['q'])"))


# --- PY010 SQL ---------------------------------------------------------------------


def test_request_data_in_a_query_is_reported_however_the_query_was_passed() -> None:
    body = """
name = request.args['q']
sql = "SELECT * FROM users WHERE name = '" + name + "'"
cursor.execute(sql)
"""
    finding = one(route(body), "PY010")

    assert finding.confidence == "HIGH"
    assert finding.line_start == 10


def test_a_query_built_on_an_earlier_line_from_something_unknown_is_reported() -> None:
    source = (
        "def find(cursor, name):\n"
        "    sql = 'SELECT * FROM users WHERE name = ' + name\n"
        "    cursor.execute(sql)\n"
    )
    assert one(source, "PY010").confidence == "MEDIUM"


def test_a_query_built_only_from_literals_is_not_reported() -> None:
    source = "TABLE = 'users'\n\ndef find(cursor):\n    cursor.execute(f'SELECT * FROM {TABLE}')\n"
    assert "PY010" not in rules_for(source)


def test_a_parameterised_query_is_not_reported_when_the_value_is_request_data() -> None:
    body = "cursor.execute('SELECT * FROM users WHERE name = ?', (request.args['q'],))"
    assert "PY010" not in rules_for(route(body))


# --- PY011 weak randomness that ends up as a secret ----------------------------------


def test_a_weak_random_number_stored_in_a_session_is_reported_where_it_was_made() -> None:
    body = """
import random
value = str(random.getrandbits(64))
remembered[cookie_name] = 'x'
session_store[cookie_name] = value
"""
    finding = one(route(body), "PY011")

    assert finding.line_start == 9
    assert "getrandbits" in finding.snippet


def test_a_weak_random_number_used_as_a_cookie_value_is_reported() -> None:
    body = """
import random
value = str(random.random())
response.set_cookie('remember', value)
"""
    assert "PY011" in rules_for(route(body))


def test_a_weak_random_number_given_a_secret_name_later_is_reported() -> None:
    source = "import random\nvalue = random.randint(0, 999999)\nreset_token = value\n"
    assert one(source, "PY011").line_start == 2


def test_a_secure_random_number_stored_in_a_session_is_not_reported() -> None:
    body = """
import random, secrets
session_store['a'] = str(random.SystemRandom().getrandbits(64))
session_store['b'] = secrets.token_urlsafe(32)
"""
    assert "PY011" not in rules_for(route(body))


def test_a_weak_random_number_that_goes_nowhere_secret_is_not_reported() -> None:
    assert "PY011" not in rules_for("import random\ndelay = random.random()\nwait(delay)\n")


def test_one_weak_random_number_is_one_finding_however_it_was_noticed() -> None:
    source = "import random\nsession_token = random.random()\nsession_store['t'] = session_token\n"
    assert len([f for f in findings_for(source) if f.rule_id == "PY011"]) == 1


# --- PY015 a parser told to resolve external entities ---------------------------------

XXE = """
import xml.sax, xml.sax.handler, xml.dom.minidom
parser = xml.sax.make_parser()
{feature}
document = xml.dom.minidom.parseString({data}, parser)
"""
ENABLE = "parser.setFeature(xml.sax.handler.feature_external_ges, True)"


def test_a_parser_with_external_entities_enabled_is_reported_when_it_parses_input() -> None:
    finding = one(route(XXE.format(feature=ENABLE, data="request.data")), "PY015")

    assert finding.severity == "HIGH"
    assert "feature_external_ges" in finding.message


def test_the_same_parser_without_the_feature_is_not_reported() -> None:
    assert "PY015" not in rules_for(route(XXE.format(feature="", data="request.data")))
    disabled = ENABLE.replace("True", "False")
    assert "PY015" not in rules_for(route(XXE.format(feature=disabled, data="request.data")))


def test_the_same_parser_given_a_document_written_in_the_source_is_not_reported() -> None:
    assert "PY015" not in rules_for(route(XXE.format(feature=ENABLE, data="'<a/>'")))


# --- PY016 a command list that starts a shell ------------------------------------------


def test_request_data_in_a_list_that_starts_a_shell_is_reported() -> None:
    body = "subprocess.run(['sh', '-c', 'echo ' + request.args['q']])"
    assert one(route(body), "PY016").severity == "CRITICAL"


def test_a_shell_chosen_at_run_time_from_two_literals_is_still_a_shell() -> None:
    body = """
arguments = []
if windows:
    arguments.append('cmd.exe')
    arguments.append('/c')
else:
    arguments.append('/bin/sh')
    arguments.append('-c')
arguments.append('echo ' + request.args['q'])
subprocess.run(arguments)
"""
    assert "PY016" in rules_for(route(body))


def test_request_data_as_the_program_to_run_is_reported() -> None:
    assert "PY016" in rules_for(route("subprocess.run([request.args['q'], '--version'])"))
    assert "PY016" in rules_for(route("subprocess.run(request.args['q'].split())"))


def test_request_data_as_an_argument_of_a_fixed_program_is_not_command_injection() -> None:
    assert "PY016" not in rules_for(route("subprocess.run(['ping', '-c', '1', request.args['q']])"))


def test_a_list_of_literals_is_not_reported() -> None:
    assert "PY016" not in rules_for(route("subprocess.run(['sh', '-c', 'echo hello'])"))


# --- PY017 path traversal -----------------------------------------------------------------


@pytest.mark.parametrize(
    "use",
    [
        "open('/data/' + name)",
        "open(f'/data/{name}', 'rb')",
        "os.remove('/data/' + name)",
        "os.path.exists('/data/' + name)",
        "codecs.open('/data/' + name, 'r', 'utf-8')",
        "(pathlib.Path('/data') / name).read_text()",
        "pathlib.Path('/data', name).exists()",
    ],
)
def test_request_data_used_as_a_file_path_is_reported(use: str) -> None:
    source = "import codecs, pathlib\n" + route(f"name = request.args['q']\n{use}")
    assert "PY017" in rules_for(source)


def test_opening_a_file_is_not_a_finding_on_its_own() -> None:
    assert "PY017" not in rules_for("def read(path):\n    return open(path).read()\n")
    assert "PY017" not in rules_for("data = open('settings.json').read()\n")


@pytest.mark.parametrize(
    "guard",
    [
        "if '../' in name:\n    return 'bad'",
        "if '..' in name:\n    return 'bad'",
        "name = os.path.basename(name)",
        "if name not in ('a.txt', 'b.txt'):\n    return 'bad'",
    ],
)
def test_a_path_that_was_checked_or_reduced_to_a_file_name_is_not_reported(guard: str) -> None:
    body = f"name = request.args['q']\n{guard}\nopen('/data/' + name)"
    assert "PY017" not in rules_for(route(body))


def test_a_resolved_path_checked_against_its_base_is_not_reported() -> None:
    body = """
import pathlib
base = pathlib.Path('/data')
target = (base / request.args['q']).resolve()
if not str(target).startswith(str(base)):
    return 'bad'
return_value = target.read_text()
"""
    assert "PY017" not in rules_for(route(body))


def test_a_method_called_open_on_something_that_is_not_a_path_is_not_reported() -> None:
    assert "PY017" not in rules_for(route("archive.open(request.args['q'])"))


# --- PY018 XPath, PY019 LDAP ----------------------------------------------------------------


@pytest.mark.parametrize(
    "use",
    [
        "tree.xpath(query)",
        "elementpath.select(tree, query)",
        "lxml.etree.XPath(query)",
    ],
)
def test_request_data_in_an_xpath_expression_is_reported(use: str) -> None:
    body = f"""
import elementpath, lxml.etree
query = "/users/user[@id='" + request.args['q'] + "']"
{use}
"""
    assert "PY018" in rules_for(route(body))


def test_an_xpath_variable_is_not_reported() -> None:
    body = "tree.xpath('/users/user[@id=$ident]', ident=request.args['q'])"
    assert "PY018" not in rules_for(route(body))


def test_an_xpath_value_with_its_quotes_replaced_or_rejected_is_not_reported() -> None:
    replaced = """tree.xpath("/u[@id='" + request.args['q'].replace("'", "&apos;") + "']")"""
    rejected = """
ident = request.args['q']
if "'" in ident:
    return 'bad'
tree.xpath("/u[@id='" + ident + "']")
"""
    assert "PY018" not in rules_for(route(replaced))
    assert "PY018" not in rules_for(route(rejected))


def test_request_data_in_an_ldap_filter_is_reported() -> None:
    body = """
import ldap3
connection.search('ou=users', f"(uid={request.args['q']})", attributes=ldap3.ALL_ATTRIBUTES)
"""
    assert "PY019" in rules_for(route(body))


def test_an_escaped_ldap_filter_is_not_reported() -> None:
    body = """
import ldap3
from ldap3.utils.conv import escape_filter_chars
connection.search('ou=users', '(uid=' + escape_filter_chars(request.args['q']) + ')')
"""
    assert "PY019" not in rules_for(route(body))


def test_a_method_called_search_in_a_file_that_does_not_use_ldap_is_not_reported() -> None:
    assert "PY019" not in rules_for(route("index.search('users', request.args['q'])"))


# --- PY020 open redirect -----------------------------------------------------------------------


def test_a_redirect_to_an_address_from_the_request_is_reported() -> None:
    source = "from flask import redirect\n" + route("return redirect(request.args['next'])")
    assert one(source, "PY020").severity == "MEDIUM"


@pytest.mark.parametrize(
    "destination",
    [
        "'/orders/' + request.args['q']",
        "f'/orders/{request.args[\"q\"]}'",
        "'https://example.com/orders/' + request.args['q']",
        "url_for('orders', number=request.args['q'])",
        "request.path",
    ],
)
def test_a_redirect_that_can_only_stay_on_this_site_is_not_reported(destination: str) -> None:
    source = "from flask import redirect, url_for\n" + route(f"return redirect({destination})")
    assert "PY020" not in rules_for(source)


@pytest.mark.parametrize(
    "destination", ["'/' + request.args['q']", "'https://' + request.args['q']"]
)
def test_a_prefix_that_does_not_fix_the_host_is_still_reported(destination: str) -> None:
    """``/`` + ``/evil.example`` is another site."""
    source = "from flask import redirect\n" + route(f"return redirect({destination})")
    assert "PY020" in rules_for(source)


def test_a_redirect_whose_host_was_checked_is_not_reported() -> None:
    body = """
from urllib.parse import urlparse
target = request.args['next']
if urlparse(target).netloc not in ('example.com',):
    return 'bad'
return redirect(target)
"""
    assert "PY020" not in rules_for("from flask import redirect\n" + route(body))


# --- PY021 reflected XSS ------------------------------------------------------------------------


def test_request_data_returned_from_a_flask_route_is_reported() -> None:
    finding = one(route("return 'Hello ' + request.args['name']"), "PY021")

    assert finding.confidence == "MEDIUM"
    assert "read on line 8" in finding.message


@pytest.mark.parametrize(
    "response",
    [
        "'Hello ' + html.escape(request.args['name'])",
        "'Hello ' + str(markupsafe.escape(request.args['name']))",
        "render_template('hello.html', name=request.args['name'])",
        "jsonify(name=request.args['name'])",
        "{'name': request.args['name']}",
        "str(int(request.args['count']))",
        "request.method",
    ],
)
def test_a_response_that_is_escaped_or_is_not_a_page_is_not_reported(response: str) -> None:
    source = "import html, markupsafe\nfrom flask import render_template, jsonify\n" + route(
        f"return {response}"
    )
    assert "PY021" not in rules_for(source)


def test_a_value_in_a_response_header_is_not_a_value_in_the_page() -> None:
    body = "return make_response(('done', {'X-Echo': request.args['q']}))"
    assert "PY021" not in rules_for("from flask import make_response\n" + route(body))


def test_a_helper_that_returns_request_data_is_not_itself_a_response() -> None:
    source = FLASK + "def read():\n    return request.args['q']\n"
    assert "PY021" not in rules_for(source)


def test_a_string_returned_from_a_json_framework_route_is_not_a_page() -> None:
    source = (
        "from fastapi import FastAPI\napp = FastAPI()\n\n"
        "@app.get('/echo')\ndef echo(text: str):\n    return 'you said ' + text\n"
    )
    assert "PY021" not in rules_for(source)


def test_request_data_given_to_a_django_response_is_reported() -> None:
    source = (
        "from django.http import HttpResponse\n\n"
        "def view(request):\n    return HttpResponse('Hello ' + request.GET['name'])\n"
    )
    assert "PY021" in rules_for(source)


def test_a_rendered_template_given_to_a_django_response_is_not_reported() -> None:
    source = (
        "from django.http import HttpResponse\n\n"
        "def view(request, template):\n"
        "    return HttpResponse(template.render({'name': request.GET['name']}))\n"
    )
    assert "PY021" not in rules_for(source)


def test_one_value_leaving_through_several_returns_is_one_finding() -> None:
    body = """
name = request.args['name']
if flag:
    return 'Hello ' + name
return 'Goodbye ' + name
"""
    finding = one(route(body), "PY021")

    assert finding.line_start == 10  # the first place it leaves


def test_two_values_from_the_request_are_two_findings() -> None:
    body = """
if flag:
    return 'Hello ' + request.args['name']
return 'Goodbye ' + request.args['other']
"""
    assert len([f for f in findings_for(route(body)) if f.rule_id == "PY021"]) == 2


def test_a_url_parameter_that_is_text_is_reported_and_one_that_is_a_number_is_not() -> None:
    source = (
        FLASK
        + "@app.route('/a/<name>')\ndef a(name):\n    return 'Hello ' + name\n\n"
        + "@app.route('/b/<int:number>')\ndef b(number):\n    return 'Number ' + str(number)\n"
    )
    assert [f.line_start for f in findings_for(source) if f.rule_id == "PY021"] == [8]


# --- PY022 trust boundary, PY023 cookie ----------------------------------------------------------


def test_request_data_stored_in_the_session_is_reported() -> None:
    value = "from flask import session\n" + route("session['user'] = request.form['user']")
    key = "import flask\n" + route("flask.session[request.form['key']] = '1'")

    assert "PY022" in rules_for(value)
    assert "PY022" in rules_for(key)


def test_a_validated_value_or_a_literal_stored_in_the_session_is_not_reported() -> None:
    body = """
role = request.form['role']
if role not in ('reader', 'editor'):
    return 'bad'
session['role'] = role
session['seen'] = 'yes'
"""
    assert "PY022" not in rules_for("from flask import session\n" + route(body))


def test_request_data_stored_in_some_other_mapping_is_not_a_trust_boundary_finding() -> None:
    assert "PY022" not in rules_for(route("cache['user'] = request.form['user']"))


def test_a_cookie_set_with_secure_false_is_reported() -> None:
    finding = one("response.set_cookie('id', value, secure=False, httponly=True)\n", "PY023")

    assert finding.cwe_id == "CWE-614"


def test_a_cookie_set_with_secure_true_or_without_saying_is_not_reported() -> None:
    assert "PY023" not in rules_for("response.set_cookie('id', value, secure=True)\n")
    assert "PY023" not in rules_for("response.set_cookie('id', value)\n")
    assert "PY023" not in rules_for("response.set_cookie('id', value, secure=is_production)\n")


# --- every new rule declares what it is ------------------------------------------------


def test_the_new_rules_declare_a_weakness_and_a_category() -> None:
    from app.analysis.rules import RULES_BY_ID

    expected = {
        "PY016": "CWE-78",
        "PY017": "CWE-22",
        "PY018": "CWE-643",
        "PY019": "CWE-90",
        "PY020": "CWE-601",
        "PY021": "CWE-79",
        "PY022": "CWE-501",
        "PY023": "CWE-614",
    }
    for rule_id, cwe in expected.items():
        rule = RULES_BY_ID[rule_id]
        assert rule.cwe_id == cwe
        assert rule.owasp_category and rule.owasp_category[0] == "A"
        assert rule.message.endswith(".")


# --- found by breaking a rule on purpose and seeing no test fail --------------------------


def test_a_command_run_with_shell_true_is_one_rule_not_two() -> None:
    found = rules_for(route("subprocess.run(request.args['q'], shell=True)"))

    assert "PY002" in found
    assert "PY016" not in found


def test_a_method_that_shares_a_name_with_a_path_method_needs_a_path() -> None:
    body = "handle = connect(request.args['q'])\nhandle.open()\nhandle.exists()"
    assert "PY017" not in rules_for(route(body))


def test_what_a_helper_returns_is_not_what_the_route_returns() -> None:
    source = FLASK + (
        "def label(text):\n    return 'label: ' + text\n\n"
        "@app.route('/x')\ndef view():\n    audit(label(request.args['q']))\n    return 'ok'\n"
    )
    assert "PY021" not in rules_for(source)
