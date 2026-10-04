"""Pattern rules and secret detection — each with its counterexample.

These analysers have no parser behind them, so the counterexamples matter even
more than they do for Python: a regex that cannot tell code from a comment will
happily report a line that says "do not use eval here".
"""

import pytest

from app.analysis.patterns import analyze_with_patterns
from app.analysis.secrets import analyze_secrets
from tests.helpers import AWS_ACCESS_KEY_ID as AWS_KEY
from tests.helpers import GITHUB_TOKEN, PRIVATE_KEY_BODY, PRIVATE_KEY_HEADER


def pattern_rules(source: str, suffix: str = ".js") -> set[str]:
    return {f.rule_id for f in analyze_with_patterns(source, f"sample{suffix}", suffix)}


def secret_rules(source: str) -> set[str]:
    return {f.rule_id for f in analyze_secrets(source, "sample.env")}


# --- JavaScript -----------------------------------------------------------


def test_eval_on_a_variable_is_reported() -> None:
    assert "JS001" in pattern_rules("const result = eval(userInput);")


def test_eval_on_a_literal_is_not_reported() -> None:
    assert "JS001" not in pattern_rules("const two = eval('1 + 1');")


def test_eval_in_a_comment_is_not_reported() -> None:
    assert "JS001" not in pattern_rules("// never call eval(userInput) here")


def test_exec_with_interpolation_is_reported() -> None:
    assert "JS002" in pattern_rules("exec(`git clone ${repoUrl}`)")


def test_exec_with_a_fixed_command_is_not_reported() -> None:
    assert "JS002" not in pattern_rules("exec('git status')")


def test_execfile_with_an_argument_array_is_not_reported() -> None:
    assert "JS002" not in pattern_rules("execFile('git', ['clone', repoUrl])")


def test_inner_html_from_a_variable_is_reported() -> None:
    assert "JS003" in pattern_rules("element.innerHTML = userComment;")


def test_inner_html_from_a_literal_is_not_reported() -> None:
    assert "JS003" not in pattern_rules("element.innerHTML = '<b>Loading…</b>';")


def test_text_content_is_not_reported() -> None:
    assert "JS003" not in pattern_rules("element.textContent = userComment;")


def test_math_random_for_a_token_is_reported() -> None:
    assert "JS004" in pattern_rules("const sessionToken = Math.random().toString(36);")


def test_math_random_for_an_animation_is_not_reported() -> None:
    assert "JS004" not in pattern_rules("const offset = Math.random() * width;")


def test_md5_is_reported() -> None:
    assert "JS005" in pattern_rules("crypto.createHash('md5').update(password)")


def test_sha256_is_not_reported() -> None:
    assert "JS005" not in pattern_rules("crypto.createHash('sha256').update(data)")


def test_disabled_tls_is_reported() -> None:
    assert "JS006" in pattern_rules("const agent = new https.Agent({ rejectUnauthorized: false })")


def test_enabled_tls_is_not_reported() -> None:
    source = "const agent = new https.Agent({ rejectUnauthorized: true })"
    assert "JS006" not in pattern_rules(source)


# --- Java -----------------------------------------------------------------


def test_runtime_exec_with_concatenation_is_reported() -> None:
    source = 'Runtime.getRuntime().exec("ping " + host);'
    assert "JV001" in pattern_rules(source, ".java")


def test_runtime_exec_with_a_fixed_command_is_not_reported() -> None:
    assert "JV001" not in pattern_rules('Runtime.getRuntime().exec("uptime");', ".java")


def test_object_input_stream_is_reported() -> None:
    source = "ObjectInputStream in = new ObjectInputStream(socket);"
    assert "JV002" in pattern_rules(source, ".java")


def test_java_md5_is_reported() -> None:
    assert "JV003" in pattern_rules('MessageDigest.getInstance("MD5");', ".java")


def test_java_sha256_is_not_reported() -> None:
    assert "JV003" not in pattern_rules('MessageDigest.getInstance("SHA-256");', ".java")


# --- SQL, PHP, Go ---------------------------------------------------------


def test_concatenated_sql_is_reported() -> None:
    source = 'String q = "SELECT * FROM users WHERE id = " + userId;'
    assert "SQL001" in pattern_rules(source, ".java")


def test_a_prepared_statement_is_not_reported() -> None:
    source = 'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");'
    assert "SQL001" not in pattern_rules(source, ".java")


def test_php_command_execution_is_reported() -> None:
    assert "PH001" in pattern_rules("<?php system($command); ?>", ".php")


def test_php_shell_exec_with_a_variable_is_reported() -> None:
    assert "PH001" in pattern_rules("<?php shell_exec($userInput); ?>", ".php")


def test_php_escaped_argument_is_still_reported_but_literal_is_not() -> None:
    # A literal command is not user input; the rule requires a variable.
    assert "PH001" not in pattern_rules("<?php system('uptime'); ?>", ".php")


def test_go_shell_invocation_is_reported() -> None:
    assert "GO001" in pattern_rules('exec.Command("sh", "-c", command)', ".go")


def test_go_direct_invocation_is_not_reported() -> None:
    assert "GO001" not in pattern_rules('exec.Command("git", "status")', ".go")


def test_rules_do_not_apply_to_other_languages() -> None:
    # A Java rule must not fire inside a Go file, and vice versa.
    assert pattern_rules('MessageDigest.getInstance("MD5");', ".go") == set()


# --- secrets --------------------------------------------------------------


def test_an_aws_key_is_reported_and_redacted() -> None:
    findings = analyze_secrets(f"AWS_ACCESS_KEY_ID={AWS_KEY}\n", ".env")
    assert [f.rule_id for f in findings] == ["SEC001"]
    assert AWS_KEY not in findings[0].snippet
    assert "redacted" in findings[0].snippet


def test_a_private_key_block_is_reported() -> None:
    assert "SEC002" in secret_rules(f"{PRIVATE_KEY_HEADER}\n{PRIVATE_KEY_BODY}\n")


@pytest.mark.parametrize(
    "source",
    [
        # A key written out in source code, on one line and across several.
        f'String key = "{PRIVATE_KEY_HEADER}\\n" + "{PRIVATE_KEY_BODY}";',
        f'String key = "{PRIVATE_KEY_HEADER}\\n"\n    + "{PRIVATE_KEY_BODY}\\n"\n',
        f'key = """{PRIVATE_KEY_HEADER}\n\n{PRIVATE_KEY_BODY}\n"""',
        f'KEY="{PRIVATE_KEY_HEADER}\\n{PRIVATE_KEY_BODY}\\n"',
    ],
)
def test_a_private_key_is_reported_however_it_is_written_down(source: str) -> None:
    assert "SEC002" in {f.rule_id for f in analyze_secrets(source, "Keys.java")}


@pytest.mark.parametrize(
    "source",
    [
        # Code that handles keys, found in a real project: it strips the header
        # from one, and builds one at runtime. Neither contains a key.
        f'pem = pem.replace("{PRIVATE_KEY_HEADER}", "");\npem = pem.replace("x", "");',
        f'String encoded = "{PRIVATE_KEY_HEADER}\\n";\nencoded = encoded + body;',
        f"if (line.startsWith('{PRIVATE_KEY_HEADER}')) {{ continue; }}",
        f"# A PEM file starts with {PRIVATE_KEY_HEADER} and ends with the matching footer.",
        f"{PRIVATE_KEY_HEADER}\n",
        f"{PRIVATE_KEY_HEADER}\n\n\n\n{PRIVATE_KEY_BODY}\n",
        # Code between a header and something base64-shaped: not one block.
        f'marker = "{PRIVATE_KEY_HEADER}";\nprepare();\n{PRIVATE_KEY_BODY}\n',
    ],
)
def test_the_header_of_a_private_key_is_not_a_private_key(source: str) -> None:
    assert "SEC002" not in {f.rule_id for f in analyze_secrets(source, "CryptoUtil.java")}


def test_a_lexers_token_is_not_a_credential() -> None:
    """Sixty of these in one syntax-highlighting library were most of a real
    project's "credentials"."""
    source = (
        'token : "comment.doc",\n'
        'defaultToken : "string.regexp"\n'
        'token: "keyword.operator",\n'
        "token = 'punctuation.operator'\n"
        'token: "empty_line"\n'
    )
    assert analyze_secrets(source, "static/js/libs/mode-java.js") == []


@pytest.mark.parametrize(
    "line",
    [
        'token = "a8f3k2m9x7q1w5z0"',  # a digit: random, not a word
        'authToken = "QwErTyUiOpAsDfGh"',  # mixed case
        'token: "Bearer abcdefgh"',
        # Names that say what they are keep their plain-word values: a weak
        # password is still a hard-coded password.
        'password = "correcthorse"',
        'api_key = "abcdefghijkl"',
        'client_secret = "keyword.operator"',
        'token_secret = "lowercaseonly"',
    ],
)
def test_a_real_token_or_a_named_credential_is_still_reported(line: str) -> None:
    assert [f.rule_id for f in analyze_secrets(line, "app/config.js")] == ["SEC005"]


def test_a_name_inside_a_string_is_not_an_assignment() -> None:
    """`"Token: "` ends a string; what follows the quote is code."""
    source = (
        'debug.append("Token: ").append(escape(token)).append("\\n");\n'
        'log.info("password: " + masked + " accepted");\n'
    )
    assert analyze_secrets(source, "Task.java") == []


def test_an_assignment_after_a_closed_string_is_still_reported() -> None:
    line = 'connect("db", password="s3cr3t_value_42")'
    assert [f.rule_id for f in analyze_secrets(line, "app/db.py")] == ["SEC005"]


@pytest.mark.parametrize(
    "path",
    [
        "src/main/resources/i18n/messages_nl.properties",
        "src/main/resources/messages.properties",
        "src/main/resources/messages_pt_BR.properties",
        "web/locales/de/login.properties",
        "app/translations/form.ini",
    ],
)
def test_a_translation_of_the_word_password_is_not_a_password(path: str) -> None:
    assert analyze_secrets("password=Wachtwoord\nsecret=Geheimnis!\n", path) == []


def test_a_real_key_in_a_message_bundle_is_still_found() -> None:
    source = f"help=contact us\ngithub.token={GITHUB_TOKEN}\n"
    found = analyze_secrets(source, "src/main/resources/i18n/messages_en.properties")
    assert [f.rule_id for f in found] == ["SEC003"]


@pytest.mark.parametrize(
    "path", ["config/application.properties", "src/main/resources/db.properties", "lang.ini"]
)
def test_an_ordinary_properties_file_is_still_scanned(path: str) -> None:
    assert [f.rule_id for f in analyze_secrets("db.password=Wachtwoord1\n", path)] == ["SEC005"]


def test_a_github_token_is_reported_and_redacted() -> None:
    findings = analyze_secrets(f"GITHUB_TOKEN={GITHUB_TOKEN}\n", ".env")
    assert findings[0].rule_id == "SEC003"
    assert GITHUB_TOKEN not in findings[0].snippet
    assert GITHUB_TOKEN[4:] not in findings[0].snippet


def test_a_database_url_with_a_password_is_reported() -> None:
    line = "DATABASE_URL=postgresql://app:hunter2real@db.example.com:5432/app\n"
    assert "SEC004" in {f.rule_id for f in analyze_secrets(line, ".env")}


def test_a_database_url_without_a_password_is_not_reported() -> None:
    assert secret_rules("DATABASE_URL=postgresql://localhost:5432/app\n") == set()


def test_a_generic_password_assignment_is_reported() -> None:
    assert "SEC005" in secret_rules('password = "a-real-looking-secret-value"\n')


def test_an_environment_reference_is_not_reported() -> None:
    assert secret_rules('password = "${DB_PASSWORD}"\n') == set()
    assert secret_rules('password = "process.env.DB_PASSWORD"\n') == set()


def test_placeholders_are_not_reported() -> None:
    assert secret_rules('password = "changeme"\n') == set()
    assert secret_rules('api_key = "your-key-here"\n') == set()
    assert secret_rules('password = "xxxxxxxxxxxx"\n') == set()


def test_an_env_example_style_file_is_quiet() -> None:
    """The file that exists to *document* secrets must not be a finding list."""
    source = (
        "DATABASE_URL=postgresql://user:CHANGE_ME@localhost:5432/app\n"
        "JWT_SECRET=CHANGE_ME_generate_a_random_48_byte_value\n"
        "API_KEY=<your api key>\n"
        "PASSWORD=${PASSWORD}\n"
    )
    assert secret_rules(source) == set()


# --- env-style files: where secrets actually leak ---------------------------
#
# A .env file is written NAME=value with no quotes. The quoted rule above is
# how *code* is written, so before this rule a repository could carry
# JWT_SECRET=<the real secret> and the scanner said nothing. The unquoted form
# is only applied to configuration files: in source code, `token = getToken()`
# would match it and every scan would be noise.


@pytest.mark.parametrize(
    "line",
    [
        "JWT_SECRET=my-actual-jwt-signing-secret-value",
        "STRIPE_SECRET_KEY=sk_test_abcdefghijklmnop",
        "ADMIN_PASSWORD=hunter2-but-longer",
        "export API_TOKEN=live-value-that-is-long",
    ],
)
def test_an_unquoted_env_secret_is_reported(line: str) -> None:
    assert "SEC005" in {f.rule_id for f in analyze_secrets(line, ".env")}


@pytest.mark.parametrize(
    "line",
    [
        "PORT=5000",  # not a credential
        "# OLD_TOKEN=commented-out-old-value",  # documentation, not a secret
        "API_KEY=${API_KEY}",  # a reference, which is the fix
        "JWT_SECRET=CHANGE_ME_generate_a_random_48_byte_value",
        "DB_PASSWORD=your_password_here",
    ],
)
def test_env_lines_that_are_not_live_secrets_stay_quiet(line: str) -> None:
    assert analyze_secrets(line, ".env.example") == []


@pytest.mark.parametrize(
    ("path", "line"),
    [
        ("app/config.py", '# password = "a-real-looking-secret-value"'),
        ("app/config.py", '   # api_key = "another-real-looking-value"'),
        (".env", "# API_TOKEN=an-old-value-we-stopped-using"),
    ],
)
def test_a_commented_out_credential_is_not_a_finding(path: str, line: str) -> None:
    """Commenting a secret out is what someone does *after* rotating it."""
    assert analyze_secrets(line, path) == []


def test_ini_and_properties_files_count_as_env_style() -> None:
    assert "SEC005" in {
        f.rule_id for f in analyze_secrets("password=a-real-looking-secret", "config/app.ini")
    }


@pytest.mark.parametrize(
    "line",
    ["token = getToken()", "password = other_variable", "secret = load(path)"],
)
def test_unquoted_assignments_in_source_code_are_not_reported(line: str) -> None:
    """The rule that would make every Python file noise if it were applied there."""
    assert analyze_secrets(line, "app/service.py") == []


def test_our_own_env_example_is_still_silent() -> None:
    """The file whose job is to document credentials must produce nothing."""
    from app.core.config import BACKEND_DIR

    example = (BACKEND_DIR / ".env.example").read_text()
    assert analyze_secrets(example, ".env.example") == []


def test_one_line_produces_one_credential_finding() -> None:
    """A specific rule wins; the generic rule must not double-report."""
    rule_ids = [f.rule_id for f in analyze_secrets(f"AWS_SECRET_ACCESS_KEY={AWS_KEY}\n", ".env")]
    assert rule_ids == ["SEC001"]


# --- a reference with a hard-coded fallback ---------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "JWT_SECRET=${JWT_SECRET:-'default_secret'}",
        "JWT_SECRET=${JWT_SECRET:-default_secret}",
        'JWT_SECRET="${JWT_SECRET:-default_secret}"',
        "export API_KEY=${API_KEY:=abcd1234efgh}",
    ],
)
def test_a_shell_default_is_still_a_hardcoded_credential(line: str) -> None:
    """``${NAME:-fallback}`` reads like "taken from the environment".

    It is a hard-coded credential whenever the variable is unset — which, in a
    committed .env file, is the normal case. The first form here is, verbatim,
    what a real model wrote when asked to fix a hard-coded JWT secret; because
    the value began with ``${`` it was dismissed as a reference, the finding
    disappeared, and the "fix" was validated.
    """
    findings = analyze_secrets(line, ".env")

    assert [finding.rule_id for finding in findings] == ["SEC005"]


def test_the_fallback_is_what_gets_redacted() -> None:
    finding = analyze_secrets("JWT_SECRET=${JWT_SECRET:-'default_secret'}", ".env")[0]

    assert "default_secret" not in finding.snippet
    assert "redacted" in finding.snippet


@pytest.mark.parametrize(
    "line",
    [
        "JWT_SECRET=${JWT_SECRET}",  # a reference, and nothing else
        "JWT_SECRET=${JWT_SECRET:-}",  # an empty fallback is not a secret
        "JWT_SECRET=${JWT_SECRET:-changeme_please}",  # a placeholder, as elsewhere
    ],
)
def test_a_plain_reference_is_still_not_reported(line: str) -> None:
    assert analyze_secrets(line, ".env") == []


@pytest.mark.parametrize("file_path", ["docker/entrypoint", "Makefile", "scripts/deploy.sh"])
def test_a_shell_default_is_a_credential_wherever_it_is_written(file_path: str) -> None:
    """Not only in .env files. A whole line of `NAME=${NAME:-literal}` is shell
    syntax, and it hard-codes the fallback in an entrypoint script or a Makefile
    exactly as it does in a .env."""
    findings = analyze_secrets("API_TOKEN=${API_TOKEN:-dev-token-12345}", file_path)

    assert [finding.rule_id for finding in findings] == ["SEC005"]


def test_a_dotted_property_key_is_still_a_credential_name() -> None:
    """`spring.datasource.password=…` is how a Java application's database
    password is actually committed, and the name did not match."""
    source = "spring.datasource.username=app\nspring.datasource.password=s3cr3t_value_42\n"
    found = analyze_secrets(source, "src/main/resources/application.properties")

    assert [(f.rule_id, f.line_start) for f in found] == [("SEC005", 2)]
    assert "s3cr3t_value_42" not in found[0].snippet
    assert found[0].snippet.startswith("spring.datasource.password = ")


def test_a_dotted_key_that_refers_to_the_environment_is_not_reported() -> None:
    source = "spring.datasource.password=${DB_PASSWORD}\njwt.secret=${JWT_SECRET:}\n"
    assert analyze_secrets(source, "application.properties") == []


def test_a_minified_line_is_not_read_as_one_statement() -> None:
    """Six "SQL injections" in a real project were the word `select` and a `+`
    thirty thousand characters apart in minified jQuery."""
    filler = "a=b(c);" * 400
    minified = f'{filler}x.innerHTML+="<select class=\'y\'>";{filler}q="delete from"+n;eval(z);'

    assert len(minified) > 1000
    assert analyze_with_patterns(minified, "static/js/jquery.min.js", ".js") == []


def test_an_ordinary_long_line_is_still_read() -> None:
    line = f'const query = "SELECT * FROM users WHERE name = " + name; // {"x" * 700}'

    assert len(line) < 1000
    assert [f.rule_id for f in analyze_with_patterns(line, "app/db.js", ".js")] == ["SQL001"]


def test_a_secret_on_a_minified_line_is_still_found() -> None:
    line = f'{"a=b(c);" * 400}var t="{GITHUB_TOKEN}";'

    assert [f.rule_id for f in analyze_secrets(line, "static/app.min.js")] == ["SEC003"]
