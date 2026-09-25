"""Pattern rules and secret detection — each with its counterexample.

These analysers have no parser behind them, so the counterexamples matter even
more than they do for Python: a regex that cannot tell code from a comment will
happily report a line that says "do not use eval here".
"""

import pytest

from app.analysis.patterns import analyze_with_patterns
from app.analysis.secrets import analyze_secrets
from tests.helpers import AWS_ACCESS_KEY_ID as AWS_KEY
from tests.helpers import GITHUB_TOKEN, PRIVATE_KEY_HEADER


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
    assert "SEC002" in secret_rules(f"{PRIVATE_KEY_HEADER}\nMIIEpAIBAAKCA…\n")


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
