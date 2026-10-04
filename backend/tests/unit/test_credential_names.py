"""Names that contain "password" and hold something else.

Each case here came out of scanning a real repository — this one included.
"""

import pytest

from app.analysis.credential_names import (
    describes_a_credential,
    is_its_own_name,
    is_not_a_credential,
    is_token_type,
    words,
)
from app.analysis.python_ast import analyze_python_source
from app.analysis.secrets import analyze_secrets


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("API_KEY_HEADER", ["api", "key", "header"]),
        ("apiKeyHeader", ["api", "key", "header"]),
        ("api.key-header", ["api", "key", "header"]),
        ("JWTSecret", ["jwt", "secret"]),
        ("password2", ["password", "2"]),
        ("", []),
    ],
)
def test_a_name_is_split_into_words_however_it_is_cased(name: str, expected: list[str]) -> None:
    assert words(name) == expected


@pytest.mark.parametrize(
    "name",
    [
        "CREDENTIAL_MESSAGE", "SECRET_NAME_PATTERN", "PASSWORD_FIELD", "apiKeyHeader",
        "TOKEN_URL", "private_key_path", "TOKEN_REFRESHED", "passwordPrompt", "SECRET_ENV",
        "auth.token.endpoint", "PASSWORD_MIN_LENGTH",
    ],
)  # fmt: skip
def test_a_name_that_is_about_a_credential_is_not_one(name: str) -> None:
    assert describes_a_credential(name)


@pytest.mark.parametrize(
    "name",
    [
        "PASSWORD", "db_password", "JWT_SECRET", "apiKey", "API_KEY", "secretValue",
        "ADMIN_PASSWORD_LINK", "PASSWORD_SALT_ADMIN", "access_token", "name_secret",
    ],
)  # fmt: skip
def test_a_name_that_holds_a_credential_still_does(name: str) -> None:
    assert not describes_a_credential(name)


@pytest.mark.parametrize(
    ("name", "value", "expected"),
    [
        ("UNAUTHORIZED", "UNAUTHORIZED", True),
        ("ErrorCode.TOKEN_EXPIRED", "token_expired", True),
        ("secretKey", "SECRET_KEY", True),
        ("PASSWORD", "password1", False),
        ("PASSWORD", "hunter2hunter2", False),
        ("x", "", False),
    ],
)
def test_a_constant_spelling_out_its_own_name(name: str, value: str, expected: bool) -> None:
    assert is_its_own_name(name, value) is expected


@pytest.mark.parametrize(
    ("name", "value", "expected"),
    [
        ("token", "keyword.operator", True),
        ("defaultToken", "comment.doc", True),
        ("event", "auth.token_refreshed", True),
        ("token", "a8f3k2m9x7q1w5z0", False),
        ("token", "QwErTyUiOpAsDfGh", False),
        ("password", "keyword.operator", False),
        ("token_secret", "lowercaseonly", False),
        ("api_key", "abcdefghijkl", False),
    ],
)
def test_a_lowercase_word_under_the_bare_name_token(name: str, value: str, expected: bool) -> None:
    assert is_token_type(name, value) is expected


def test_any_one_of_the_three_is_enough() -> None:
    assert is_not_a_credential("PASSWORD_FIELD", "S3cr3tValue42")
    assert is_not_a_credential("FORBIDDEN_TOKEN", "FORBIDDEN_TOKEN")
    assert is_not_a_credential("token", "plain.words")
    assert not is_not_a_credential("PASSWORD", "S3cr3tValue42")


# --- through the Python rule ------------------------------------------------


@pytest.mark.parametrize(
    "source",
    [
        'UNAUTHORIZED = "UNAUTHORIZED"\n',
        'TOKEN_REFRESHED = "auth.token_refreshed"\n',
        'CREDENTIAL_MESSAGE = "Rotate this credential. No code change is proposed."\n',
        'SECRET_NAME_PATTERN = r"\\w*(?:password|passwd|secret)\\w*"\n',
        'class C:\n    PASSWORD_FIELD = "user_password"\n',
        'self.token_url = "https://example.test/oauth/token"\n',
    ],
)
def test_python_names_about_credentials_are_not_reported(source: str) -> None:
    assert [f.rule_id for f in analyze_python_source(source, "app/config.py")] == []


@pytest.mark.parametrize(
    "source",
    [
        'PASSWORD = "a-long-enough-passphrase"\n',
        'JWT_SECRET = "s3cr3t_value_42"\n',
        'api_key = "abcdefghijkl"\n',
        'auth_token = "A8f3K2m9X7q1W5z0"\n',
        'config.db_password = "correcthorse"\n',
    ],
)
def test_python_credentials_are_still_reported(source: str) -> None:
    assert [f.rule_id for f in analyze_python_source(source, "app/config.py")] == ["PY006"]


# --- through the line rule --------------------------------------------------


def test_configuration_about_a_credential_is_not_reported() -> None:
    source = (
        "AUTH_TOKEN_URL=https://example.test/oauth/token\n"
        "PASSWORD_MIN_LENGTH=12characters\n"
        "JWT_SECRET_FILE=/run/secrets/jwt_key\n"
    )
    assert analyze_secrets(source, ".env") == []


def test_configuration_that_is_a_credential_still_is() -> None:
    source = "JWT_SECRET=s3cr3t_value_42\nAPI_TOKEN=lowercaseonlytoken\n"

    assert [f.line_start for f in analyze_secrets(source, ".env")] == [1, 2]
