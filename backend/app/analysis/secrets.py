"""Secret detection, with the secret redacted before it is stored.

The rule that governs this whole module: **a finding about a leaked credential
must not leak the credential again.** The finding records the file, the line
and the shape of the value; the value itself never reaches the database, the
API, the UI or a report — all of which are read by more people, and kept for
longer, than the source file it came from.

Detection is deliberately two-tier:

* **Known formats** (AWS key ids, GitHub tokens, private key blocks) are
  unmistakable, so they are CRITICAL and HIGH confidence.
* **A generic `password = "..."` assignment** is a guess. It is LOW confidence
  and it skips the things that look like credentials but are not: environment
  lookups, template placeholders, obvious dummies, and anything too short to be
  real.
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass

from app.analysis.credential_names import describes_a_credential, is_not_a_credential
from app.analysis.findings import Finding, clean_snippet
from app.analysis.rules import (
    SECRET_AWS_KEY,
    SECRET_CONNECTION_STRING,
    SECRET_GENERIC,
    SECRET_PRIVATE_KEY,
    SECRET_PROVIDER_TOKEN,
    Rule,
)

ANALYZER = "secrets"

MIN_SECRET_LENGTH = 8
PLACEHOLDER_VALUES = frozenset(
    {
        "changeme",
        "change_me",
        "password",
        "secret",
        "yourpassword",
        "your_password",
        "your_password_here",
        "xxxxxxxx",
        "placeholder",
        "redacted",
        "example",
        "dummy",
        "testtest",
        "notasecret",
        "hunter2",
    }
)


@dataclass(frozen=True)
class SecretRule:
    rule: Rule
    pattern: re.Pattern[str]
    value_group: int = 0


SECRET_RULES: tuple[SecretRule, ...] = (
    SecretRule(SECRET_AWS_KEY, re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), 1),
    SecretRule(
        SECRET_PRIVATE_KEY,
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ),
    SecretRule(
        SECRET_PROVIDER_TOKEN,
        re.compile(
            r"\b((?:gh[pousr]_[A-Za-z0-9]{36,}"  # GitHub
            r"|xox[abposr]-[A-Za-z0-9-]{10,}"  # Slack
            r"|sk-[A-Za-z0-9]{32,}"  # OpenAI-style
            r"|AIza[0-9A-Za-z_-]{35}))"  # Google
        ),
        1,
    ),
    SecretRule(
        SECRET_CONNECTION_STRING,
        # postgres://user:password@host - the password is group 1
        re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s:/@]+:([^\s:/@]{4,})@[^\s/]+"),
        1,
    ),
)

# The header alone is not a key. Code that *handles* keys is full of it:
# `pem.replace("-----BEGIN PRIVATE KEY-----", "")` strips one, and
# `"-----BEGIN PRIVATE KEY-----\\n" + encoded` builds one at runtime. What makes
# a line a leaked key is the base64 that follows the header, on the same line
# or on the next ones.
KEY_BODY = re.compile(r"[A-Za-z0-9+/]{24,}")
KEY_BODY_LOOKAHEAD_LINES = 2
# What can sit between a header and its body in source code: an escaped or
# real line break, the end of one string literal and the start of the next.
_KEY_GLUE = re.compile(r"""(?:\\[nr]|[\s"'+,;()])+""")


def has_key_body(lines: list[str], index: int, header_end: int) -> bool:
    """True when base64 follows the header at ``lines[index][header_end:]``."""
    candidates = [lines[index][header_end:]]
    candidates += lines[index + 1 : index + 1 + KEY_BODY_LOOKAHEAD_LINES]
    for candidate in candidates:
        rest = _KEY_GLUE.sub("", candidate, count=1) if _KEY_GLUE.match(candidate) else candidate
        if KEY_BODY.match(rest):
            return True
        if rest.strip():
            # Something else follows the header: code, not a key.
            return False
    return False


# A regex describing credential-ish *names*, not a credential.
SECRET_NAME_PATTERN = (
    r"\w*(?:password|passwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|token)\w*"  # noqa: S105
)

# name = "value" — the quoted form, which is how code is written.
GENERIC_ASSIGNMENT = re.compile(
    rf"(?i)\b({SECRET_NAME_PATTERN})"
    rf"\s*[:=]\s*[\"']([^\"'\n]{{{MIN_SECRET_LENGTH},80}})[\"']"
)

# NAME=value with no quotes at all, which is how .env files are written — and
# .env is where secrets actually leak. This form is only used for configuration
# files, never for source code: in code, `token = getToken()` and
# `password = other_variable` would both match, and the quoted rule already
# covers the real case there.
#
# The name may be a dotted property key — `spring.datasource.password=…` is how
# a Java application's database password is actually committed.
ENV_ASSIGNMENT = re.compile(
    rf"(?i)^\s*(?:export\s+)?((?:[\w-]+\.)*{SECRET_NAME_PATTERN})"
    rf"\s*=\s*([^\s#\"']{{{MIN_SECRET_LENGTH},120}})\s*$"
)

# NAME=${NAME:-fallback} — a reference with a literal default. It reads like
# "taken from the environment" and is a hard-coded credential whenever the
# variable is unset, which in a committed .env file is the normal case. The
# fallback is group 2.
SHELL_DEFAULT_ASSIGNMENT = re.compile(
    rf"(?i)^\s*(?:export\s+)?({SECRET_NAME_PATTERN})\s*=\s*[\"']?"
    rf"\$\{{\w+:?[-=]\s*[\"']?([^\"'}}\s]{{{MIN_SECRET_LENGTH},120}})[\"']?\s*\}}[\"']?\s*$"
)

# Files whose whole content is `NAME=value` configuration.
ENV_STYLE_SUFFIXES = frozenset({".env", ".ini", ".cfg", ".conf", ".properties", ".sh"})
ENV_STYLE_NAMES = frozenset({".env", ".flaskenv"})


def is_env_style(file_path: str) -> bool:
    """True for files written as NAME=value rather than as source code."""
    name = file_path.rsplit("/", 1)[-1]
    if name in ENV_STYLE_NAMES or name.startswith(".env"):
        return True
    suffix = f".{name.rsplit('.', 1)[-1]}" if "." in name else ""
    return suffix in ENV_STYLE_SUFFIXES


# Message bundles: `password=Wachtwoord` is the Dutch word for the label on a
# login form, in a file whose whole purpose is to hold such words.
I18N_SEGMENTS = frozenset({"i18n", "l10n", "locale", "locales", "lang", "langs", "translations"})
I18N_BUNDLE_NAME = re.compile(r"(?i)^messages?(?:[_-][a-z]{2,3}(?:[_-][a-z]{2,4})?)?\.properties$")


def is_message_bundle(file_path: str) -> bool:
    parts = file_path.split("/")
    return bool(I18N_SEGMENTS & {part.lower() for part in parts[:-1]}) or bool(
        I18N_BUNDLE_NAME.match(parts[-1])
    )


def inside_string_literal(line: str, position: int) -> bool:
    """True when ``position`` falls inside an open double-quoted string.

    `out.append("Token: ").append(escape(token))` contains the text
    ``Token: "`` — a name, a colon and a quote — but the quote is the *end* of
    a string, and what follows it is code. An odd number of double quotes
    before the name means the name is inside a literal.
    """
    return line.count('"', 0, position) % 2 == 1


# Lines that are documenting the problem, not committing it.
REFERENCE_VALUE = re.compile(
    r"(?i)^\s*(?:\$\{?[a-z_]|<[a-z_ ]+>|%\([a-z_]+\)|process\.env|os\.environ|env\.|\{\{)"
)


def analyze_secrets(source: str, file_path: str) -> list[Finding]:
    return list(_scan(source, file_path))


def _scan(source: str, file_path: str) -> Iterator[Finding]:
    env_style = is_env_style(file_path)
    message_bundle = is_message_bundle(file_path)
    lines = source.splitlines()
    for index, raw_line in enumerate(lines, start=1):
        if not raw_line.strip():
            continue

        matched_known = False
        for secret in SECRET_RULES:
            match = secret.pattern.search(raw_line)
            if not match:
                continue
            value = match.group(secret.value_group) if secret.value_group else match.group(0)
            if _is_placeholder(value):
                continue
            if secret.rule is SECRET_PRIVATE_KEY and not has_key_body(
                lines, index - 1, match.end()
            ):
                continue
            matched_known = True
            yield _finding(secret.rule, file_path, index, raw_line, value)

        if matched_known:
            continue  # one line, one credential: the specific rule wins

        if raw_line.lstrip().startswith("#"):
            continue  # a commented-out line is documentation, not a live secret
        if message_bundle:
            continue  # known formats above still apply; the guess below does not

        # Checked first: `${NAME:-fallback}` would otherwise be read as a
        # reference to a variable and dismissed, which it only half is. Not
        # limited to .env-style files: the pattern is a whole line of shell
        # syntax, so it is as much a credential in a Makefile or an
        # extensionless entrypoint script as it is in a .env.
        generic = SHELL_DEFAULT_ASSIGNMENT.match(raw_line)
        if generic is None:
            generic = GENERIC_ASSIGNMENT.search(raw_line)
            if generic and (
                inside_string_literal(raw_line, generic.start(1))
                or is_not_a_credential(generic.group(1), generic.group(2))
            ):
                generic = None
        if generic is None and env_style:
            generic = ENV_ASSIGNMENT.match(raw_line)
        if generic:
            name, value = generic.group(1), generic.group(2)
            if _is_placeholder(value) or REFERENCE_VALUE.match(value):
                continue
            if describes_a_credential(name):
                continue  # TOKEN_URL=…, PASSWORD_FIELD=…: about one, not one
            yield _finding(
                SECRET_GENERIC,
                file_path,
                index,
                raw_line,
                value,
                snippet=f"{name} = {_redact(value)}",
            )


def _finding(
    rule: Rule,
    file_path: str,
    line: int,
    raw_line: str,
    value: str,
    *,
    snippet: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule.id,
        title=rule.title,
        message=rule.message,
        severity=rule.severity,
        confidence=rule.confidence,
        cwe_id=rule.cwe_id,
        owasp_category=rule.owasp_category,
        file_path=file_path,
        line_start=line,
        line_end=line,
        # The line is only ever stored with the secret removed from it.
        snippet=snippet if snippet is not None else clean_snippet(_mask_line(raw_line, value)),
        analyzer=ANALYZER,
    )


# Values that announce themselves as fill-me-in. A .env.example file is full of
# these, and reporting it is how a scanner gets muted.
PLACEHOLDER_PREFIXES = (
    "change_me",
    "changeme",
    "your_",
    "your-",
    "replace_",
    "replace-",
    "example",
    "sample",
    "todo",
    "insert_",
    "put_your",
)


def _is_placeholder(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < MIN_SECRET_LENGTH:
        return True
    lowered = stripped.lower()
    if lowered in PLACEHOLDER_VALUES:
        return True
    if lowered.startswith(PLACEHOLDER_PREFIXES):
        return True
    # "xxxxxxxxxxxx", "************", "<your key>", "${VAR}"
    return bool(len(set(lowered)) <= 2 or lowered.startswith(("<", "${", "$(")))


def _mask_line(raw_line: str, value: str) -> str:
    return raw_line.replace(value, _redact(value))


def _redact(value: str) -> str:
    """Enough to recognise which credential it was, not enough to use it."""
    if len(value) <= 8:
        return f"<redacted {len(value)} chars>"
    return f"{value[:4]}…<redacted {len(value)} chars>"
