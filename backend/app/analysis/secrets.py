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

# name = "value" in most syntaxes: python, js, java, yaml, env files, ini.
GENERIC_ASSIGNMENT = re.compile(
    r"(?i)\b(\w*(?:password|passwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|token)\w*)"
    rf"\s*[:=]\s*[\"']([^\"'\n]{{{MIN_SECRET_LENGTH},80}})[\"']"
)

# Lines that are documenting the problem, not committing it.
REFERENCE_VALUE = re.compile(
    r"(?i)^\s*(?:\$\{?[a-z_]|<[a-z_ ]+>|%\([a-z_]+\)|process\.env|os\.environ|env\.|\{\{)"
)


def analyze_secrets(source: str, file_path: str) -> list[Finding]:
    return list(_scan(source, file_path))


def _scan(source: str, file_path: str) -> Iterator[Finding]:
    for index, raw_line in enumerate(source.splitlines(), start=1):
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
            matched_known = True
            yield _finding(secret.rule, file_path, index, raw_line, value)

        if matched_known:
            continue  # one line, one credential: the specific rule wins

        generic = GENERIC_ASSIGNMENT.search(raw_line)
        if generic:
            name, value = generic.group(1), generic.group(2)
            if _is_placeholder(value) or REFERENCE_VALUE.match(value):
                continue
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


def _is_placeholder(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < MIN_SECRET_LENGTH:
        return True
    lowered = stripped.lower()
    if lowered in PLACEHOLDER_VALUES:
        return True
    # "xxxxxxxxxxxx", "************", "your-key-here"
    return bool(len(set(lowered)) <= 2 or lowered.startswith(("your-", "your_", "<", "${")))


def _mask_line(raw_line: str, value: str) -> str:
    return raw_line.replace(value, _redact(value))


def _redact(value: str) -> str:
    """Enough to recognise which credential it was, not enough to use it."""
    if len(value) <= 8:
        return f"<redacted {len(value)} chars>"
    return f"{value[:4]}…<redacted {len(value)} chars>"
