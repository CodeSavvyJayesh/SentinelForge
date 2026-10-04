"""Telling a credential from something that merely has a credential's name.

"Is the variable called password?" is most of how a hard-coded credential is
found, and most of how a scanner gets muted: codebases are full of names that
contain the word and hold something else. These three checks were each written
after a real repository produced the false positive they describe, and they are
shared by the Python rule and the line-based one so the two cannot drift apart.

They only ever *remove* guesses. The known-format rules — a GitHub token, an
AWS key id, a private key block — do not consult them.
"""

import re

# The last word of a name that describes a credential rather than holding one:
# `PASSWORD_FIELD = "password"`, `API_KEY_HEADER = "X-API-Key"`,
# `TOKEN_URL = "https://…"`, `CREDENTIAL_MESSAGE = "Rotate this credential…"`.
DESCRIPTOR_WORDS = frozenset(
    {
        "message", "msg", "error", "prompt", "hint", "help", "title", "text", "label",
        "description", "pattern", "regex", "format", "name", "names", "field", "fields",
        "header", "param", "parameter", "column", "attribute", "attr", "env", "var", "variable",
        "url", "uri", "endpoint", "path", "file", "filename", "dir", "type", "kind", "policy",
        "length", "prefix", "suffix", "placeholder", "expired", "refreshed", "required",
        "invalid", "missing", "enabled", "disabled",
    }
)  # fmt: skip

_WORDS = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
# Names that say "credential" outright, as opposed to the bare word "token",
# which is also what every lexer and syntax highlighter calls its output.
_UNAMBIGUOUS = re.compile(r"(?i)password|passwd|secret|key|credential")


def words(name: str) -> list[str]:
    """`apiKeyHeader`, `API_KEY_HEADER` and `api.key-header` → api, key, header."""
    return [word.lower() for word in _WORDS.findall(name)]


def describes_a_credential(name: str) -> bool:
    """True when the name's last word says it is *about* a credential."""
    parts = words(name)
    return bool(parts) and parts[-1] in DESCRIPTOR_WORDS


def is_its_own_name(name: str, value: str) -> bool:
    """`UNAUTHORIZED = "UNAUTHORIZED"`: an identifier spelled out, not a secret."""
    return "".join(words(name.rsplit(".", 1)[-1])) == "".join(words(value)) != ""


def is_token_type(name: str, value: str) -> bool:
    """`token: "keyword.operator"` — a lexer's token, not a credential.

    Only for names whose one credential-ish word is "token". A real token is
    random, so it has a digit or an uppercase letter in it; a token *type* or
    an event name is a lowercase word or a dotted path of them.
    """
    if _UNAMBIGUOUS.search(name):
        return False
    return not any(character.isdigit() or character.isupper() for character in value)


def is_not_a_credential(name: str, value: str) -> bool:
    return (
        describes_a_credential(name) or is_its_own_name(name, value) or is_token_type(name, value)
    )


__all__ = [
    "DESCRIPTOR_WORDS",
    "describes_a_credential",
    "is_its_own_name",
    "is_not_a_credential",
    "is_token_type",
    "words",
]
