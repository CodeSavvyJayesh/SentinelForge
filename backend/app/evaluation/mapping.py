"""Which rule answers which question.

A benchmark test case asks one question — "is there a command injection in
this file?" — and a finding only counts as an answer if it is a finding *of
that kind*. A weak-hash finding in a file whose question is about SQL is
neither right nor wrong about SQL; it is about something else.

So every rule is assigned, here, to the one benchmark category it speaks to,
or declared to speak to none. This is the same thing the benchmark's own
scorecard generator does for each tool it supports.

**The table was written before the first measurement and is not adjusted to
improve one.** It follows the weakness each rule already declared in the rule
catalogue. Two rows are not word-for-word matches and are stated rather than
hidden:

* The weak-hash rules declare CWE-327 (broken algorithm) and the benchmark
  files MD5 and SHA-1 under CWE-328 (weak hash). Same weakness, the
  benchmark's label is the narrower one. They are **not** counted towards the
  benchmark's ``crypto`` category, which is about ciphers and is also CWE-327:
  crediting a hash rule for a file about DES would be a lucky match on a
  number.
* The weak-randomness rules declare CWE-338 and the benchmark uses its parent,
  CWE-330.

A rule in ``NOT_IN_BENCHMARK`` checks for something no category of either
benchmark asks about. Its findings in benchmark files are counted and
published, and never scored.
"""

from app.analysis.engine import PYTHON_SUFFIXES
from app.analysis.patterns import PATTERN_RULES
from app.analysis.rules import ALL_RULES

RULE_CATEGORY: dict[str, str] = {
    # Command injection
    "PY002": "cmdi",
    "PY003": "cmdi",
    "JS002": "cmdi",
    "JV001": "cmdi",
    "PH001": "cmdi",
    "GO001": "cmdi",
    # SQL injection
    "PY010": "sqli",
    "SQL001": "sqli",
    # Code injection
    "PY001": "codeinj",
    "JS001": "codeinj",
    # Deserialisation of untrusted data
    "PY004": "deserialization",
    "PY005": "deserialization",
    "JV002": "deserialization",
    # Weak hash
    "PY007": "hash",
    "JS005": "hash",
    "JV003": "hash",
    # Weak randomness
    "PY011": "weakrand",
    "JS004": "weakrand",
    # Cross-site scripting
    "JS003": "xss",
    # XML external entities
    "PY015": "xxe",
}

NOT_IN_BENCHMARK: frozenset[str] = frozenset(
    {
        "PY006",  # credential in source
        "PY008",  # TLS verification off
        "PY009",  # Flask debug
        "PY012",  # tempfile.mktemp
        "PY013",  # JWT signature not verified
        "PY014",  # unverified SSL context
        "JS006",  # TLS verification off
        "SEC001",
        "SEC002",
        "SEC003",
        "SEC004",
        "SEC005",
    }
)

_PATTERN_SUFFIXES: dict[str, frozenset[str] | None] = {
    item.rule.id: item.suffixes for item in PATTERN_RULES
}
_PYTHON_RULES: frozenset[str] = frozenset(rule.id for rule in ALL_RULES if rule.id.startswith("PY"))


def reads(rule_id: str, suffix: str) -> bool:
    """Whether a rule is ever applied to files with this suffix."""
    if rule_id in _PYTHON_RULES:
        return suffix in PYTHON_SUFFIXES
    if rule_id in _PATTERN_SUFFIXES:
        suffixes = _PATTERN_SUFFIXES[rule_id]
        return suffixes is None or suffix in suffixes
    return True  # secret rules read every text file


def rules_for(category: str, suffixes: frozenset[str]) -> tuple[str, ...]:
    """The rules that could report this category in files of these kinds.

    Empty means the analyser has nothing that looks for the weakness in this
    language: every vulnerable case in the category is missed by construction,
    and the results say "no rule" rather than presenting that as a measurement.
    """
    return tuple(
        sorted(
            rule_id
            for rule_id, mapped in RULE_CATEGORY.items()
            if mapped == category and any(reads(rule_id, suffix) for suffix in suffixes)
        )
    )


__all__ = ["NOT_IN_BENCHMARK", "RULE_CATEGORY", "reads", "rules_for"]
