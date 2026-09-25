"""Pattern analysis for languages we do not parse.

Python gets a real parser. JavaScript, Java, PHP and Go get carefully written
regular expressions, and this file is honest about what that costs:

* A regex cannot tell code from a comment or a string, so line comments are
  stripped before matching and every rule here is capped at MEDIUM confidence
  unless the pattern is unmistakable (`rejectUnauthorized: false` cannot be
  anything else).
* A regex cannot follow a value, so rules require the dangerous *shape* —
  interpolation, concatenation — rather than the function name alone.
  `exec("ls")` is not reported; ``exec(`ls ${dir}`)`` is.

The alternative is a parser per language, which is Phase 5 of a different
project. The trade-off is written down in docs/security/analysis.md rather
than hidden behind a confidence score nobody reads.
"""

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from app.analysis.findings import Finding, clean_snippet
from app.analysis.rules import (
    GO_SHELL,
    JAVA_DESERIALIZE,
    JAVA_RUNTIME_EXEC,
    JAVA_WEAK_HASH,
    JS_CHILD_PROCESS,
    JS_EVAL,
    JS_INNER_HTML,
    JS_MATH_RANDOM,
    JS_TLS_OFF,
    JS_WEAK_HASH,
    PHP_COMMAND,
    SQL_CONCATENATION,
    Rule,
)

ANALYZER = "pattern"

JAVASCRIPT_SUFFIXES = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte"})
JAVA_SUFFIXES = frozenset({".java", ".kt", ".kts", ".scala"})
PHP_SUFFIXES = frozenset({".php", ".phtml"})
GO_SUFFIXES = frozenset({".go"})
SQL_HOST_SUFFIXES = (
    JAVASCRIPT_SUFFIXES | JAVA_SUFFIXES | PHP_SUFFIXES | GO_SUFFIXES | {".cs", ".rb"}
)

# A line comment, in every syntax these languages use. Stripped before matching
# so that "// eval(userInput) - removed, see ticket 42" is not a finding.
LINE_COMMENT = re.compile(r"(^|\s)(//|#)\s.*$")


@dataclass(frozen=True)
class PatternRule:
    rule: Rule
    pattern: re.Pattern[str]
    suffixes: frozenset[str] | None = None  # None: any text file
    # An optional second opinion. The regex finds a candidate; this decides
    # whether it is really a finding. Keeping the two apart stops the patterns
    # growing into unreadable lookahead soup — the bug that motivated it was a
    # negative lookahead defeated by `\s*` matching zero characters, so
    # `eval( "literal" )` was reported and `eval("literal")` was not.
    refine: Callable[[re.Match[str], str], bool] | None = None


def _compile(expression: str) -> re.Pattern[str]:
    return re.compile(expression)


# A call argument that is a single quoted literal and nothing else.
LITERAL_ONLY_ARGUMENT = re.compile(r"^\s*([\"\'`])[^\"\'`]*\1\s*\)")


def _argument_is_built(match: re.Match[str], line: str) -> bool:
    """True when eval()'s argument is not just a quoted literal.

    `eval("2 + 2")` is pointless, not dangerous. `eval("a" + b)` and
    `eval(userInput)` are the rule's reason to exist.
    """
    return not LITERAL_ONLY_ARGUMENT.match(match.group(1))


PATTERN_RULES: tuple[PatternRule, ...] = (
    # --- JavaScript / TypeScript ---
    PatternRule(
        JS_EVAL,
        _compile(r"\beval\s*\((.*)$"),
        JAVASCRIPT_SUFFIXES,
        refine=_argument_is_built,
    ),
    PatternRule(
        JS_CHILD_PROCESS,
        # exec("..." + x) or exec(`... ${x}`) - interpolation is the point
        _compile(
            r"\b(?:child_process\.)?exec(?:Sync)?\s*\("
            r"\s*(?:`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+|\w+\s*\+)"
        ),
        JAVASCRIPT_SUFFIXES,
    ),
    PatternRule(
        JS_INNER_HTML,
        # The value must start with something that is not a quote: assigning a
        # fixed string is not the vulnerability. Written as a character class
        # rather than a lookahead, so `\s*` cannot shrink to nothing and let a
        # literal through.
        _compile(r"(?:\.innerHTML\s*=\s*[^\s\"'`]|dangerouslySetInnerHTML)"),
        JAVASCRIPT_SUFFIXES,
    ),
    PatternRule(
        JS_MATH_RANDOM,
        _compile(
            r"(?i)(?:token|password|secret|otp|nonce|session|key)\w*"
            r"\s*[:=][^;\n]*Math\.random\s*\("
        ),
        JAVASCRIPT_SUFFIXES,
    ),
    PatternRule(
        JS_WEAK_HASH,
        _compile(r"createHash\s*\(\s*[\"'](?:md5|sha1)[\"']\s*\)"),
        JAVASCRIPT_SUFFIXES,
    ),
    PatternRule(
        JS_TLS_OFF,
        _compile(r"(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0)"),
        JAVASCRIPT_SUFFIXES,
    ),
    # --- Java / Kotlin ---
    PatternRule(
        JAVA_RUNTIME_EXEC,
        _compile(r"Runtime\.getRuntime\(\)\.exec\s*\([^)]*(?:\+|\$\{)"),
        JAVA_SUFFIXES,
    ),
    PatternRule(
        JAVA_DESERIALIZE,
        _compile(r"new\s+ObjectInputStream\s*\(|\.readObject\s*\(\s*\)"),
        JAVA_SUFFIXES,
    ),
    PatternRule(
        JAVA_WEAK_HASH,
        _compile(r"MessageDigest\.getInstance\s*\(\s*\"(?:MD5|SHA-?1)\"\s*\)"),
        JAVA_SUFFIXES,
    ),
    # --- PHP ---
    PatternRule(
        PHP_COMMAND,
        _compile(r"\b(?:system|shell_exec|passthru|popen|proc_open|eval)\s*\(\s*\$"),
        PHP_SUFFIXES,
    ),
    # --- Go ---
    PatternRule(
        GO_SHELL,
        _compile(r"exec\.Command\s*\(\s*\"(?:/bin/)?(?:ba)?sh\"\s*,\s*\"-c\""),
        GO_SUFFIXES,
    ),
    # --- SQL built by concatenation, in any of the above ---
    PatternRule(
        SQL_CONCATENATION,
        _compile(
            r"(?i)[\"'`][^\"'`]*"
            r"\b(?:select|insert into|update|delete from)\b"
            r"[^\"'`]*[\"'`]\s*(?:\+|\.|\$\{)"
        ),
        SQL_HOST_SUFFIXES,
    ),
)


def analyze_with_patterns(source: str, file_path: str, suffix: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = source.splitlines()
    for rule in PATTERN_RULES:
        if rule.suffixes is not None and suffix not in rule.suffixes:
            continue
        findings.extend(_scan(rule, lines, file_path))
    return findings


def _scan(rule: PatternRule, lines: list[str], file_path: str) -> Iterator[Finding]:
    for index, raw_line in enumerate(lines, start=1):
        line = LINE_COMMENT.sub("", raw_line)
        if not line.strip():
            continue
        match = rule.pattern.search(line)
        if match and (rule.refine is None or rule.refine(match, line)):
            yield Finding(
                rule_id=rule.rule.id,
                title=rule.rule.title,
                message=rule.rule.message,
                severity=rule.rule.severity,
                confidence=rule.rule.confidence,
                cwe_id=rule.rule.cwe_id,
                owasp_category=rule.rule.owasp_category,
                file_path=file_path,
                line_start=index,
                line_end=index,
                snippet=clean_snippet(raw_line),
                analyzer=ANALYZER,
            )
