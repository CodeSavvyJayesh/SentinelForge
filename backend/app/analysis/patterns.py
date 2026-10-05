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
* A regex reads one line, and formatted Java does not keep a call on one line.
  For ``.java`` files a statement that was wrapped is also read joined up, so
  ``Cipher.getInstance(`` on one line and ``"DES/CBC/..."`` on the next is one
  call. Measured on a benchmark, this was the difference between seeing a
  third of the weak ciphers and seeing all of them.

What a regex still cannot do is tell whether the value in a concatenated query
came from the request. On the benchmark's SQL injection cases these rules
report the vulnerable and the safe test cases alike, and the evaluation says so.

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
    JAVA_INSECURE_COOKIE,
    JAVA_RUNTIME_EXEC,
    JAVA_WEAK_CIPHER,
    JAVA_WEAK_HASH,
    JAVA_WEAK_RANDOM,
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
    # A third opinion that looks around the match: the lines of the file and
    # the index of the one that matched.
    context: Callable[[list[str], int], bool] | None = None
    # For a rule a single expression cannot state: given the text and whether
    # it is a whole statement, say whether it is a finding. Replaces ``refine``
    # when set; ``pattern`` is then only used to say which line to report.
    decide: Callable[[str, bool], bool] | None = None


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


# Words that say a nearby value is a secret. The Java rule for weak randomness
# needs one within this many lines after the generator: `new Random()` in a
# game is not a finding, and in the line above `String sessionKey =` it is.
SECRET_WORDS = (
    "token", "password", "passwd", "secret", "otp", "nonce", "session", "cookie", "csrf",
    "salt", "key",
)  # fmt: skip
SECRET_WINDOW = 5


def _near_a_secret(lines: list[str], index: int) -> bool:
    window = " ".join(lines[index : index + SECRET_WINDOW + 1]).lower()
    return any(word in window for word in SECRET_WORDS)


# --- SQL built by concatenation ---------------------------------------------
#
# Decided in two steps rather than by one expression: find the string literals,
# then look at what they are joined to.
#
# A literal is matched with its own delimiter, so a quote of the *other* kind
# inside it does not end it early:
#
#     "SELECT * FROM users WHERE name = '" + name
#
# The first version of this rule stopped at any quote, and so missed the
# commonest way an injectable query is written. The second did it in one
# expression and took minutes on a real repository: asking a regex to find a
# keyword *somewhere inside* a quoted run makes it try every split of the run.
# Finding the literals first is linear.
STRING_LITERAL = re.compile(r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`")
# UPDATE is only SQL with its table and SET after it, or as a literal that is
# nothing but the keyword, which a table name is about to be joined to. The
# bare word is in too many messages ("failed to update " + name) to be
# evidence of a query.
SQL_STATEMENT = re.compile(
    r"(?i)\b(?:select|insert\s+into|delete\s+from)\b"
    r"|\bupdate\s+[\w.\"`\[\]]+\s+set\b"
    r"|^[\"'`]\s*update\s+[\"'`]$"
)
# With every literal replaced by `""`: a literal joined to something that is not
# one. `"..." + "..."` is a long string written on two lines, not a query built
# from a value.
JOINED_TO_A_VALUE = re.compile(r"\"\"\s*[+.]\s*[A-Za-z_$(]|[\w)\]]\s*\+\s*\"\"")
JOINED_AT_END_OF_LINE = re.compile(r"\"\"\s*[+.]\s*$")


def _sql_is_built(text: str, whole_statement: bool) -> bool:
    """Whether ``text`` joins a SQL string to a value.

    ``whole_statement`` is false when ``text`` is one line of a statement that
    may continue and will not be read again: a literal followed by ``+`` at the
    end of the line is then joined to *something*, and that is reported.
    """
    literals = STRING_LITERAL.findall(text)
    if not any(SQL_STATEMENT.search(literal) for literal in literals):
        return False
    if any(literal.startswith("`") and "${" in literal for literal in literals):
        return True  # a template literal with a value interpolated into it
    outline = STRING_LITERAL.sub('""', text)
    if JOINED_TO_A_VALUE.search(outline):
        return True
    return not whole_statement and JOINED_AT_END_OF_LINE.search(outline) is not None


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
        # With or without a provider argument, in any letter case.
        _compile(r"MessageDigest\.getInstance\s*\(\s*\"(?i:MD2|MD4|MD5|SHA-?1)\"\s*[,)]"),
        JAVA_SUFFIXES,
    ),
    PatternRule(
        JAVA_WEAK_CIPHER,
        _compile(
            r"\b(?:Cipher|KeyGenerator|SecretKeyFactory)\s*\.\s*getInstance\s*\(\s*\""
            r"(?i:(?:DES|DESede|TripleDES|3DES|RC2|RC4|ARCFOUR|Blowfish)"
            r"|[A-Za-z0-9]+/ECB/)"
        ),
        JAVA_SUFFIXES,
    ),
    PatternRule(
        JAVA_WEAK_RANDOM,
        _compile(
            r"(?<![\w.])new\s+(?:java\.util\.)?Random\s*\("
            r"|\bMath\.random\s*\(|\bThreadLocalRandom\.current\s*\("
        ),
        JAVA_SUFFIXES,
        context=_near_a_secret,
    ),
    PatternRule(
        JAVA_INSECURE_COOKIE,
        _compile(r"\.setSecure\s*\(\s*false\s*\)"),
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
        SQL_STATEMENT,
        SQL_HOST_SUFFIXES,
        decide=_sql_is_built,
    ),
)


# A pattern here is written to recognise one statement on one line. Minified
# code puts a whole library on one line, and against thirty thousand characters
# almost every pattern matches something: the word "select" in one place and a
# "+" somewhere after it is not a SQL query. Past this length a line is not one
# statement, so these rules have nothing to say about it. (Secret detection is
# separate and still reads every line: a key in a bundle is still a key.)
MAX_STATEMENT_LENGTH = 1000


# Languages in which a statement ends with `;` or a brace, so wrapped lines can
# be joined back into the statement they are part of. Only Java for now: it is
# the one that was measured.
WRAPPED_STATEMENT_SUFFIXES = frozenset({".java"})
MAX_STATEMENT_LINES = 12


def analyze_with_patterns(source: str, file_path: str, suffix: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = source.splitlines()
    statements = _wrapped_statements(lines) if suffix in WRAPPED_STATEMENT_SUFFIXES else []
    for rule in PATTERN_RULES:
        if rule.suffixes is not None and suffix not in rule.suffixes:
            continue
        # A language whose wrapped statements are joined up leaves "ends with a
        # plus" to the joined reading, which can see what the plus leads to.
        found = list(_scan(rule, lines, file_path, joined_later=bool(statements)))
        reported = {finding.line_start for finding in found}
        for statement in statements:
            if rule.decide is not None and any(index + 1 in reported for index, _ in statement):
                continue  # this statement was already reported from one of its lines
            for index in _across_lines(rule, statement):
                if index + 1 not in reported and _in_context(rule, lines, index):
                    reported.add(index + 1)
                    found.append(_finding(rule, file_path, index + 1, lines[index]))
        findings.extend(sorted(found, key=lambda finding: finding.line_start))
    return findings


def _scan(
    rule: PatternRule, lines: list[str], file_path: str, *, joined_later: bool = False
) -> Iterator[Finding]:
    for index, raw_line in enumerate(lines, start=1):
        if len(raw_line) > MAX_STATEMENT_LENGTH:
            continue
        line = LINE_COMMENT.sub("", raw_line)
        if not line.strip():
            continue
        if rule.decide is not None:
            accepted = rule.decide(line, joined_later)
        else:
            match = rule.pattern.search(line)
            accepted = match is not None and (rule.refine is None or rule.refine(match, line))
        if accepted and _in_context(rule, lines, index - 1):
            yield _finding(rule, file_path, index, raw_line)


def _in_context(rule: PatternRule, lines: list[str], index: int) -> bool:
    return rule.context is None or rule.context(lines, index)


def _wrapped_statements(lines: list[str]) -> list[list[tuple[int, str]]]:
    """Statements that were written across several lines: (line index, text) pairs.

    A statement that fits on one line is not returned; the line scan has
    already read it.
    """
    statements: list[list[tuple[int, str]]] = []
    current: list[tuple[int, str]] = []
    for index, raw_line in enumerate(lines):
        line = LINE_COMMENT.sub("", raw_line).strip()
        if line:
            current.append((index, line))
        if not line or line.endswith((";", "{", "}")) or len(current) >= MAX_STATEMENT_LINES:
            if len(current) > 1:
                statements.append(current)
            current = []
    if len(current) > 1:
        statements.append(current)
    return statements


def _across_lines(rule: PatternRule, statement: list[tuple[int, str]]) -> Iterator[int]:
    """Lines where the rule matches the statement read as one piece of text.

    Includes matches that sit on a single line; the caller already has those
    from the line scan and reports each line once.
    """
    joined = ""
    starts: list[tuple[int, int]] = []  # (offset in the joined text, line index)
    for index, text in statement:
        if joined:
            joined += " "
        starts.append((len(joined), index))
        joined += text
    if len(joined) > MAX_STATEMENT_LENGTH:
        return

    def line_of(offset: int) -> int:
        return max(line for start, line in starts if start <= offset)

    if rule.decide is not None:
        if rule.decide(joined, True):
            # Reported where the SQL is, which is the line a reader looks for.
            located = rule.pattern.search(joined)
            yield line_of(located.start()) if located else statement[0][0]
        return

    for match in rule.pattern.finditer(joined):
        if rule.refine is None or rule.refine(match, joined):
            yield line_of(match.start())


def _finding(rule: PatternRule, file_path: str, line: int, raw_line: str) -> Finding:
    return Finding(
        rule_id=rule.rule.id,
        title=rule.rule.title,
        message=rule.rule.message,
        severity=rule.rule.severity,
        confidence=rule.rule.confidence,
        cwe_id=rule.rule.cwe_id,
        owasp_category=rule.rule.owasp_category,
        file_path=file_path,
        line_start=line,
        line_end=line,
        snippet=clean_snippet(raw_line),
        analyzer=ANALYZER,
    )
