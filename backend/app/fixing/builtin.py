"""Fixes that need no model: one mechanical rewrite per rule.

A rule gets a rewrite here only when all three of these hold:

* **there is one right answer** — ``secure=False`` becomes ``secure=True``;
  there is nothing to design;
* **it fits on the lines the finding points at** (plus, for one rule, an
  ``import``), so the change is small enough to read at a glance;
* **what else changes can be said in a sentence**, and is: every fix carries a
  ``caution`` for the developer who is about to accept it.

SQL injection is the instructive absence. A parameterised query is the right
fix, but the placeholder is ``%s`` for one driver and ``?`` for another, and
choosing wrong produces code that looks fixed and fails at runtime. That is a
decision, not a rewrite, so it is left to a person or to the model.

Python rewrites are addressed through the syntax tree, never by searching the
line for text: ``verify=False`` inside a string, a comment, or a different
call on the same line is not the keyword argument the analyser reported. Every
edit also names the text it expects to replace and refuses if something else
is there, so a file whose lines are not where the tree says they are is left
alone rather than edited in the wrong place.

Nothing here decides that a fix worked. A rewrite returns the new file, and
:mod:`app.fixing.local` re-scans it like any other proposal.
"""

import ast
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from app.analysis.findings import Finding

# The analyser's own helpers, so that "which call is this" is answered here
# exactly as it was answered when the finding was made.
from app.analysis.python_ast import (
    WEAK_HASHES,
    _call_name,
    _has_safe_loader,
    _keyword_is_false,
    _keyword_is_true,
    _literal_string,
)

Lines = list[str]
Rewrite = Callable[[Lines, Finding], Lines | None]


@dataclass(frozen=True)
class BuiltinFix:
    rule_id: str
    #: What the change is, as a button would say it.
    title: str
    #: One sentence: what was changed and why that removes the weakness.
    rationale: str
    #: What else the change does, for the person deciding whether to accept it.
    caution: str
    rewrite: Rewrite


class _CannotRewrite(Exception):
    """The code is not in a shape this rewrite handles. Not an error."""


# --- editing Python by position ---------------------------------------------


@dataclass(frozen=True)
class _Edit:
    line: int  # 1-based
    start: int  # UTF-8 byte offsets within the line, as ``ast`` reports them
    end: int
    expected: str
    replacement: str


def _edit(text: str, node: ast.AST, replacement: str) -> _Edit:
    """Replace the whole of a node that sits on one line.

    What the node says in the source is read from the text the tree was parsed
    from; ``_apply`` then checks that the same words are at that position in
    the list of lines being edited.
    """
    source = ast.get_source_segment(text, node)
    if source is None or node.lineno != node.end_lineno:
        raise _CannotRewrite
    return _Edit(node.lineno, node.col_offset, node.end_col_offset, source, replacement)


def _rename_attribute(node: ast.Attribute, replacement: str) -> _Edit:
    """Replace the name after the last dot of ``a.b.name``."""
    end = node.end_col_offset
    return _Edit(node.end_lineno, end - len(node.attr.encode()), end, node.attr, replacement)


def _apply(lines: Lines, edits: Iterable[_Edit]) -> Lines:
    result = list(lines)
    # Right to left within a line, so an earlier edit does not move a later one.
    for edit in sorted(edits, key=lambda item: (item.line, item.start), reverse=True):
        if not 1 <= edit.line <= len(result):
            raise _CannotRewrite
        raw = result[edit.line - 1].encode("utf-8")
        try:
            found = raw[edit.start : edit.end].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _CannotRewrite from exc
        if found != edit.expected:
            # The tree and the lines disagree about where this code is. Editing
            # anyway would change something nobody looked at.
            raise _CannotRewrite
        result[edit.line - 1] = (
            raw[: edit.start] + edit.replacement.encode("utf-8") + raw[edit.end :]
        ).decode("utf-8")
    return result


def _calls_on_line(lines: Lines, line: int) -> tuple[str, ast.Module, list[ast.Call]]:
    text = "".join(lines)
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError) as exc:
        raise _CannotRewrite from exc
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and node.lineno == line]
    return text, tree, calls


def _keyword(call: ast.Call, name: str) -> ast.keyword:
    return next(keyword for keyword in call.keywords if keyword.arg == name)


def _python(build: Callable[[str, ast.Call], list[_Edit] | None]) -> Rewrite:
    """A rewrite made of edits to the calls on the finding's line."""

    def rewrite(lines: Lines, finding: Finding) -> Lines | None:
        try:
            text, _tree, calls = _calls_on_line(lines, finding.line_start)
            edits: list[_Edit] = []
            for call in calls:
                edits.extend(build(text, call) or [])
            return _apply(lines, edits) if edits else None
        except _CannotRewrite:
            return None

    return rewrite


# --- the Python rewrites -----------------------------------------------------


def _yaml_load(text: str, call: ast.Call) -> list[_Edit] | None:
    if _call_name(call.func) != "yaml.load" or _has_safe_loader(call):
        return None
    if any(keyword.arg == "Loader" for keyword in call.keywords):
        return [_edit(text, _keyword(call, "Loader").value, "yaml.SafeLoader")]
    if not isinstance(call.func, ast.Attribute) or call.keywords:
        raise _CannotRewrite
    if len(call.args) == 1:
        return [_rename_attribute(call.func, "safe_load")]
    if len(call.args) == 2:  # noqa: PLR2004 - yaml.load(stream, Loader)
        # safe_load takes the stream alone, so the call is written out again
        # without its loader.
        stream = ast.get_source_segment(text, call.args[0])
        if stream is None:
            raise _CannotRewrite
        return [_edit(text, call, f"yaml.safe_load({stream})")]
    raise _CannotRewrite


def _weak_hash(text: str, call: ast.Call) -> list[_Edit] | None:
    name = _call_name(call.func) or ""
    tail = name.rsplit(".", 1)[-1]
    if tail in WEAK_HASHES and "hashlib" in name:
        if not isinstance(call.func, ast.Attribute):
            raise _CannotRewrite
        return [_rename_attribute(call.func, "sha256")]
    if name == "hashlib.new" and call.args and _literal_string(call.args[0]) in WEAK_HASHES:
        algorithm = call.args[0]
        source = ast.get_source_segment(text, algorithm) or ""
        value = _literal_string(algorithm)
        # Only a plain literal — 'md5' or "md5" — is rewritten, quotes kept.
        if source not in {f'"{value}"', f"'{value}'"}:
            raise _CannotRewrite
        return [_edit(text, algorithm, f"{source[0]}sha256{source[0]}")]
    return None


def _flip_keyword(
    name: str, *, to: bool, applies: Callable[[ast.Call], bool]
) -> Callable[[str, ast.Call], list[_Edit] | None]:
    def build(text: str, call: ast.Call) -> list[_Edit] | None:
        is_wrong = _keyword_is_false(call, name) if to else _keyword_is_true(call, name)
        if not is_wrong or not applies(call):
            return None
        return [_edit(text, _keyword(call, name).value, str(to))]

    return build


def _is_http_call(call: ast.Call) -> bool:
    name = _call_name(call.func) or ""
    return name.startswith(("requests.", "httpx.", "session.")) or name.rsplit(".", 1)[-1] in {
        "get",
        "post",
        "request",
    }


def _tail_is(tail: str) -> Callable[[ast.Call], bool]:
    return lambda call: (_call_name(call.func) or "").rsplit(".", 1)[-1] == tail


def _unverified_context(_text: str, call: ast.Call) -> list[_Edit] | None:
    if _call_name(call.func) != "ssl._create_unverified_context":
        return None
    # The two functions take different arguments, so only the bare call has an
    # obvious equivalent.
    if call.args or call.keywords or not isinstance(call.func, ast.Attribute):
        raise _CannotRewrite
    return [_rename_attribute(call.func, "create_default_context")]


RANDOM_NAME = "random"
SIMPLE_EXPRESSIONS = (ast.Name, ast.Attribute, ast.Constant)


def _weak_random_call(text: str, call: ast.Call) -> _Edit | None:
    """``random.x(...)`` as the same thing drawn from ``secrets``, or nothing."""
    name = _call_name(call.func) or ""
    if not name.startswith(f"{RANDOM_NAME}.") or name.count(".") != 1:
        return None
    function = name.split(".", 1)[1]

    def segment(node: ast.AST) -> str:
        source = ast.get_source_segment(text, node)
        if source is None:
            raise _CannotRewrite
        return source

    if function == "choice" and len(call.args) == 1 and not call.keywords:
        return _edit(text, call, f"secrets.choice({segment(call.args[0])})")

    if function == "choices" and len(call.args) == 1 and len(call.keywords) == 1:
        population, count = call.args[0], call.keywords[0]
        # Both are written out again inside a comprehension, so they have to be
        # something that is safe to evaluate more than once.
        if (
            count.arg == "k"
            and isinstance(population, SIMPLE_EXPRESSIONS)
            and isinstance(count.value, SIMPLE_EXPRESSIONS)
        ):
            return _edit(
                text,
                call,
                f"[secrets.choice({segment(population)}) for _ in range({segment(count.value)})]",
            )

    if function == "randrange" and len(call.args) == 1 and not call.keywords:
        return _edit(text, call, f"secrets.randbelow({segment(call.args[0])})")

    if function == "randint" and len(call.args) == 2 and not call.keywords:  # noqa: PLR2004
        low, high = (_literal_int(argument) for argument in call.args)
        if low is not None and high is not None and high >= low:
            draw = f"secrets.randbelow({high - low + 1})"
            # Parenthesised: the call may sit inside a larger expression.
            return _edit(text, call, draw if low == 0 else f"({draw} + {low})")

    raise _CannotRewrite


def _literal_int(node: ast.AST) -> int | None:
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    return None


def _weak_random(lines: Lines, finding: Finding) -> Lines | None:
    try:
        text, tree, calls = _calls_on_line(lines, finding.line_start)
        edits = [edit for call in calls if (edit := _weak_random_call(text, call)) is not None]
        if not edits:
            return None
        return _import_secrets(_apply(lines, edits), tree, before_line=finding.line_start)
    except _CannotRewrite:
        return None


def _import_secrets(lines: Lines, tree: ast.Module, *, before_line: int) -> Lines:
    """Add ``import secrets`` after the last top-level import above the fix."""
    imported = any(
        isinstance(node, ast.Import)
        and any(alias.name == "secrets" and alias.asname is None for alias in node.names)
        for node in tree.body
    )
    if imported:
        return lines
    if _name_is_used(tree, "secrets"):
        # The name already means something else in this file.
        raise _CannotRewrite

    imports = [
        node
        for node in tree.body
        if isinstance(node, ast.Import | ast.ImportFrom) and node.end_lineno < before_line
    ]
    if imports:
        after = imports[-1].end_lineno
    elif tree.body and _is_docstring(tree.body[0]):
        after = tree.body[0].end_lineno
    else:
        after = (tree.body[0].lineno - 1) if tree.body else 0
    ending = "\r\n" if sum(line.endswith("\r\n") for line in lines) > len(lines) / 2 else "\n"
    result = list(lines)
    if 0 < after <= len(result) and not result[after - 1].endswith(("\n", "\r")):
        result[after - 1] += ending
    result.insert(after, f"import secrets{ending}")
    return result


def _is_docstring(node: ast.stmt) -> bool:
    return (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )


def _name_is_used(tree: ast.AST, name: str) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == name:
            return True
        if isinstance(node, ast.arg) and node.arg == name:
            return True
        if isinstance(node, ast.alias) and (node.asname or node.name.split(".")[0]) == name:
            return True
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) and (
            node.name == name
        ):
            return True
    return False


# --- rewrites for the languages that are matched as text ---------------------


def _substitute(pattern: str, replacement: str) -> Rewrite:
    """Replace a pattern on the finding's own lines, and nowhere else."""
    compiled = re.compile(pattern)

    def rewrite(lines: Lines, finding: Finding) -> Lines | None:
        first = finding.line_start - 1
        last = max(finding.line_end, finding.line_start)
        if not 0 <= first < len(lines):
            return None
        result = list(lines)
        changed = False
        for index in range(first, min(last, len(lines))):
            replaced = compiled.sub(replacement, result[index])
            changed = changed or replaced != result[index]
            result[index] = replaced
        return result if changed else None

    return rewrite


# --- the catalogue ----------------------------------------------------------

HASH_CAUTION = (
    "Values hashed before this change will not match values hashed after it. For passwords "
    "use a password hash (scrypt, bcrypt or Argon2) rather than a plain digest."
)
VERIFY_CAUTION = (
    "A connection to a server whose certificate is self-signed or invalid will now fail. "
    "Give it that server's CA certificate instead of switching the check off."
)
COOKIE_CAUTION = (
    "The cookie is no longer sent over plain http://, so the site has to be served over "
    "https:// for it to work."
)

_FIXES: tuple[BuiltinFix, ...] = (
    BuiltinFix(
        "PY004",
        "Load YAML with the safe loader",
        "yaml.load can build arbitrary Python objects from the document; the safe loader "
        "builds only plain data.",
        "A document that relies on custom YAML tags will now be refused.",
        _python(_yaml_load),
    ),
    BuiltinFix(
        "PY007",
        "Use SHA-256 instead of a broken hash",
        "MD5 and SHA-1 are collision-broken; SHA-256 is not.",
        HASH_CAUTION,
        _python(_weak_hash),
    ),
    BuiltinFix(
        "PY008",
        "Turn certificate verification back on",
        "verify=False accepts any certificate, so anybody on the network path can "
        "impersonate the server.",
        VERIFY_CAUTION,
        _python(_flip_keyword("verify", to=True, applies=_is_http_call)),
    ),
    BuiltinFix(
        "PY009",
        "Turn the debugger off",
        "debug=True serves an interactive console that runs Python for whoever reaches it.",
        "The reloader and the in-browser debugger stop. Use `flask run --debug` on your own "
        "machine instead of setting it in the code.",
        _python(_flip_keyword("debug", to=False, applies=_tail_is("run"))),
    ),
    BuiltinFix(
        "PY011",
        "Draw this value from the secrets module",
        "The random module is predictable from its own output; secrets draws from the "
        "operating system's cryptographic source.",
        "The value can no longer be reproduced by seeding the generator.",
        _weak_random,
    ),
    BuiltinFix(
        "PY014",
        "Use a context that verifies certificates",
        "An unverified context accepts any certificate; the default context checks the "
        "certificate and the host name.",
        VERIFY_CAUTION,
        _python(_unverified_context),
    ),
    BuiltinFix(
        "PY023",
        "Mark the cookie Secure",
        "Without the Secure flag the browser also sends the cookie over plain HTTP, where "
        "it can be read on the network.",
        COOKIE_CAUTION,
        _python(_flip_keyword("secure", to=True, applies=_tail_is("set_cookie"))),
    ),
    BuiltinFix(
        "JS005",
        "Use SHA-256 instead of a broken hash",
        "MD5 and SHA-1 are collision-broken; SHA-256 is not.",
        HASH_CAUTION,
        _substitute(r"(createHash\s*\(\s*[\"'])(?:md5|sha1)([\"']\s*\))", r"\g<1>sha256\g<2>"),
    ),
    BuiltinFix(
        "JS006",
        "Turn certificate verification back on",
        "rejectUnauthorized: false accepts any certificate, so anybody on the network path "
        "can impersonate the server.",
        VERIFY_CAUTION,
        _substitute(r"(rejectUnauthorized\s*:\s*)false\b", r"\g<1>true"),
    ),
    BuiltinFix(
        "JV003",
        "Use SHA-256 instead of a broken hash",
        "MD2, MD4, MD5 and SHA-1 are collision-broken; SHA-256 is not.",
        HASH_CAUTION,
        _substitute(
            r"(MessageDigest\.getInstance\s*\(\s*\")(?i:MD2|MD4|MD5|SHA-?1)(\"\s*[,)])",
            r"\g<1>SHA-256\g<2>",
        ),
    ),
    BuiltinFix(
        "JV005",
        "Use SecureRandom",
        "java.util.Random is predictable from its own output; SecureRandom is a drop-in "
        "subclass that is not.",
        "SecureRandom cannot be seeded to reproduce a sequence, and is slower.",
        _substitute(
            r"(?<![\w.])new\s+(?:java\.util\.)?Random\s*\(\s*\)", "new java.security.SecureRandom()"
        ),
    ),
    BuiltinFix(
        "JV006",
        "Mark the cookie Secure",
        "Without the Secure flag the browser also sends the cookie over plain HTTP, where "
        "it can be read on the network.",
        COOKIE_CAUTION,
        _substitute(r"(\.setSecure\s*\(\s*)false(\s*\))", r"\g<1>true\g<2>"),
    ),
)

FIXES: dict[str, BuiltinFix] = {fix.rule_id: fix for fix in _FIXES}


def titles() -> dict[str, str]:
    """Which rules have a built-in fix, and what each one does."""
    return {rule_id: fix.title for rule_id, fix in sorted(FIXES.items())}


__all__ = ["FIXES", "BuiltinFix", "titles"]
