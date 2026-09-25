"""Python analysis over the abstract syntax tree.

Why an AST and not a regular expression: `eval(config)` and `# eval(config)`
and `"eval(config)"` are the same three lines to a regex and three completely
different things to a parser. The AST also knows that `sqlite3.connect(...)`
bound to `db` earlier makes `db.execute(...)` a database call, and that
`shell=True` is a keyword argument to *this* call rather than a word that
happens to appear nearby.

**Nothing here executes the code.** `ast.parse` builds a tree; it does not
import, call or evaluate anything in the file. That is the entire reason the
analysis of hostile code is safe to run in-process.
"""

import ast
from dataclasses import dataclass

from app.analysis.findings import Confidence, Finding, Severity, clean_snippet
from app.analysis.rules import (
    PY_EVAL_EXEC,
    PY_FLASK_DEBUG,
    PY_HARDCODED_SECRET,
    PY_JWT_UNVERIFIED,
    PY_MKTEMP,
    PY_OS_SYSTEM,
    PY_PICKLE,
    PY_SHELL_TRUE,
    PY_SQL_BUILT,
    PY_TLS_VERIFY_OFF,
    PY_UNVERIFIED_SSL_CONTEXT,
    PY_WEAK_HASH,
    PY_WEAK_RANDOM,
    PY_XML_PARSE,
    PY_YAML_LOAD,
    Rule,
)

ANALYZER = "python-ast"

WEAK_HASHES = frozenset({"md5", "sha1"})
SQL_KEYWORDS = ("select ", "insert ", "update ", "delete ", "drop ", "union ")
EXECUTE_METHODS = frozenset({"execute", "executemany", "executescript", "raw"})
SECRET_NAMES = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "credential",
    "auth",
)
# Assignments that are obviously not a credential, however they are named.
SECRET_PLACEHOLDERS = frozenset(
    {
        "",
        "none",
        "null",
        "changeme",
        "change_me",
        "your_password_here",
        "xxx",
        "todo",
        "example",
        "placeholder",
        "redacted",
        "dummy",
        "test",
        "fake",
    }
)
MIN_SECRET_LENGTH = 8
RANDOM_FUNCTIONS = frozenset({"random", "randint", "randrange", "choice", "choices", "sample"})
XML_PARSERS = frozenset({"parse", "fromstring", "XMLParser", "iterparse"})


@dataclass
class _Context:
    file_path: str
    lines: list[str]


def analyze_python_source(source: str, file_path: str) -> list[Finding]:
    """Return findings for one Python file.

    A file that does not parse yields nothing and is reported as unparsable by
    the engine: guessing at broken code produces noise, not findings.
    """
    tree = ast.parse(source)  # SyntaxError is handled by the caller
    visitor = _Visitor(_Context(file_path=file_path, lines=source.splitlines()))
    visitor.visit(tree)
    return visitor.findings


class _Visitor(ast.NodeVisitor):
    def __init__(self, context: _Context) -> None:
        self.context = context
        self.findings: list[Finding] = []
        # Local name -> module it came from, so `from xml.etree import
        # ElementTree` and `from defusedxml import ElementTree` can be told
        # apart. Both are called `ElementTree.parse(...)` at the call site;
        # only one of them is a finding.
        self.imports: dict[str, str] = {}

    # -- imports ----------------------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802 - ast API
        for alias in node.names:
            self.imports[alias.asname or alias.name.split(".")[0]] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802 - ast API
        module = node.module or ""
        for alias in node.names:
            self.imports[alias.asname or alias.name] = f"{module}.{alias.name}".strip(".")
        self.generic_visit(node)

    def _resolve(self, name: str) -> str:
        """Rewrite a call name through the imports, so the module is visible."""
        head, _, tail = name.partition(".")
        origin = self.imports.get(head)
        if not origin:
            return name
        return f"{origin}.{tail}" if tail else origin

    # -- helpers ----------------------------------------------------------

    def _snippet(self, node: ast.AST) -> str:
        line_number = getattr(node, "lineno", 0)
        if 1 <= line_number <= len(self.context.lines):
            return clean_snippet(self.context.lines[line_number - 1])
        return ""

    def _add(
        self,
        rule: Rule,
        node: ast.AST,
        *,
        snippet: str | None = None,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
        message: str | None = None,
    ) -> None:
        self.findings.append(
            Finding(
                rule_id=rule.id,
                title=rule.title,
                message=message or rule.message,
                severity=severity or rule.severity,
                confidence=confidence or rule.confidence,
                cwe_id=rule.cwe_id,
                owasp_category=rule.owasp_category,
                file_path=self.context.file_path,
                line_start=getattr(node, "lineno", 0) or 0,
                line_end=getattr(node, "end_lineno", None) or getattr(node, "lineno", 0) or 0,
                snippet=snippet if snippet is not None else self._snippet(node),
                analyzer=ANALYZER,
            )
        )

    # -- calls ------------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802 - ast API
        name = _call_name(node.func)
        if name:
            self._check_call(node, name)
        self._check_sql_execute(node, name)
        self.generic_visit(node)

    def _check_call(self, node: ast.Call, name: str) -> None:
        tail = name.rsplit(".", 1)[-1]

        # eval / exec, but only on something built at runtime. eval("2 + 2") is
        # pointless, not dangerous, and flagging it teaches people to ignore us.
        if name in {"eval", "exec"} and node.args and not _is_literal(node.args[0]):
            self._add(PY_EVAL_EXEC, node)

        if name in {"os.system", "os.popen", "system", "popen"} and name.startswith("os."):
            self._add(PY_OS_SYSTEM, node)

        if name.startswith(("subprocess.", "Popen")) or tail in {"run", "call", "check_output"}:
            self._check_shell_true(node, name)

        if (
            name in {"yaml.load", "load"}
            and name.startswith("yaml.")
            and not _has_safe_loader(node)
        ):
            self._add(PY_YAML_LOAD, node)

        if name in {"pickle.loads", "pickle.load", "cPickle.loads", "dill.loads"}:
            self._add(PY_PICKLE, node)

        if tail in {"md5", "sha1"} and ("hashlib" in name or tail in WEAK_HASHES):
            self._add(PY_WEAK_HASH, node)
        if name in {"hashlib.new"} and node.args and _literal_string(node.args[0]) in WEAK_HASHES:
            self._add(PY_WEAK_HASH, node)

        if _keyword_is_false(node, "verify") and (
            name.startswith(("requests.", "httpx.", "session."))
            or tail in {"get", "post", "request"}
        ):
            self._add(PY_TLS_VERIFY_OFF, node)

        if name == "ssl._create_unverified_context":
            self._add(PY_UNVERIFIED_SSL_CONTEXT, node)

        if tail == "run" and _keyword_is_true(node, "debug"):
            self._add(PY_FLASK_DEBUG, node)

        if name.startswith("random.") and tail in RANDOM_FUNCTIONS:
            self._check_weak_random(node)

        if name in {"tempfile.mktemp", "mktemp"} and "tempfile" in name:
            self._add(PY_MKTEMP, node)

        if name.startswith("jwt.") and tail == "decode":
            self._check_jwt(node)

        if tail in XML_PARSERS:
            origin = self._resolve(name)
            # xml.etree / xml.dom / xml.sax resolve entities; defusedxml is the
            # fix, so it must never be reported as the problem.
            if origin.startswith("xml.") and not origin.startswith("defusedxml"):
                self._add(PY_XML_PARSE, node)

    def _check_shell_true(self, node: ast.Call, name: str) -> None:
        if not (name.startswith("subprocess.") or "Popen" in name):
            return
        if _keyword_is_true(node, "shell"):
            self._add(PY_SHELL_TRUE, node)

    def _check_weak_random(self, node: ast.Call) -> None:
        """Only flag randomness that is clearly standing in for a secret.

        `random.choice(colours)` is fine. The rule exists for tokens, passwords
        and one-time codes, so the surrounding line has to look like one.
        """
        line = self._snippet(node).lower()
        if any(word in line for word in ("token", "password", "secret", "otp", "key", "nonce")):
            self._add(PY_WEAK_RANDOM, node)

    def _check_jwt(self, node: ast.Call) -> None:
        if _keyword_is_false(node, "verify"):
            self._add(PY_JWT_UNVERIFIED, node)
            return
        for keyword in node.keywords:
            if keyword.arg == "options" and isinstance(keyword.value, ast.Dict):
                for key, value in zip(keyword.value.keys, keyword.value.values, strict=False):
                    if (
                        isinstance(key, ast.Constant)
                        and key.value == "verify_signature"
                        and isinstance(value, ast.Constant)
                        and value.value is False
                    ):
                        self._add(PY_JWT_UNVERIFIED, node)

    def _check_sql_execute(self, node: ast.Call, name: str | None) -> None:
        """A query string that was *built* rather than parameterised."""
        if not name or name.rsplit(".", 1)[-1] not in EXECUTE_METHODS or not node.args:
            return
        argument = node.args[0]
        if _is_built_string(argument) and _looks_like_sql(argument):
            self._add(PY_SQL_BUILT, node, snippet=self._snippet(argument) or self._snippet(node))

    # -- assignments ------------------------------------------------------

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802 - ast API
        self._check_hardcoded_secret(node)
        self.generic_visit(node)

    def _check_hardcoded_secret(self, node: ast.Assign) -> None:
        value = _literal_string(node.value)
        if value is None or len(value) < MIN_SECRET_LENGTH:
            return
        if value.strip().lower() in SECRET_PLACEHOLDERS:
            return
        # A value that reads configuration is the fix, not the problem.
        for target in node.targets:
            name = _target_name(target)
            if not name or not any(word in name.lower() for word in SECRET_NAMES):
                continue
            if _looks_like_reference(value):
                continue
            # The secret itself is never stored: the finding says where it is,
            # not what it is. A report is read by more people than the code.
            self._add(
                PY_HARDCODED_SECRET,
                node,
                snippet=f"{name} = {_redact(value)}",
            )
            return


# --- small AST helpers ----------------------------------------------------


def _call_name(node: ast.AST) -> str | None:
    """Dotted name of the thing being called, e.g. ``subprocess.run``."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _target_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _is_literal(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.JoinedStr):  # an f-string is built at runtime
        return False
    return False


def _literal_string(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _keyword_is_true(node: ast.Call, name: str) -> bool:
    return any(
        keyword.arg == name
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is True
        for keyword in node.keywords
    )


def _keyword_is_false(node: ast.Call, name: str) -> bool:
    return any(
        keyword.arg == name
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is False
        for keyword in node.keywords
    )


def _has_safe_loader(node: ast.Call) -> bool:
    for keyword in node.keywords:
        if keyword.arg == "Loader":
            loader = _call_name(keyword.value) or ""
            return "Safe" in loader
    return False


def _is_built_string(node: ast.AST) -> bool:
    """f-string, ``+`` concatenation, ``%`` formatting, or ``.format()``."""
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
        return True
    return bool(isinstance(node, ast.Call) and _call_name(node.func or node).endswith(".format"))


def _looks_like_sql(node: ast.AST) -> bool:
    text = " ".join(_string_parts(node)).lower()
    return any(keyword in text for keyword in SQL_KEYWORDS)


def _string_parts(node: ast.AST) -> list[str]:
    """Every literal string inside an expression, however it is assembled."""
    parts: list[str] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            parts.append(child.value)
    return parts


def _looks_like_reference(value: str) -> bool:
    """``os.environ['X']``-style values, or a template someone fills in later."""
    lowered = value.strip().lower()
    return (
        lowered.startswith(("$", "{{", "<", "%(", "os.environ", "env."))
        or lowered.endswith("}}")
        or "getenv" in lowered
    )


def _redact(value: str) -> str:
    """Keep the shape, lose the secret."""
    return f"<redacted {len(value)}-character value>"
