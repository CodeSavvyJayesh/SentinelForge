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

Since the evaluation phase, a rule also asks *what reaches the call*. The
file is walked once by :mod:`app.analysis.python_flow`, which describes every
argument as built from request data, built only from literals, or not known.
Each rule then does one of two things with that:

* A rule for a call that is dangerous by nature (``os.system``, ``eval``,
  ``pickle.loads``) reports it unless its argument is **shown** to be built
  from literals. A value nothing is known about is reported exactly as before.
* A rule for a call that is ordinary until request data reaches it (``open``,
  ``redirect``, an XPath query) reports it only when request data **is shown**
  to reach it. ``open(path)`` on its own is not a finding.
"""

import ast
import re
from dataclasses import dataclass

from app.analysis import python_flow as flow
from app.analysis.credential_names import is_not_a_credential
from app.analysis.findings import Confidence, Finding, Severity, clean_snippet
from app.analysis.rules import (
    PY_EVAL_EXEC,
    PY_FLASK_DEBUG,
    PY_HARDCODED_SECRET,
    PY_INSECURE_COOKIE,
    PY_JWT_UNVERIFIED,
    PY_LDAP_INJECTION,
    PY_MKTEMP,
    PY_OPEN_REDIRECT,
    PY_OS_SYSTEM,
    PY_PATH_TRAVERSAL,
    PY_PICKLE,
    PY_REFLECTED_XSS,
    PY_SHELL_COMMAND,
    PY_SHELL_TRUE,
    PY_SQL_BUILT,
    PY_TLS_VERIFY_OFF,
    PY_TRUST_BOUNDARY,
    PY_UNVERIFIED_SSL_CONTEXT,
    PY_WEAK_HASH,
    PY_WEAK_RANDOM,
    PY_XML_PARSE,
    PY_XPATH_INJECTION,
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
# The line a weak random number is produced on has to look like a secret...
RANDOM_CONTEXT = ("token", "password", "secret", "otp", "key", "nonce")
# ...or the value has to be followed to somewhere that is one.
SECRET_PLACES = (*RANDOM_CONTEXT, "passwd", "session", "cookie", "csrf", "salt")

SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "cmd", "cmd.exe", "powershell", "pwsh"})

# Methods of a pathlib path that touch the file system.
PATH_METHODS = frozenset(
    {
        "read_text", "read_bytes", "write_text", "write_bytes", "open", "exists", "is_file",
        "is_dir", "unlink", "rmdir", "mkdir", "iterdir", "glob", "rglob", "stat", "touch",
    }
)  # fmt: skip
# Method -> position of the filter, in ldap3 and in python-ldap.
LDAP_METHODS = {"search": 1, "search_s": 2, "search_st": 2, "search_ext": 2, "search_ext_s": 2}
LDAP_KEYWORDS = ("search_filter", "filterstr")
REDIRECT_CALLS = frozenset(
    {
        "flask.redirect", "quart.redirect", "bottle.redirect", "django.shortcuts.redirect",
        "django.http.HttpResponseRedirect", "django.http.HttpResponsePermanentRedirect",
        "starlette.responses.RedirectResponse", "fastapi.responses.RedirectResponse",
    }
)  # fmt: skip
# Calls that put their first argument into a page as HTML.
HTML_CALLS = frozenset(
    {
        "flask.make_response", "flask.Response", "flask.render_template_string",
        "flask.Markup", "markupsafe.Markup", "django.http.HttpResponse",
        "django.utils.safestring.mark_safe",
    }
)  # fmt: skip
SESSION_OBJECTS = frozenset({"flask.session", "quart.session"})
XML_DOCUMENT_PARSERS = frozenset(
    {
        "xml.dom.minidom.parse", "xml.dom.minidom.parseString", "xml.dom.pulldom.parse",
        "xml.dom.pulldom.parseString", "xml.sax.parse", "xml.sax.parseString",
    }
)  # fmt: skip


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
    observed = flow.analyse(tree)
    visitor = _Visitor(_Context(file_path=file_path, lines=source.splitlines()), observed)
    visitor.visit(tree)
    visitor.after_the_walk()
    return visitor.findings


class _Visitor(ast.NodeVisitor):
    def __init__(self, context: _Context, observed: flow.Flow) -> None:
        self.context = context
        self.flow = observed
        self.findings: list[Finding] = []
        # Local name -> module it came from, so `from xml.etree import
        # ElementTree` and `from defusedxml import ElementTree` can be told
        # apart. Both are called `ElementTree.parse(...)` at the call site;
        # only one of them is a finding.
        self.imports: dict[str, str] = {}
        # Places a value is written into a page: (where, the body, the function).
        self._html: list[tuple[ast.AST, flow.Value, ast.AST | None]] = []
        # Lines where a weak random number is produced that ends up as a secret.
        self._weak_random_lines: set[int] = set()

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
        source: flow.Taint | None = None,
    ) -> None:
        line = getattr(node, "lineno", 0) or 0
        text = message or rule.message
        if source is not None:
            # Shown, not inferred: say where the value came in.
            text = f"{text} Here the value comes from the request, read on line {source.line}."
            confidence = confidence or Confidence.HIGH
        self.findings.append(
            Finding(
                rule_id=rule.id,
                title=rule.title,
                message=text,
                severity=severity or rule.severity,
                confidence=confidence or rule.confidence,
                cwe_id=rule.cwe_id,
                owasp_category=rule.owasp_category,
                file_path=self.context.file_path,
                line_start=line,
                line_end=getattr(node, "end_lineno", None) or getattr(node, "lineno", 0) or 0,
                snippet=snippet if snippet is not None else self._snippet(node),
                analyzer=ANALYZER,
            )
        )

    # -- what reaches a call ------------------------------------------------

    def _reaching(
        self, node: ast.Call, index: int, kind: str, keyword: str | None = None
    ) -> tuple[str, flow.Taint | None]:
        """How dangerous one argument of a call is for one kind of use.

        "Unknown" whenever the walk did not get there or the argument is not
        present: never "clean" by default.
        """
        if self.flow.unreachable(node):
            return flow.CLEAN, None  # nothing reaches a call that never runs
        seen = self.flow.call(node)
        value = None if seen is None else seen.argument(index, keyword)
        if value is None:
            return flow.UNKNOWN, None
        return flow.classify(value, kind)

    def _dangerous_by_nature(
        self, rule: Rule, node: ast.Call, index: int, kind: str, keyword: str | None = None
    ) -> None:
        """Report unless the argument is shown to be built from literals."""
        level, source = self._reaching(node, index, kind, keyword)
        if level != flow.CLEAN:
            self._add(rule, node, source=source)

    def _dangerous_with_input(
        self, rule: Rule, node: ast.Call, index: int, kind: str, keyword: str | None = None
    ) -> None:
        """Report only when request data is shown to reach the argument."""
        level, source = self._reaching(node, index, kind, keyword)
        if level == flow.TAINTED:
            self._add(rule, node, source=source)

    # -- calls ------------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802 - ast API
        name = _call_name(node.func)
        if name:
            self._check_call(node, name)
        self._check_sql_execute(node, name)
        self._check_reached_by_input(node)
        self.generic_visit(node)

    def _check_call(self, node: ast.Call, name: str) -> None:
        tail = name.rsplit(".", 1)[-1]

        # eval / exec, but only on something built at runtime. eval("2 + 2") is
        # pointless, not dangerous, and flagging it teaches people to ignore us.
        if name in {"eval", "exec"} and node.args and not _is_literal(node.args[0]):
            self._dangerous_by_nature(PY_EVAL_EXEC, node, 0, flow.CODE)

        if name in {"os.system", "os.popen", "system", "popen"} and name.startswith("os."):
            self._dangerous_by_nature(PY_OS_SYSTEM, node, 0, flow.COMMAND)

        if name.startswith(("subprocess.", "Popen")) or tail in {"run", "call", "check_output"}:
            self._check_shell_true(node, name)

        if (
            name in {"yaml.load", "load"}
            and name.startswith("yaml.")
            and not _has_safe_loader(node)
        ):
            self._dangerous_by_nature(PY_YAML_LOAD, node, 0, flow.DATA, "stream")

        if name in {"pickle.loads", "pickle.load", "cPickle.loads", "dill.loads"}:
            self._dangerous_by_nature(PY_PICKLE, node, 0, flow.DATA)

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
                if tail == "fromstring":
                    # A document written in the source is not untrusted XML.
                    self._dangerous_by_nature(PY_XML_PARSE, node, 0, flow.DATA)
                else:
                    self._add(PY_XML_PARSE, node)

        if tail == "set_cookie" and _keyword_is_false(node, "secure"):
            self._add(PY_INSECURE_COOKIE, node)

    def _check_shell_true(self, node: ast.Call, name: str) -> None:
        if not (name.startswith("subprocess.") or "Popen" in name):
            return
        if _keyword_is_true(node, "shell"):
            self._dangerous_by_nature(PY_SHELL_TRUE, node, 0, flow.COMMAND, "args")

    def _check_weak_random(self, node: ast.Call) -> None:
        """Only flag randomness that is clearly standing in for a secret.

        `random.choice(colours)` is fine. The rule exists for tokens, passwords
        and one-time codes, so the surrounding line has to look like one.
        """
        line = self._snippet(node).lower()
        if any(word in line for word in RANDOM_CONTEXT):
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
        level, source = self._reaching(node, 0, flow.SQL)
        if level == flow.CLEAN:
            return  # every part of the query is written in the source
        if level == flow.TAINTED:
            # However the string was put together, request data is in it.
            self._add(
                PY_SQL_BUILT,
                node,
                snippet=self._snippet(argument) or self._snippet(node),
                source=source,
            )
            return
        if _is_built_string(argument) and _looks_like_sql(argument):
            self._add(PY_SQL_BUILT, node, snippet=self._snippet(argument) or self._snippet(node))
            return
        # The same thing one step removed: the query was built on an earlier
        # line and passed here by name. What is known about it is how it
        # begins, and that the rest is not a literal.
        seen = self.flow.call(node)
        query = None if seen is None else seen.argument(0)
        if query is not None and query.prefix and _is_sql_text(query.prefix):
            self._add(PY_SQL_BUILT, node)

    # -- calls that are ordinary until request data reaches them ----------------

    def _check_reached_by_input(self, node: ast.Call) -> None:  # noqa: PLR0912 - one branch per sink
        seen = self.flow.call(node)
        if seen is None:
            return
        qualified = seen.qualified or ""
        method = node.func.attr if isinstance(node.func, ast.Attribute) else None

        if qualified in flow.SUBPROCESS_CALLS and not _keyword_is_true(node, "shell"):
            self._check_command_list(node, seen)

        if qualified in flow.FILE_CALLS:
            self._dangerous_with_input(PY_PATH_TRAVERSAL, node, 0, flow.PATH)
        elif (
            method in PATH_METHODS
            and seen.receiver is not None
            and flow.FLAG_PATH in seen.receiver.flags
        ):
            level, source = flow.classify(seen.receiver, flow.PATH)
            if level == flow.TAINTED:
                self._add(PY_PATH_TRAVERSAL, node, source=source)

        if method == "xpath":
            self._dangerous_with_input(PY_XPATH_INJECTION, node, 0, flow.XPATH)
        elif qualified in flow.XPATH_CALLS:
            self._dangerous_with_input(
                PY_XPATH_INJECTION, node, flow.XPATH_CALLS[qualified], flow.XPATH, "path"
            )

        if method in LDAP_METHODS and any(
            origin.split(".")[0] in {"ldap", "ldap3"} for origin in self.imports.values()
        ):
            keyword = next((key for key in LDAP_KEYWORDS if key in seen.keywords), None)
            self._dangerous_with_input(
                PY_LDAP_INJECTION, node, LDAP_METHODS[method], flow.LDAP, keyword
            )

        if qualified in REDIRECT_CALLS:
            destination = seen.argument(0)
            # "/orders/" + number can only be a page of this site.
            if destination is not None and not _stays_on_this_site(destination.prefix):
                self._dangerous_with_input(PY_OPEN_REDIRECT, node, 0, flow.REDIRECT)

        if qualified in HTML_CALLS:
            body = seen.argument(0)
            if body is not None:
                self._html.append((node, _body_of(body), seen.function))

        if method == "set_cookie":
            value = seen.argument(1, "value")
            weak = None if value is None else flow.predictable(value)
            if weak is not None:
                self._weak_random_lines.add(weak.line)

        if qualified in XML_DOCUMENT_PARSERS or method == "parse":
            self._check_entity_parser(node, seen, qualified in XML_DOCUMENT_PARSERS)

    def _check_command_list(self, node: ast.Call, seen: flow.CallSeen) -> None:
        """``subprocess.run([...])`` with no ``shell=True`` — usually the safe form.

        It stops being safe in two cases: the list itself starts a shell
        (``["sh", "-c", command]``), or its first element — the program to run —
        is the caller's to choose.
        """
        command = seen.argument(0, "args")
        if command is None:
            return
        if command.items is None:
            level, source = flow.classify(command, flow.COMMAND)
            if level == flow.TAINTED:
                self._add(PY_SHELL_COMMAND, node, source=source)
            return
        if not command.items:
            return
        program, arguments = command.items[0], command.items[1:]
        level, source = flow.classify(program, flow.COMMAND)
        if level == flow.TAINTED:
            self._add(PY_SHELL_COMMAND, node, source=source)
            return
        names = program.constants
        starts_a_shell = names is not None and all(
            isinstance(name, str) and name.replace("\\", "/").rsplit("/", 1)[-1].lower() in SHELLS
            for name in names
        )
        if starts_a_shell:
            for argument in arguments:
                level, source = flow.classify(argument, flow.COMMAND)
                if level == flow.TAINTED:
                    self._add(PY_SHELL_COMMAND, node, source=source)
                    return

    def _check_entity_parser(self, node: ast.Call, seen: flow.CallSeen, document: bool) -> None:
        """A parser that was told to resolve external entities, given a document."""
        parser = seen.argument(1, "parser") if document else seen.receiver
        if parser is None or flow.FLAG_ENTITIES not in parser.flags:
            return
        level, source = self._reaching(node, 0, flow.DATA)
        if level != flow.CLEAN:
            self._add(
                PY_XML_PARSE,
                node,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                message=(
                    "This parser was configured to resolve external entities "
                    "(feature_external_ges), so a document can make it read local files "
                    "or call internal addresses. Leave that feature off, or parse "
                    "untrusted XML with defusedxml."
                ),
                source=source,
            )

    # -- after every call has been visited ---------------------------------------

    def after_the_walk(self) -> None:
        """Findings that are about where a value ended up, not about one call."""
        if not self.flow.complete:
            return
        for returned in self.flow.returns:
            # A dict returned from a route is sent as JSON, not as a page.
            if (
                returned.route
                and self.flow.html_routes
                and flow.FLAG_DICT not in returned.value.flags
            ):
                self._html.append((returned.node, _body_of(returned.value), returned.function))
        self._report_html()

        for stored in self.flow.stores:
            target = stored.qualified or stored.target or ""
            if stored.key is not None and (
                target in SESSION_OBJECTS or target == "session" or target.endswith(".session")
            ):
                for value in (stored.key, stored.value):
                    level, source = flow.classify(value, flow.TRUST)
                    if level == flow.TAINTED:
                        self._add(PY_TRUST_BOUNDARY, stored.node, source=source)
                        break
            weak = flow.predictable(stored.value)
            place = f"{stored.target or ''} {stored.key_text}".lower()
            if weak is not None and any(word in place for word in SECRET_PLACES):
                self._weak_random_lines.add(weak.line)
        already = {f.line_start for f in self.findings if f.rule_id == PY_WEAK_RANDOM.id}
        for line in sorted(self._weak_random_lines - already):
            self._add_at(PY_WEAK_RANDOM, line)

    def _report_html(self) -> None:
        """One finding per request value per function, at the first place it leaves.

        A page built from one parameter and returned through three ``return``
        statements is one thing to fix, not three.
        """
        first: dict[tuple[int, tuple[str, int, int]], tuple[ast.AST, flow.Taint]] = {}
        for node, body, function in self._html:
            level, source = flow.classify(body, flow.HTML)
            if level != flow.TAINTED or source is None:
                continue
            key = (id(function), source.label)
            line = getattr(node, "lineno", 0)
            if key not in first or line < getattr(first[key][0], "lineno", 0):
                first[key] = (node, source)
        for node, source in first.values():
            self._add(PY_REFLECTED_XSS, node, source=source, confidence=Confidence.MEDIUM)

    def _add_at(self, rule: Rule, line: int) -> None:
        """Report a rule at a line rather than at a node."""
        marker = ast.Pass(lineno=line, end_lineno=line, col_offset=0, end_col_offset=0)
        self._add(rule, marker)

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
            if is_not_a_credential(name, value):
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


SAME_SITE_PREFIX = re.compile(r"/[^/\\]|https?://[^/@\\]+/")


def _stays_on_this_site(prefix: str | None) -> bool:
    """Whether an address that begins with ``prefix`` is fixed to one host.

    ``/orders/`` is; ``/`` alone is not, because ``/`` + ``/evil.example`` is
    another site. ``https://example.com/`` is; ``https://`` is not.
    """
    return bool(prefix and SAME_SITE_PREFIX.match(prefix))


def _body_of(value: flow.Value) -> flow.Value:
    """The page in ``(page, status, headers)``; headers are not HTML."""
    return value.items[0] if value.items else value


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
    # Matched on the attribute itself, not on a dotted name. `_call_name` cannot
    # name a call on a literal — `"SELECT …".format(x)` has no name to its left —
    # so going through it missed the most common way `.format()` is written.
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    )


def _looks_like_sql(node: ast.AST) -> bool:
    return _is_sql_text(" ".join(_string_parts(node)))


def _is_sql_text(text: str) -> bool:
    lowered = text.lower()
    return any(keyword in lowered for keyword in SQL_KEYWORDS)


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
