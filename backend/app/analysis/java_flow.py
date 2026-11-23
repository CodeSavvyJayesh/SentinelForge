"""Follow values through Java methods: where request data goes, and what stays constant.

Phase 16 did this for Python. This is the same idea for Java, written for the
same two reasons:

1. **To report what a pattern cannot see.** A file name, an LDAP filter or a
   page of HTML built from a request parameter is only a weakness because of
   where the value came from, and that is usually several statements away from
   where it is used. The walk carries each value's origin from the statements
   that read the request to the calls that use it.
2. **To withdraw what a pattern got wrong.** The SQL rule reports a query
   string joined to a value. When the walk can show that every value joined in
   is a constant — `bar = "safe!"`, a map entry put in under a different key, a
   branch that can never be taken — the report is withdrawn.

The two are deliberately asymmetric, and that is the safety property:

* A new finding needs a **positive** reason: request data, read from the
  request in this file, reaching the call. Anything the walk does not
  understand is *not* request data.
* Withdrawing a finding needs a **positive** reason too: every value involved
  is known to be built from literals. Anything the walk does not understand is
  *not* known to be safe.

So a gap in the walk can cost a finding it might have made; it cannot hide a
finding the pattern made.

Nothing is executed. The source is read by :mod:`app.analysis.java_syntax` and
walked here; calls into other methods of the project are followed by reading
those methods, with the values the caller passed.
"""

from __future__ import annotations

import operator
import re
from collections.abc import Hashable, Iterable, Iterator
from dataclasses import dataclass, field, replace

from app.analysis import java_syntax as js

# --- what is known about a value ---------------------------------------------

COMMAND = "command"
SQL = "sql"
PATH = "path"
LDAP = "ldap"
XPATH = "xpath"
HTML = "html"
TRUST = "trust"

MAX_CONSTANTS = 8
MAX_TEXT = 2048
MAX_ITEMS = 32
MAX_CALL_DEPTH = 4
MAX_STEPS = 150_000
LOOP_PASSES = 3


@dataclass(frozen=True)
class Value:
    # Request data reaches it.
    tainted: bool = False
    # Kinds of use the request data in it has been made safe for.
    safe: frozenset[str] = frozenset()
    # Where it came from is not known: a field, a parameter, an unknown call.
    opaque: bool = False
    # Every value it can be, when that is known.
    constants: frozenset[Hashable] | None = None
    # A list or array whose elements are known one by one.
    items: tuple[Value, ...] | None = None
    # A map whose keys are literals.
    entries: tuple[tuple[Hashable, Value], ...] | None = None
    # What sort of object it is, when that matters: "request", "writer", ...
    kind: str | None = None
    # Part of it is a query string joined to a value, which the SQL pattern
    # reports where the joining is done. A query like that is not reported a
    # second time where it is run.
    built: bool = False

    @property
    def clean(self) -> bool:
        """Built only from literals in the source, as far as anything inside it goes."""
        return not self.everything().tainted and not self.everything().opaque

    def everything(self) -> Value:
        """Itself, with what it contains folded in and the structure forgotten."""
        if self.items is None and self.entries is None:
            return self
        folded = Value(
            self.tainted, self.safe if self.tainted else frozenset(), self.opaque, built=self.built
        )
        for item in self.items or ():
            folded = join(folded, item.everything())
        for _key, entry in self.entries or ():
            folded = join(folded, entry.everything())
        return Value(folded.tainted, folded.safe, folded.opaque, kind=self.kind, built=folded.built)

    def dangerous_for(self, kind: str) -> bool:
        whole = self.everything()
        return whole.tainted and kind not in whole.safe


CLEAN = Value()
OPAQUE = Value(opaque=True)
TAINTED = Value(tainted=True)


def constant(value: Hashable) -> Value:
    return Value(constants=frozenset({value}))


def join(first: Value | None, second: Value | None) -> Value:
    """What is known about a value that is one or the other."""
    if first is None:
        return second if second is not None else CLEAN
    if second is None or first == second:
        return first
    if first.tainted and second.tainted:
        safe = first.safe & second.safe
    else:
        safe = first.safe if first.tainted else second.safe
    constants = None
    if first.constants is not None and second.constants is not None:
        merged = first.constants | second.constants
        constants = merged if len(merged) <= MAX_CONSTANTS else None
    items = None
    if (
        first.items is not None
        and second.items is not None
        and len(first.items) == len(second.items)
    ):
        items = tuple(join(a, b) for a, b in zip(first.items, second.items, strict=True))
    elif first.items is not None or second.items is not None:
        whole = join(first.everything(), second.everything())
        return replace(whole, kind=first.kind if first.kind == second.kind else None)
    entries = None
    if first.entries is not None and second.entries is not None:
        keys = [key for key, _ in first.entries]
        keys += [key for key, _ in second.entries if key not in keys]
        found_first = dict(first.entries)
        found_second = dict(second.entries)
        entries = tuple(
            (key, join(found_first.get(key, CLEAN), found_second.get(key, CLEAN))) for key in keys
        )
    elif first.entries is not None or second.entries is not None:
        whole = join(first.everything(), second.everything())
        return replace(whole, kind=first.kind if first.kind == second.kind else None)
    return Value(
        tainted=first.tainted or second.tainted,
        safe=safe,
        opaque=first.opaque or second.opaque,
        constants=constants,
        items=items,
        entries=entries,
        kind=first.kind if first.kind == second.kind else None,
        built=first.built or second.built,
    )


def join_all(values: Iterable[Value]) -> Value:
    result: Value | None = None
    for value in values:
        result = join(result, value)
    return result if result is not None else CLEAN


def derived(values: Iterable[Value], *, known: frozenset[Hashable] | None = None) -> Value:
    """A value computed from these: their origins, none of their structure."""
    whole = join_all(value.everything() for value in values)
    return Value(whole.tainted, whole.safe, whole.opaque, constants=known, built=whole.built)


def only(value: Value) -> Hashable | None:
    if value.constants is not None and len(value.constants) == 1:
        return next(iter(value.constants))
    return None


# --- what the walk knows about the outside world ----------------------------------

REQUEST_TYPES = frozenset(
    {"HttpServletRequest", "ServletRequest", "HttpServletRequestWrapper", "ServletRequestWrapper"}
)
RESPONSE_TYPES = frozenset({"HttpServletResponse", "ServletResponse", "HttpServletResponseWrapper"})
TYPE_KINDS: dict[str, str] = {
    "HttpSession": "session",
    "DirContext": "ldap",
    "InitialDirContext": "ldap",
    "LdapContext": "ldap",
    "InitialLdapContext": "ldap",
    "XPath": "xpath",
    "Statement": "sql",
    "PreparedStatement": "sql",
    "CallableStatement": "sql",
    "Connection": "sql",
    "JdbcTemplate": "sql",
    "JdbcOperations": "sql",
    "NamedParameterJdbcTemplate": "sql",
    "EntityManager": "sql",
    "Runtime": "process",
    "ProcessBuilder": "process",
}
# Spring's way of saying "this parameter comes from the request".
REQUEST_ANNOTATIONS = frozenset(
    {
        "RequestParam",
        "PathVariable",
        "RequestHeader",
        "CookieValue",
        "RequestBody",
        "MatrixVariable",
    }
)
# Reading these from the request returns data the client chose.
REQUEST_SOURCES = frozenset(
    {
        "getParameter",
        "getParameterValues",
        "getParameterMap",
        "getParameterNames",
        "getHeader",
        "getHeaders",
        "getHeaderNames",
        "getQueryString",
        "getCookies",
        "getRequestURI",
        "getRequestURL",
        "getPathInfo",
        "getPathTranslated",
        "getInputStream",
        "getReader",
        "getPart",
        "getParts",
        "getRemoteUser",
    }
)
# Reading these returns something the server decides.
REQUEST_CLEAN = frozenset(
    {
        "getMethod",
        "getContextPath",
        "getServletPath",
        "getScheme",
        "getProtocol",
        "getServerName",
        "getServerPort",
        "getLocalPort",
        "getContentLength",
        "isSecure",
        "getRequestDispatcher",
    }
)
SANITISERS: dict[str, frozenset[str]] = {
    "encodeForHTML": frozenset({HTML}),
    "encodeForHTMLAttribute": frozenset({HTML}),
    "encodeForJavaScript": frozenset({HTML}),
    "encodeForCSS": frozenset({HTML}),
    "escapeHtml": frozenset({HTML}),
    "escapeHtml3": frozenset({HTML}),
    "escapeHtml4": frozenset({HTML}),
    "escapeXml": frozenset({HTML}),
    "escapeXml10": frozenset({HTML}),
    "escapeXml11": frozenset({HTML}),
    "htmlEscape": frozenset({HTML}),
    "forHtml": frozenset({HTML}),
    "forHtmlContent": frozenset({HTML}),
    "forHtmlAttribute": frozenset({HTML}),
    "encodeForSQL": frozenset({SQL}),
    "escapeSql": frozenset({SQL}),
    "encodeForLDAP": frozenset({LDAP}),
    "encodeForDN": frozenset({LDAP}),
    "encodeForXPath": frozenset({XPATH}),
    "encodeForOS": frozenset({COMMAND}),
}
# Methods that put an argument into the object they are called on.
STORING = frozenset(
    {
        "add",
        "addAll",
        "addElement",
        "push",
        "offer",
        "put",
        "putAll",
        "set",
        "setValue",
        "append",
        "insert",
        "addFirst",
        "addLast",
        "offerFirst",
        "offerLast",
        "putIfAbsent",
        "merge",
        "compute",
        "replace",
        "setAttribute",
    }
)
# Methods that read from an object without storing what they are given.
QUERYING = frozenset(
    {
        "equals",
        "equalsIgnoreCase",
        "contains",
        "containsKey",
        "containsValue",
        "startsWith",
        "endsWith",
        "indexOf",
        "lastIndexOf",
        "matches",
        "compareTo",
        "isEmpty",
        "size",
        "length",
        "hashCode",
        "get",
        "getOrDefault",
        "charAt",
    }
)
COLLECTION_TYPES = frozenset(
    {"ArrayList", "LinkedList", "Vector", "Stack", "ArrayDeque", "CopyOnWriteArrayList"}
)
MAP_TYPES = frozenset(
    {"HashMap", "LinkedHashMap", "TreeMap", "Hashtable", "ConcurrentHashMap", "Properties"}
)
BUILDER_TYPES = frozenset({"StringBuilder", "StringBuffer"})

# Calls that use a value in a way the value can attack.
STRONG_SQL_CALLS = frozenset(
    {
        "executeQuery",
        "executeUpdate",
        "executeLargeUpdate",
        "prepareStatement",
        "prepareCall",
        "addBatch",
        "createNativeQuery",
        "createSQLQuery",
        "queryForObject",
        "queryForList",
        "queryForMap",
        "queryForRowSet",
        "queryForLong",
        "queryForInt",
        "batchUpdate",
        "nativeSQL",
    }
)
WEAK_SQL_CALLS = frozenset({"execute", "query", "update", "createQuery"})
FILE_CONSTRUCTORS = frozenset(
    {"File", "FileInputStream", "FileOutputStream", "FileReader", "FileWriter", "RandomAccessFile"}
)
FILE_CALLS = frozenset(
    {
        "newInputStream",
        "newOutputStream",
        "newBufferedReader",
        "newBufferedWriter",
        "readAllBytes",
        "readAllLines",
        "readString",
        "write",
        "writeString",
        "lines",
        "delete",
        "deleteIfExists",
        "copy",
        "move",
        "createFile",
        "newByteChannel",
    }
)
WRITER_CALLS = frozenset({"print", "println", "printf", "format", "write", "append"})


@dataclass(frozen=True)
class Hit:
    """A use of request data that the walk reports."""

    kind: str  # COMMAND, SQL, PATH, LDAP, XPATH, HTML, TRUST
    line: int
    detail: str


@dataclass
class FileReport:
    hits: list[Hit] = field(default_factory=list)
    # Lines of a query string joined to values, and whether every value was clean.
    sql_joins: dict[int, bool] = field(default_factory=dict)
    # Line ranges of the methods that were read whole.
    methods: list[tuple[int, int]] = field(default_factory=list)
    unreadable: list[tuple[int, int]] = field(default_factory=list)


class _GaveUp(Exception):
    """The walk ran out of budget. What it found so far is discarded."""


# --- the project: every class the walk can follow a call into ---------------------


# A name that more classes than this share is not followed: which one is meant
# cannot be told without the imports, and following all of them costs time and
# blurs the answer.
MAX_CANDIDATES = 8


class Project:
    """The Java classes of one analysis, so a call can be followed into another file.

    Files are read lazily. Every source is indexed by the type names it declares
    and extends, with a regular expression, which is cheap; a file is parsed only
    when the walk needs one of its classes. On a large repository most files are
    never parsed: nothing reached by request data calls into them.
    """

    def __init__(self) -> None:
        self.classes: dict[str, list[js.ClassDecl]] = {}
        self.implementors: dict[str, list[js.ClassDecl]] = {}
        self.units: dict[str, js.CompilationUnit] = {}
        self.class_file: dict[int, str] = {}
        self._sources: dict[str, str] = {}
        self._declaring: dict[str, set[str]] = {}
        self._extending: dict[str, set[str]] = {}
        self._unreadable: set[str] = set()

    @property
    def sources(self) -> dict[str, str]:
        return self._sources

    def add_source(self, path: str, source: str) -> None:
        self._sources[path] = source
        for name in _DECLARED.findall(source):
            self._declaring.setdefault(name, set()).add(path)
        for clause in _SUPERTYPES.findall(source):
            for name in _type_names(clause):
                self._extending.setdefault(name, set()).add(path)

    def unit(self, path: str) -> js.CompilationUnit | None:
        """The file, parsed; None if it is not part of the project or cannot be read."""
        if path in self.units:
            return self.units[path]
        source = self._sources.get(path)
        if source is None or path in self._unreadable:
            return None
        try:
            parsed = js.parse(source)
        except js.SyntaxProblem:
            self._unreadable.add(path)
            return None
        self.add(path, parsed)
        return parsed

    def add(self, path: str, unit: js.CompilationUnit) -> None:
        self.units[path] = unit
        for declared in unit.all_classes():
            self.classes.setdefault(declared.name, []).append(declared)
            self.class_file[id(declared)] = path
            for supertype in declared.supertypes:
                self.implementors.setdefault(supertype, []).append(declared)

    def _load(self, paths: set[str]) -> bool:
        """Parse these files, unless there are too many to say which is meant."""
        if len(paths) > MAX_CANDIDATES:
            return False
        for path in sorted(paths):
            self.unit(path)
        return True

    def named(self, type_name: str, path: str | None = None) -> list[js.ClassDecl]:
        """Classes with this simple name: the ones in ``path`` if there are any there."""
        simple = type_name.split(".")[-1].removesuffix("[]")
        if path is not None:
            self.unit(path)
            local = [
                declared
                for declared in self.classes.get(simple, [])
                if self.class_file.get(id(declared)) == path
            ]
            if local:
                return local
        if not self._load(self._declaring.get(simple, set())):
            return []
        found = self.classes.get(simple, [])
        return found if len(found) <= MAX_CANDIDATES else []

    def implementations(
        self, type_name: str, method: str, arity: int, path: str | None = None
    ) -> list[js.Method]:
        """The methods a call on something declared as ``type_name`` may run."""
        simple = type_name.split(".")[-1]
        classes = list(self.named(simple, path))
        if self._load(self._extending.get(simple, set())):
            implementors = self.implementors.get(simple, [])
            if len(implementors) <= MAX_CANDIDATES:
                classes += [declared for declared in implementors if declared not in classes]
        found: list[js.Method] = []
        for declared in classes:
            found.extend(_methods(declared, method, arity, bodies_only=True))
        return found if len(found) <= MAX_CANDIDATES else []


_DECLARED = re.compile(r"\b(?:class|interface|enum|record)\s+([A-Za-z_$][\w$]*)")
_SUPERTYPES = re.compile(r"\b(?:extends|implements)\s+([^{;()=]{1,400}?)\{")
_GENERIC = re.compile(r"<[^<>]*>")
_NOT_TYPES = frozenset({"extends", "implements", "super", "permits", "final"})


def _type_names(clause: str) -> list[str]:
    for _ in range(4):
        clause = _GENERIC.sub("", clause)
    names = []
    for word in re.split(r"[,\s&]+", clause):
        simple = word.split(".")[-1]
        if simple and simple not in _NOT_TYPES and re.fullmatch(r"[A-Za-z_$][\w$]*", simple):
            names.append(simple)
    return names


def _methods(
    declared: js.ClassDecl, name: str, arity: int, *, bodies_only: bool = False
) -> list[js.Method]:
    return [
        method
        for method in declared.methods
        if method.name == name
        and _arity_fits(method, arity)
        and not method.is_constructor
        and (method.body is not None or not bodies_only)
    ]


def _arity_fits(method: js.Method, arity: int) -> bool:
    count = len(method.parameters)
    if count == arity:
        return True
    return (
        bool(method.parameters)
        and method.parameters[-1].type_name.endswith("[]")
        and arity >= count - 1
    )


def _kind_of_type(type_name: str) -> str | None:
    simple = type_name.split(".")[-1].removesuffix("[]")
    if simple in REQUEST_TYPES:
        return "request"
    if simple in RESPONSE_TYPES:
        return "response"
    return TYPE_KINDS.get(simple)


def _dotted(node: js.Node) -> str | None:
    if isinstance(node, js.Name):
        return node.name
    if isinstance(node, js.Field):
        base = _dotted(node.target)
        return f"{base}.{node.name}" if base else None
    return None


def _first_line(node: js.Node) -> int:
    line = node.line
    while isinstance(node, js.Binary):
        node = node.left
        line = min(line, node.line)
    return line


def _concatenated(node: js.Node) -> list[js.Node]:
    """`a + b + c` as [a, b, c]."""
    parts: list[js.Node] = []
    pending = [node]
    while pending:
        current = pending.pop()
        if isinstance(current, js.Binary) and current.op == "+":
            pending.append(current.right)
            pending.append(current.left)
        else:
            parts.append(current)
    return parts


# --- the walk ----------------------------------------------------------------------


@dataclass
class _Frame:
    method: js.Method
    owner: js.ClassDecl
    types: dict[str, str]
    in_file: bool
    returns: list[Value] = field(default_factory=list)
    breaks: list[list[dict[str, Value]]] = field(default_factory=list)
    continues: list[list[dict[str, Value]]] = field(default_factory=list)


State = dict[str, Value]


class Walker:
    def __init__(self, project: Project, path: str, sql_text: object) -> None:
        self.project = project
        self.path = path
        self.report = FileReport()
        self.steps = 0
        self.frames: list[_Frame] = []
        self.summaries: dict[tuple[int, tuple[Value, ...]], Value] = {}
        self.active: set[int] = set()
        self._sql_text = sql_text  # a compiled pattern: is this literal SQL?
        self._hits: dict[tuple[str, int], Hit] = {}
        self._joins: dict[int, bool] = {}

    # -- entry points

    def file(self, unit: js.CompilationUnit, only_lines: list[int] | None = None) -> FileReport:
        for declared in unit.all_classes():
            for method in declared.methods:
                holds_sql = only_lines is not None and any(
                    method.line <= line <= method.last_line for line in only_lines
                )
                if only_lines is not None and not holds_sql:
                    continue
                if only_lines is None and not self.can_see_request(method, declared):
                    # Walked only if a method that can see the request calls it.
                    continue
                if not method.readable:
                    self.report.unreadable.append((method.line, method.last_line))
                    continue
                if method.body is None:
                    continue
                saved_hits, saved_joins = dict(self._hits), dict(self._joins)
                try:
                    self.steps = 0
                    self.entry(method, declared)
                    self.report.methods.append((method.line, method.last_line))
                except (_GaveUp, RecursionError):
                    # Nothing from a method the walk could not finish is used.
                    self._hits, self._joins = saved_hits, saved_joins
                    self.report.unreadable.append((method.line, method.last_line))
        self.report.hits = sorted(self._hits.values(), key=lambda hit: (hit.line, hit.kind))
        self.report.sql_joins = dict(self._joins)
        return self.report

    def can_see_request(self, method: js.Method, owner: js.ClassDecl) -> bool:
        """Whether request data can enter this method other than through a caller."""
        for parameter in method.parameters:
            if _kind_of_type(parameter.type_name) == "request" or any(
                name.split(".")[-1] in REQUEST_ANNOTATIONS for name in parameter.annotations
            ):
                return True
        current: js.ClassDecl | None = owner
        while current is not None:
            if any(
                _kind_of_type(field.type_name) == "request" for field in current.fields.values()
            ):
                return True
            current = current.outer
        return False

    def entry(self, method: js.Method, owner: js.ClassDecl) -> None:
        state: State = {}
        types: dict[str, str] = {}
        for parameter in method.parameters:
            types[parameter.name] = parameter.type_name
            state[parameter.name] = self._parameter_value(parameter)
        self.run(method, owner, state, types, in_file=True)

    def _parameter_value(self, parameter: js.Parameter) -> Value:
        kind = _kind_of_type(parameter.type_name)
        if kind is not None:
            return Value(kind=kind)
        if any(name.split(".")[-1] in REQUEST_ANNOTATIONS for name in parameter.annotations):
            return TAINTED
        return OPAQUE

    def run(
        self,
        method: js.Method,
        owner: js.ClassDecl,
        state: State,
        types: dict[str, str],
        *,
        in_file: bool,
    ) -> Value:
        if method.body is None:
            return CLEAN
        frame = _Frame(method, owner, types, in_file)
        self.frames.append(frame)
        try:
            self.block(method.body.body, state)
        finally:
            self.frames.pop()
        return join_all(frame.returns) if frame.returns else CLEAN

    @property
    def frame(self) -> _Frame:
        return self.frames[-1]

    def tick(self) -> None:
        self.steps += 1
        if self.steps > MAX_STEPS:
            raise _GaveUp()

    # -- recording

    def hit(self, kind: str, line: int, detail: str) -> None:
        if self.frame.in_file:
            self._hits.setdefault((kind, line), Hit(kind, line, detail))

    def joined_sql(self, first: int, last: int, clean: bool) -> None:
        if not self.frame.in_file:
            return
        for line in range(first, last + 1):
            self._joins[line] = self._joins.get(line, True) and clean

    # -- statements

    def block(self, statements: Iterable[js.Node], state: State | None) -> State | None:
        for statement in statements:
            if state is None:
                return None  # what follows a return is never reached
            state = self.statement(statement, state)
        return state

    def statement(self, node: js.Node, state: State) -> State | None:
        self.tick()
        if isinstance(node, js.Block):
            return self.block(node.body, state)
        if isinstance(node, js.Local):
            for name, _dimensions, initial in node.names:
                self.frame.types[name] = node.type_name
                value = self.expression(initial, state) if initial is not None else CLEAN
                if value.kind is None:
                    kind = _kind_of_type(node.type_name)
                    if kind is not None:
                        value = replace(value, kind=kind)
                state[name] = value
            return state
        if isinstance(node, js.ExpressionStatement):
            self.expression(node.expression, state)
            return state
        if isinstance(node, js.If):
            test = self.expression(node.test, state)
            decided = _truth(test)
            if decided is True:
                return self.statement(node.then, state)
            if decided is False:
                return self.statement(node.otherwise, state) if node.otherwise else state
            then = self.statement(node.then, dict(state))
            otherwise = self.statement(node.otherwise, dict(state)) if node.otherwise else state
            return _merge(then, otherwise)
        if isinstance(node, js.While):
            if node.do:
                state = self.statement(node.body, state) or state
            return self.loop(node.test, (), node.body, state)
        if isinstance(node, js.For):
            for part in node.init:
                state = self.statement(part, state) or state
            return self.loop(node.test, node.update, node.body, state)
        if isinstance(node, js.ForEach):
            iterable = self.expression(node.iterable, state)
            element = _element(iterable)
            self.frame.types[node.name] = node.type_name
            entry = dict(state)
            entry[node.name] = element
            return self.loop(None, (), node.body, entry, element=(node.name, element))
        if isinstance(node, js.Try):
            for resource in node.resources:
                state = self.statement(resource, state) or state
            before = dict(state)
            after = self.block(node.body.body, dict(state))
            ends: list[State | None] = [after]
            for catch in node.catches:
                start = _merge(before, after) or dict(before)
                start[catch.name] = OPAQUE
                ends.append(self.block(catch.body.body, start))
            merged = None
            for end in ends:
                merged = _merge(merged, end)
            if node.finally_ is not None:
                base = merged if merged is not None else dict(before)
                finished = self.block(node.finally_.body, base)
                return finished if merged is not None else None
            return merged
        if isinstance(node, js.Switch):
            return self.switch(node, state)
        if isinstance(node, js.Return):
            value = self.expression(node.value, state) if node.value is not None else CLEAN
            self.frame.returns.append(value)
            return None
        if isinstance(node, js.Jump):
            if node.kind == "throw":
                if node.value is not None:
                    self.expression(node.value, state)
                return None
            target = self.frame.breaks if node.kind == "break" else self.frame.continues
            if target:
                target[-1].append(dict(state))
            return None
        return state

    def loop(
        self,
        test: js.Node | None,
        update: tuple[js.Node, ...],
        body: js.Node,
        state: State,
        *,
        element: tuple[str, Value] | None = None,
    ) -> State | None:
        if test is not None:
            decided = _truth(self.expression(test, dict(state)))
            if decided is False:
                return state
        current = dict(state)
        exits: list[State] = []
        for _ in range(LOOP_PASSES):
            self.frame.breaks.append([])
            self.frame.continues.append([])
            try:
                ended = self.statement(body, dict(current))
            finally:
                breaks = self.frame.breaks.pop()
                continues = self.frame.continues.pop()
            exits.extend(breaks)
            following = ended
            for continued in continues:
                following = _merge(following, continued)
            if following is not None:
                for part in update:
                    following = self.statement(part, following) or following
            merged = _merge(current, following)
            if element is not None and merged is not None:
                merged[element[0]] = element[1]
            if merged == current:
                break
            current = merged if merged is not None else current
        result: State | None = current
        for exited in exits:
            result = _merge(result, exited)
        return result

    def switch(self, node: js.Switch, state: State) -> State | None:
        subject = self.expression(node.subject, state)
        chosen = only(subject) if subject.constants is not None else None
        starts: list[int] = []
        if subject.constants is not None and len(subject.constants) == 1:
            for index, case in enumerate(node.cases):
                if case.labels is None:
                    continue
                if any(only(self.expression(label, {})) == chosen for label in case.labels):
                    starts = [index]
                    break
            if not starts:
                starts = [index for index, case in enumerate(node.cases) if case.labels is None]
                if not starts:
                    return state
        else:
            starts = list(range(len(node.cases)))
        merged: State | None = None
        for start in starts:
            self.frame.breaks.append([])
            try:
                current: State | None = dict(state)
                for case in node.cases[start:]:
                    current = self.block(case.body, current)
                    if case.arrow or current is None:
                        break
                breaks = self.frame.breaks.pop()
            except BaseException:
                self.frame.breaks.pop()
                raise
            merged = _merge(merged, current)
            for broken in breaks:
                merged = _merge(merged, broken)
        has_default = any(case.labels is None for case in node.cases)
        if not has_default and len(starts) > 1:
            merged = _merge(merged, state)
        return merged

    # -- expressions

    def expression(self, node: js.Node | None, state: State) -> Value:
        if node is None:
            return CLEAN
        self.tick()
        if isinstance(node, js.Literal):
            return constant(node.value) if isinstance(node.value, Hashable) else CLEAN
        if isinstance(node, js.Name):
            return self.name(node.name, state)
        if isinstance(node, js.Field):
            return self.field_access(node, state)
        if isinstance(node, js.Binary):
            return self.binary(node, state)
        if isinstance(node, js.Unary):
            operand = self.expression(node.operand, state)
            if node.op in ("++", "--"):
                if isinstance(node.operand, js.Name):
                    number = only(operand)
                    if isinstance(number, int) and not isinstance(number, bool):
                        changed = number + (1 if node.op == "++" else -1)
                        state[node.operand.name] = constant(changed)
                        return operand if node.postfix else constant(changed)
                    state[node.operand.name] = derived([operand])
                return derived([operand])
            return _unary(node.op, operand)
        if isinstance(node, js.Conditional):
            test = self.expression(node.test, state)
            decided = _truth(test)
            if decided is True:
                return self.expression(node.then, state)
            if decided is False:
                return self.expression(node.otherwise, state)
            return join(
                self.expression(node.then, dict(state)),
                self.expression(node.otherwise, dict(state)),
            )
        if isinstance(node, js.Assign):
            return self.assign(node, state)
        if isinstance(node, js.Cast):
            value = self.expression(node.operand, state)
            simple = node.type_name.split(".")[-1]
            number = only(value)
            if simple in ("int", "long", "short", "byte") and isinstance(number, (int, float, str)):
                try:
                    return constant(ord(number) if isinstance(number, str) else int(number))
                except (TypeError, ValueError):
                    return derived([value])
            if simple == "char" and isinstance(number, int) and 0 <= number < 0x110000:
                return constant(chr(number))
            return value
        if isinstance(node, js.InstanceOf):
            return derived([self.expression(node.operand, state)])
        if isinstance(node, js.Index):
            target = self.expression(node.target, state)
            index = self.expression(node.index, state)
            position = only(index)
            if (
                target.items is not None
                and isinstance(position, int)
                and 0 <= position < len(target.items)
            ):
                return target.items[position]
            return _element(target)
        if isinstance(node, js.ArrayInit):
            return Value(
                items=tuple(self.expression(item, state) for item in node.items[:MAX_ITEMS])
            )
        if isinstance(node, js.NewArray):
            if node.items is None:
                return CLEAN
            return Value(
                items=tuple(self.expression(item, state) for item in node.items[:MAX_ITEMS])
            )
        if isinstance(node, js.New):
            return self.creation(node, state)
        if isinstance(node, js.Call):
            return self.call(node, state)
        return OPAQUE  # js.Opaque: a lambda, a switch expression

    def name(self, name: str, state: State) -> Value:
        if name in state:
            return state[name]
        if name in ("this", "super"):
            return Value(kind="instance:" + self.frame.owner.name)
        found = self.field_value(self.frame.owner, name)
        if found is not None:
            return found
        return Value(opaque=True, kind="name:" + name)

    def field_value(self, owner: js.ClassDecl | None, name: str) -> Value | None:
        current = owner
        while current is not None:
            declared = current.fields.get(name)
            if declared is not None:
                return self.field_declared(declared)
            current = current.outer
        return None

    def field_declared(self, declared: js.FieldDecl) -> Value:
        kind = _kind_of_type(declared.type_name)
        if kind is not None:
            return Value(opaque=True, kind=kind)
        if declared.is_final and declared.value is not None and declared.is_static:
            value = self.expression(declared.value, {})
            if value.clean:
                return value
        return OPAQUE

    def field_access(self, node: js.Field, state: State) -> Value:
        dotted = _dotted(node)
        if dotted is not None and dotted.split(".")[0] not in state:
            # A static field, perhaps of another class in the project.
            held = self.static_field(dotted)
            if held is not None:
                return held
        target = self.expression(node.target, state)
        if node.name == "length":
            if target.items is not None:
                return constant(len(target.items))
            return derived([target])
        if target.kind and target.kind.startswith("instance:"):
            for declared in self.project.named(target.kind.split(":", 1)[1], self.path):
                found = self.field_value(declared, node.name)
                if found is not None:
                    return found
        return derived([target]) if not target.clean else OPAQUE

    def assign(self, node: js.Assign, state: State) -> Value:
        value = self.expression(node.value, state)
        if node.op != "=":
            current = self.expression(node.target, state)
            value = _arithmetic(node.op[:-1], current, value)
        target = node.target
        if isinstance(target, js.Name):
            if target.name in state or self.field_value(self.frame.owner, target.name) is None:
                state[target.name] = value
        elif isinstance(target, js.Index) and isinstance(target.target, js.Name):
            name = target.target.name
            holder = state.get(name)
            if holder is not None:
                position = only(self.expression(target.index, state))
                if (
                    holder.items is not None
                    and isinstance(position, int)
                    and 0 <= position < len(holder.items)
                ):
                    items = list(holder.items)
                    items[position] = value
                    state[name] = replace(holder, items=tuple(items))
                else:
                    state[name] = join(holder.everything(), value.everything())
        elif isinstance(target, js.Field) and isinstance(target.target, js.Name):
            name = target.target.name
            if name in state and not value.clean:
                state[name] = join(state[name], value.everything())
        return value

    def binary(self, node: js.Binary, state: State) -> Value:
        if node.op == "+":
            parts = _concatenated(node)
            values = [self.expression(part, state) for part in parts]
            is_query = self.check_sql_join(node, parts, values)
            result = values[0]
            for value in values[1:]:
                result = _plus(result, value)
            return replace(result, built=True) if is_query else result
        left = self.expression(node.left, state)
        if node.op in ("&&", "||"):
            decided = _truth(left)
            if node.op == "&&" and decided is False:
                return constant(False)
            if node.op == "||" and decided is True:
                return constant(True)
        right = self.expression(node.right, state)
        return _arithmetic(node.op, left, right)

    def check_sql_join(self, node: js.Binary, parts: list[js.Node], values: list[Value]) -> bool:
        is_sql = any(
            isinstance(part, js.Literal)
            and isinstance(part.value, str)
            and self._sql_text.search('"' + part.value + '"')  # type: ignore[attr-defined]
            for part in parts
        )
        if not is_sql:
            return False
        clean = all(
            value.clean or not value.dangerous_for(SQL) and not value.everything().opaque
            for part, value in zip(parts, values, strict=True)
            if not isinstance(part, js.Literal)
        )
        self.joined_sql(_first_line(node), node.last_line or node.line, clean)
        return True

    def creation(self, node: js.New, state: State) -> Value:
        args = [self.expression(arg, state) for arg in node.args]
        simple = node.type_name.split(".")[-1]
        if simple in FILE_CONSTRUCTORS and any(arg.dangerous_for(PATH) for arg in args):
            self.hit(PATH, node.line, f"new {simple}(...)")
        if simple == "ProcessBuilder" and any(arg.dangerous_for(COMMAND) for arg in args):
            self.hit(COMMAND, node.line, "new ProcessBuilder(...)")
        if simple in COLLECTION_TYPES:
            if args and args[0].items is not None:
                return Value(items=args[0].items, kind="list")
            if args and not (only(args[0]) is not None and isinstance(only(args[0]), int)):
                return replace(derived(args), kind="list")
            return Value(items=(), kind="list")
        if simple in MAP_TYPES:
            if args and not isinstance(only(args[0]), int):
                return replace(derived(args), kind="map")
            return Value(entries=(), kind="map")
        if simple in BUILDER_TYPES:
            if args and isinstance(only(args[0]), int):
                return Value(constants=frozenset({""}), kind="builder")
            text = _concatenate(args) if args else constant("")
            return replace(text, kind="builder")
        if simple == "String":
            if args and args[0].items is not None:
                return derived(args)
            if len(args) == 1 and isinstance(only(args[0]), str):
                return args[0]
            return derived(args)
        kind = _kind_of_type(simple)
        if kind is not None:
            return replace(derived(args), kind=kind) if args else Value(kind=kind)
        classes = self.project.named(simple, self.path)
        if classes and not node.anonymous:
            for declared in classes:
                for constructor in declared.methods:
                    if constructor.is_constructor and _arity_fits(constructor, len(args)):
                        self.follow(constructor, declared, args, receiver=None)
                        break
            return Value(kind="instance:" + simple)
        return derived(args)

    # -- calls

    def call(self, node: js.Call, state: State) -> Value:
        args = [self.expression(arg, state) for arg in node.args]
        if node.target is None:
            return self.unqualified(node, args, state)
        dotted = _dotted(node.target)
        root = dotted.split(".")[0] if dotted else None
        is_static = (
            dotted is not None
            and root not in state
            and self.field_value(self.frame.owner, root or "") is None
        )
        if is_static and dotted is not None:
            held = self.static_field(dotted)
            if held is None:
                return self.static_call(node, dotted, args)
            return self.method_call(node, held, args, state)
        receiver = self.expression(node.target, state)
        result = self.method_call(node, receiver, args, state)
        return result

    def unqualified(self, node: js.Call, args: list[Value], state: State) -> Value:
        if node.name in SANITISERS and args:
            return _sanitised(args[0], SANITISERS[node.name])
        owner: js.ClassDecl | None = self.frame.owner
        while owner is not None:
            candidates = _methods(owner, node.name, len(args), bodies_only=True)
            if candidates:
                receiver = Value(kind="instance:" + owner.name)
                return join_all(
                    self.follow(method, owner, args, receiver=receiver) for method in candidates
                )
            owner = owner.outer
        return _unknown_call(None, args)

    def static_field(self, dotted: str) -> Value | None:
        """The value of `Holder.FIELD`, when Holder is a class of the project."""
        parts = dotted.split(".")
        if len(parts) < 2:
            return None
        for declared in self.project.named(parts[-2], self.path):
            found = declared.fields.get(parts[-1])
            if found is not None and found.is_static:
                return self.field_declared(found)
        return None

    def static_call(self, node: js.Call, dotted: str, args: list[Value]) -> Value:
        name = node.name
        simple = dotted.split(".")[-1]
        if name in SANITISERS and args:
            return _sanitised(args[0], SANITISERS[name])
        if simple == "Runtime" and name == "getRuntime":
            return Value(kind="process")
        if simple in ("Paths", "Path") and name in ("get", "of"):
            if any(arg.dangerous_for(PATH) for arg in args):
                self.hit(PATH, node.line, f"{simple}.{name}(...)")
            return derived(args)
        if simple == "Files" and name in FILE_CALLS:
            # copy(source, target) and move: the target is where a path does harm;
            # the source may be a stream of uploaded content.
            paths = args[1:2] if name in ("copy", "move") else args[:1]
            if any(arg.dangerous_for(PATH) for arg in paths):
                self.hit(PATH, node.line, f"Files.{name}(...)")
            return derived(args)
        if simple in ("Arrays", "List", "Set") and name in ("asList", "of"):
            if len(args) == 1 and args[0].items is not None:
                return Value(items=args[0].items, kind="list")
            return Value(items=tuple(args[:MAX_ITEMS]), kind="list")
        if simple == "String" and name == "valueOf" and len(args) == 1:
            known = only(args[0])
            if isinstance(known, (str, int, bool)) and known is not None:
                text = ("true" if known else "false") if isinstance(known, bool) else str(known)
                return constant(text)
            return derived(args)
        if simple == "String" and name == "format":
            return derived(args)
        if simple in ("Integer", "Long") and name in ("parseInt", "valueOf", "parseLong"):
            known = only(args[0]) if args else None
            if isinstance(known, str):
                try:
                    return constant(int(known))
                except ValueError:
                    return CLEAN
            # A number: nothing to inject, wherever it came from.
            return CLEAN
        candidates: list[tuple[js.ClassDecl, js.Method]] = []
        for declared in self.project.named(simple, self.path):
            for method in _methods(declared, name, len(args), bodies_only=True):
                candidates.append((declared, method))
        if candidates and len(candidates) <= MAX_CANDIDATES:
            return join_all(
                self.follow(method, owner, args, receiver=None) for owner, method in candidates
            )
        if (
            name in STRONG_SQL_CALLS
            and args
            and args[0].dangerous_for(SQL)
            and not args[0].everything().built
        ):
            self.hit(SQL, node.line, f"{simple}.{name}(...)")
        return _unknown_call(None, args, static=True)

    def method_call(self, node: js.Call, receiver: Value, args: list[Value], state: State) -> Value:
        name = node.name
        kind = receiver.kind
        line = node.line
        if name in SANITISERS and args:
            return _sanitised(args[0], SANITISERS[name])
        # The request, and what is read from it.
        if kind == "request":
            if name in REQUEST_SOURCES:
                return TAINTED
            if name == "getSession":
                return Value(kind="session")
            if name in REQUEST_CLEAN:
                return CLEAN
            return OPAQUE
        if kind == "response":
            if name in ("getWriter", "getOutputStream"):
                return Value(kind="writer")
            return CLEAN
        if kind == "writer" and name in WRITER_CALLS:
            if any(arg.dangerous_for(HTML) for arg in args):
                self.hit(HTML, line, f"response writer .{name}(...)")
            return Value(kind="writer")
        if kind == "session" and name in ("setAttribute", "putValue"):
            if any(arg.dangerous_for(TRUST) for arg in args[:2]):
                self.hit(TRUST, line, f"session.{name}(...)")
            return CLEAN
        if kind == "process" and name in ("exec", "command"):
            if any(arg.dangerous_for(COMMAND) for arg in args):
                self.hit(COMMAND, line, f".{name}(...)")
            return Value(opaque=True, kind="process" if name == "command" else None)
        if kind == "ldap" and name == "search":
            if any(arg.dangerous_for(LDAP) for arg in args[:2]):
                self.hit(LDAP, line, "directory search")
            return OPAQUE
        if kind == "xpath" and name in ("compile", "evaluate", "evaluateExpression"):
            if args and args[0].dangerous_for(XPATH):
                self.hit(XPATH, line, f"XPath .{name}(...)")
            return OPAQUE
        if name == "newXPath":
            return Value(kind="xpath")
        if self.is_sql_call(node, receiver):
            checked = args if name == "batchUpdate" else args[:1]
            if any(arg.dangerous_for(SQL) and not arg.everything().built for arg in checked):
                self.hit(SQL, line, f".{name}(...)")
            if name in ("prepareStatement", "prepareCall", "createStatement"):
                return Value(opaque=True, kind="sql")
            return OPAQUE
        if name in ("createStatement", "getConnection"):
            return Value(opaque=True, kind="sql")
        # A method of a class in the project: read it.
        followed = self.project_method(node, receiver, args)
        if followed is not None:
            self.store_into_receiver(node, args, state)
            return followed
        # A library object's properties: what `setPath(x)` put in, `getPath()` gives back.
        bean = self.property(node, receiver, args, state)
        if bean is not None:
            return bean
        # Collections, builders and strings, with what can be known exactly.
        exact = self.known_method(node, receiver, args, state)
        if exact is not None:
            return exact
        self.store_into_receiver(node, args, state)
        return _unknown_call(receiver, args)

    def property(
        self, node: js.Call, receiver: Value, args: list[Value], state: State
    ) -> Value | None:
        name = node.name
        if receiver.items is not None or receiver.kind in ("map", "builder", "list"):
            return None
        if receiver.entries is not None and not all(
            isinstance(key, tuple) and key[:1] == ("property",) for key, _ in receiver.entries
        ):
            return None
        setter = _property_name(name, "set")
        if setter is not None and len(args) == 1:
            if not isinstance(node.target, js.Name) or node.target.name not in state:
                return None
            properties = dict(receiver.entries or ())
            properties[("property", setter)] = args[0]
            state[node.target.name] = replace(receiver, entries=tuple(properties.items()))
            return CLEAN
        getter = _property_name(name, "get") or _property_name(name, "is")
        if getter is not None and not args and receiver.entries is not None:
            found = dict(receiver.entries).get(("property", getter))
            if found is not None:
                return found
            # Not a property that was set: what the object itself was made from.
            return Value(receiver.tainted, receiver.safe, receiver.opaque, built=receiver.built)
        return None

    def is_sql_call(self, node: js.Call, receiver: Value) -> bool:
        if node.name in STRONG_SQL_CALLS:
            return True
        if node.name not in WEAK_SQL_CALLS:
            return False
        if receiver.kind == "sql":
            return True
        dotted = _dotted(node.target) if node.target is not None else None
        return bool(dotted and "jdbc" in dotted.lower())

    def store_into_receiver(self, node: js.Call, args: list[Value], state: State) -> None:
        """A call that may keep its arguments in the object it is called on."""
        if not isinstance(node.target, js.Name) or node.target.name not in state:
            return
        if node.name in QUERYING or all(arg.clean for arg in args):
            return
        holder = state[node.target.name]
        state[node.target.name] = replace(
            join(holder.everything(), derived(args)), kind=holder.kind
        )

    def project_method(self, node: js.Call, receiver: Value, args: list[Value]) -> Value | None:
        candidates: list[tuple[js.ClassDecl, js.Method]] = []
        type_name = None
        if receiver.kind and receiver.kind.startswith("instance:"):
            type_name = receiver.kind.split(":", 1)[1]
        elif isinstance(node.target, js.Name):
            type_name = self.frame.types.get(node.target.name)
            if type_name is None:
                declared = self.field_declaration(node.target.name)
                type_name = declared.type_name if declared else None
        if type_name is None:
            return None
        for method in self.project.implementations(type_name, node.name, len(args), self.path):
            candidates.append((method.owner, method))
        if not candidates:
            return None
        return join_all(
            self.follow(method, owner, args, receiver=receiver) for owner, method in candidates
        )

    def field_declaration(self, name: str) -> js.FieldDecl | None:
        current: js.ClassDecl | None = self.frame.owner
        while current is not None:
            if name in current.fields:
                return current.fields[name]
            current = current.outer
        return None

    def follow(
        self, method: js.Method, owner: js.ClassDecl, args: list[Value], *, receiver: Value | None
    ) -> Value:
        """What a method of the project returns, given these arguments."""
        if method.body is None or not method.readable:
            return _unknown_call(receiver, args)
        key = (id(method), tuple(args))
        if key in self.summaries:
            return self.summaries[key]
        if id(method) in self.active or len(self.frames) > MAX_CALL_DEPTH:
            return _unknown_call(receiver, args)
        state: State = {}
        types: dict[str, str] = {}
        for index, parameter in enumerate(method.parameters):
            types[parameter.name] = parameter.type_name
            if (
                parameter.type_name.endswith("[]")
                and index == len(method.parameters) - 1
                and (len(args) != len(method.parameters) or args[index].items is None)
            ):
                state[parameter.name] = (
                    Value(items=tuple(args[index:])) if len(args) >= index else CLEAN
                )
            elif index < len(args):
                value = args[index]
                if value.kind is None:
                    kind = _kind_of_type(parameter.type_name)
                    value = replace(value, kind=kind) if kind else value
                state[parameter.name] = value
        in_file = self.project.class_file.get(id(owner)) == self.path
        self.active.add(id(method))
        try:
            result = self.run(method, owner, state, types, in_file=in_file and self.frame.in_file)
        finally:
            self.active.discard(id(method))
        self.summaries[key] = result
        return result

    def known_method(
        self, node: js.Call, receiver: Value, args: list[Value], state: State
    ) -> Value | None:
        name = node.name
        target = node.target
        holder = target.name if isinstance(target, js.Name) and target.name in state else None
        # Lists.
        if receiver.items is not None and receiver.entries is None:
            items = list(receiver.items)
            position = only(args[0]) if args else None
            if name == "add" and len(args) == 1 and len(items) < MAX_ITEMS:
                items.append(args[0])
                self._set(state, holder, replace(receiver, items=tuple(items)))
                return constant(True)
            if (
                name == "add"
                and len(args) == 2
                and isinstance(position, int)
                and 0 <= position <= len(items)
            ):
                items.insert(position, args[1])
                self._set(state, holder, replace(receiver, items=tuple(items)))
                return CLEAN
            if (
                name == "remove"
                and len(args) == 1
                and isinstance(position, int)
                and not isinstance(position, bool)
            ):
                if 0 <= position < len(items):
                    removed = items.pop(position)
                    self._set(state, holder, replace(receiver, items=tuple(items)))
                    return removed
                return CLEAN
            if name == "get" and len(args) == 1:
                if isinstance(position, int) and 0 <= position < len(items):
                    return items[position]
                return _element(receiver)
            if (
                name == "set"
                and len(args) == 2
                and isinstance(position, int)
                and 0 <= position < len(items)
            ):
                previous = items[position]
                items[position] = args[1]
                self._set(state, holder, replace(receiver, items=tuple(items)))
                return previous
            if name == "size":
                return constant(len(items))
            if name == "isEmpty":
                return constant(not items)
            if name in ("clear", "removeAll"):
                self._set(state, holder, replace(receiver, items=()))
                return CLEAN
            if name in ("iterator", "listIterator", "stream", "toArray", "subList", "elements"):
                return replace(receiver, kind=None) if name == "toArray" else derived([receiver])
            if name in ("addAll",):
                self._set(
                    state, holder, replace(join(receiver.everything(), derived(args)), kind="list")
                )
                return CLEAN
        # Maps.
        if receiver.entries is not None:
            entries = dict(receiver.entries)
            key = only(args[0]) if args else None
            has_key = bool(args) and args[0].constants is not None and len(args[0].constants) == 1
            if name in ("put", "putIfAbsent") and len(args) == 2 and has_key:
                previous = entries.get(key, CLEAN)
                if not (name == "putIfAbsent" and key in entries):
                    entries[key] = args[1]
                self._set(state, holder, replace(receiver, entries=tuple(entries.items())))
                return previous
            if name in ("get", "remove") and len(args) == 1 and has_key:
                found = entries.get(key, Value(constants=frozenset({None})))
                if name == "remove":
                    entries.pop(key, None)
                    self._set(state, holder, replace(receiver, entries=tuple(entries.items())))
                return found
            if name == "getOrDefault" and len(args) == 2 and has_key:
                return entries.get(key, args[1])
            if name in ("containsKey",) and has_key:
                return constant(key in entries)
            if name == "size":
                return constant(len(entries))
            if name in ("get", "getOrDefault", "values", "keySet", "entrySet", "remove"):
                return derived([receiver] + args[1:])
            if name in ("put", "putAll", "putIfAbsent", "merge", "compute"):
                self._set(
                    state, holder, replace(join(receiver.everything(), derived(args)), kind="map")
                )
                return CLEAN
        # String builders: they change in place, and return themselves.
        if receiver.kind == "builder":
            if name in ("append", "insert"):
                added = args[-1] if name == "append" else (args[1] if len(args) > 1 else CLEAN)
                if name == "append" and len(args) == 1:
                    joined = _concatenate([receiver, added])
                else:
                    joined = derived([receiver, added])
                joined = replace(joined, kind="builder")
                self._set(state, holder, joined)
                return joined
            if name in ("replace", "reverse", "deleteCharAt", "delete", "setCharAt", "setLength"):
                changed = replace(
                    derived([receiver] + (args[2:3] if name == "replace" else [])), kind="builder"
                )
                self._set(state, holder, changed)
                return changed
            if name == "toString":
                return replace(receiver, kind=None)
            if name == "length":
                text = only(receiver)
                return constant(len(text)) if isinstance(text, str) else CLEAN
        # Strings.
        text = only(receiver)
        if isinstance(text, str) and receiver.kind is None:
            exact = _string_method(text, name, args)
            if exact is not None:
                return exact
        if name in ("split",):
            return derived([receiver])
        if name in (
            "hasMoreElements",
            "hasNext",
            "equals",
            "equalsIgnoreCase",
            "contains",
            "isEmpty",
            "startsWith",
            "endsWith",
            "length",
            "size",
            "indexOf",
            "lastIndexOf",
            "compareTo",
            "hashCode",
            "matches",
        ):
            return CLEAN  # a boolean or a number
        if name in (
            "nextElement",
            "next",
            "getValue",
            "getName",
            "toString",
            "trim",
            "strip",
            "toLowerCase",
            "toUpperCase",
            "intern",
            "getBytes",
            "toCharArray",
            "substring",
            "concat",
            "replace",
            "replaceAll",
            "replaceFirst",
            "charAt",
            "chars",
            "get",
            "nextToken",
            "getKey",
            "readLine",
            "clone",
            "decode",
            "encode",
        ):
            return derived([receiver] + args)
        return None

    def _set(self, state: State, holder: str | None, value: Value) -> None:
        if holder is not None:
            state[holder] = value


# --- small pieces of arithmetic -------------------------------------------------

_COMPARISONS = {
    "==": operator.eq,
    "!=": operator.ne,
    "<": operator.lt,
    ">": operator.gt,
    "<=": operator.le,
    ">=": operator.ge,
}
_NUMERIC = {
    "+": operator.add,
    "-": operator.sub,
    "*": operator.mul,
    "%": operator.mod,
    "&": operator.and_,
    "|": operator.or_,
    "^": operator.xor,
}


def _property_name(method: str, prefix: str) -> str | None:
    """`setPath` -> "path"; None if the method is not named like an accessor."""
    rest = method[len(prefix) :]
    if method.startswith(prefix) and rest[:1].isupper():
        return rest[:1].lower() + rest[1:]
    return None


def _truth(value: Value) -> bool | None:
    known = only(value)
    return known if isinstance(known, bool) else None


def _number(value: object) -> int | float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str) and len(value) == 1:
        return ord(value)  # a char
    return None


def _arithmetic(op: str, left: Value, right: Value) -> Value:
    a = only(left)
    b = only(right)
    if op in ("&&", "||"):
        if isinstance(a, bool) and isinstance(b, bool):
            return constant(a and b if op == "&&" else a or b)
        return derived([left, right])
    both_known = (
        left.constants is not None
        and right.constants is not None
        and len(left.constants) == 1
        and len(right.constants) == 1
    )
    # `==` on two strings compares references, which the source does not decide;
    # on numbers, characters, booleans and null it compares values.
    comparable = not (isinstance(a, str) and isinstance(b, str) and len(a) != 1)
    if op in ("==", "!=") and both_known and comparable and (a is not None or b is not None):
        same = a == b
        return constant(same if op == "==" else not same)
    x, y = _number(a), _number(b)
    if x is not None and y is not None:
        if op in _COMPARISONS:
            return constant(_COMPARISONS[op](x, y))
        try:
            if op in _NUMERIC and isinstance(x, int) and isinstance(y, int):
                result = _NUMERIC[op](x, y)
                if abs(result) < 2**63:
                    return constant(result)
            if op == "/" and isinstance(x, int) and isinstance(y, int) and y != 0:
                return constant(int(x / y))
        except (ArithmeticError, ValueError):
            pass
    if isinstance(a, bool) and isinstance(b, bool) and op in ("&", "|", "^"):
        return constant(_NUMERIC[op](a, b))
    if op == "+":
        return _plus(left, right)
    return derived([left, right])


def _plus(left: Value, right: Value) -> Value:
    """Java's `+`: numbers add, and anything joined to a string is text."""
    a, b = only(left), only(right)
    numbers = (int, float)
    if (
        isinstance(a, numbers)
        and isinstance(b, numbers)
        and not isinstance(a, bool)
        and not isinstance(b, bool)
    ):
        total = a + b
        return constant(total) if abs(total) < 2**63 else CLEAN
    return _concatenate([left, right])


def _unary(op: str, operand: Value) -> Value:
    known = only(operand)
    if op == "!" and isinstance(known, bool):
        return constant(not known)
    number = _number(known)
    if op == "-" and number is not None:
        return constant(-number)
    if op == "~" and isinstance(number, int):
        return constant(~number)
    return derived([operand])


def _text(value: Hashable) -> str | None:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (str, int, float)):
        return str(value)
    return None


def _concatenate(values: list[Value]) -> Value:
    texts: list[str] = []
    for value in values:
        known = only(value)
        text = _text(known) if value.constants is not None and len(value.constants) == 1 else None
        if text is None:
            return derived(values)
        texts.append(text)
    joined = "".join(texts)
    return constant(joined) if len(joined) <= MAX_TEXT else derived(values)


def _string_method(text: str, name: str, args: list[Value]) -> Value | None:
    known = [only(arg) for arg in args]
    if not all(arg.constants is not None and len(arg.constants) == 1 for arg in args):
        return None
    try:
        if name == "charAt" and len(known) == 1 and isinstance(known[0], int):
            return constant(text[known[0]]) if 0 <= known[0] < len(text) else CLEAN
        if name == "length" and not args:
            return constant(len(text))
        if (
            name in ("toString", "intern", "trim", "strip", "toLowerCase", "toUpperCase")
            and not args
        ):
            result = {
                "trim": text.strip(),
                "strip": text.strip(),
                "toLowerCase": text.lower(),
                "toUpperCase": text.upper(),
            }.get(name, text)
            return constant(result)
        if name == "substring" and all(isinstance(k, int) for k in known) and 1 <= len(known) <= 2:
            end = known[1] if len(known) == 2 else len(text)
            if 0 <= known[0] <= end <= len(text):  # type: ignore[operator]
                return constant(text[known[0] : end])  # type: ignore[misc]
            return CLEAN
        if name == "equals" and len(known) == 1:
            return constant(text == known[0])
        if name == "concat" and len(known) == 1 and isinstance(known[0], str):
            return constant(text + known[0])
        if name == "isEmpty" and not args:
            return constant(not text)
    except (TypeError, IndexError):
        return None
    return None


def _element(value: Value) -> Value:
    """Any one element of a list, array, map or iterator."""
    if value.items is not None:
        return join_all(value.items) if value.items else CLEAN
    whole = value.everything()
    return Value(whole.tainted, whole.safe, whole.opaque, built=whole.built)


def _sanitised(value: Value, kinds: frozenset[str]) -> Value:
    whole = value.everything()
    return Value(whole.tainted, whole.safe | kinds, whole.opaque, built=whole.built)


def _unknown_call(receiver: Value | None, args: list[Value], *, static: bool = False) -> Value:
    """A call nothing is known about: what it returns comes from what it was given.

    That is the usual assumption of taint tracking, and it is how request data
    is carried through a library call. A call given only literals, made on
    nothing or on something built from literals, returns something not from the
    request; whether it is *known* to be harmless is a separate question, and
    the answer is no unless it was given something and all of it was clean.
    """
    inputs = list(args) + ([receiver] if receiver is not None else [])
    result = derived(inputs)
    if not inputs or (static and not args):
        return OPAQUE
    if receiver is not None and receiver.kind and receiver.kind.startswith("name:"):
        return replace(result, opaque=True)
    return result


def _merge(first: State | None, second: State | None) -> State | None:
    if first is None:
        return dict(second) if second is not None else None
    if second is None:
        return dict(first)
    merged: State = {}
    for name in first.keys() | second.keys():
        if name in first and name in second:
            merged[name] = join(first[name], second[name])
        else:
            # Declared on one path only: it is out of scope after the merge,
            # or it was assigned on one path, which is "could be either".
            merged[name] = first.get(name) or second.get(name)  # type: ignore[assignment]
    return merged


def analyse(
    unit: js.CompilationUnit,
    path: str,
    project: Project,
    sql_text: object,
    *,
    only_lines: list[int] | None = None,
) -> FileReport:
    """Walk the methods of one file: all of them, or those holding one of ``only_lines``."""
    return Walker(project, path, sql_text).file(unit, only_lines)


def iter_lines(report: FileReport) -> Iterator[int]:  # pragma: no cover - debugging aid
    for hit in report.hits:
        yield hit.line
