"""Following a value through a Python function.

The rules in :mod:`app.analysis.python_ast` recognise a dangerous call by its
shape. That is enough to say "this is ``os.system``" and not enough to say
"and what it runs came from the request". Measured against a benchmark with
known answers, shape alone reported the safe test cases as often as the
vulnerable ones. This module is the missing half: for every call, it works out
*what each argument can be*.

It does so by reading the function the way the interpreter would run it —
statement by statement, in order — but with descriptions of values instead of
values:

* **where a value came from** — the HTTP request, a predictable random
  generator, or something this module does not understand;
* **what it is, when that can be known** — ``'safe'``, ``126``, a list whose
  second element is the request parameter;
* **what has been done to it** — passed through ``html.escape``, or checked by
  an ``if`` that leaves the function when the check fails.

**Nothing is executed.** No function of the analysed code is called, nothing
is imported, and the only operations ever performed are on literals that were
written in the source (``7 * 18``, ``'ABC'[1]``), under a size limit.

Three properties the rest of the analyser relies on:

1. *It is approximate in one direction.* When two paths meet, a value is
   everything it could be on either. When something is not understood, the
   result is "unknown", never "safe". A rule can then choose: the rules for
   calls that are dangerous by nature report unknown values as before, and
   only stay silent for values **shown** to be built from literals.
2. *It is bounded.* A loop body is read twice, a call into another function of
   the same file is followed three deep, and the whole file has a budget of
   steps. Past any limit the answer is "unknown" for everything, which is
   exactly what the analyser knew before this module existed.
3. *It stays inside one file.* A helper imported from another module is a call
   whose result depends on its arguments and nothing more is assumed.

What is deliberately not modelled is listed in ``docs/security/analysis.md``.
"""

import ast
import operator
from collections.abc import Callable, Hashable, Iterable
from dataclasses import dataclass, field, replace

from app.analysis.python_models import (
    ABSORBING_METHODS,
    FILE_CALLS,
    HOST_ATTRIBUTES,
    HTML_BY_DEFAULT,
    HTML_ESCAPE_NAMES,
    HTML_SAFE_CALLS,
    LOOKUP_CALLS,
    LOOKUP_METHODS,
    MUTATING_METHODS,
    NOT_TEXT,
    NUMERIC_FUNCTIONS,
    PATH_CONSTRUCTORS,
    PURE_CALLS,
    PURE_FUNCTIONS,
    PURE_METHODS,
    QUOTE_KINDS,
    QUOTES,
    RANDOM_FUNCTIONS,
    REDIRECT_VALIDATORS,
    REQUEST_NOT_INPUT,
    REQUEST_OBJECTS,
    REQUEST_PATHS,
    REQUEST_SAME_SITE,
    RESPONSE_FUNCTIONS,
    ROUTE_DECORATORS,
    SANITISERS,
    SITE_ADDRESS_CALLS,
    SUBPROCESS_CALLS,
    URL_PARSERS,
    WEB_FRAMEWORKS,
    WHOLE_VALUE_CHECKS,
    XPATH_CALLS,
)
from app.analysis.python_values import (
    ALL_KINDS,
    BINARY,
    CLEAN,
    CODE,
    COMMAND,
    COMPARE,
    DATA,
    FLAG_DICT,
    FLAG_ENTITIES,
    FLAG_PATH,
    FLAG_REQUEST,
    FLAG_SET,
    HTML,
    INPUT,
    LDAP,
    LOOP_PASSES,
    MAX_CALL_DEPTH,
    MAX_CONSTANTS,
    MAX_STEPS,
    NOTHING,
    OPAQUE,
    PATH,
    PLAIN,
    RANDOM,
    REDIRECT,
    SQL,
    TAINTED,
    TRUST,
    UNKNOWN,
    XPATH,
    Taint,
    Value,
    capped,
    classify,
    constant,
    fold,
    guarded,
    join,
    made_safe,
    method_of,
    predictable,
)

# --- what was seen at each place a rule cares about ---------------------------


@dataclass
class CallSeen:
    node: ast.Call
    name: str | None  # as written: "subprocess.run", "cur.execute"
    qualified: str | None  # through the imports: "xml.dom.minidom.parseString"
    receiver: Value | None
    arguments: tuple[Value, ...]
    keywords: dict[str, Value]
    # The function it was seen in, and whether that function answers a request.
    function: ast.AST | None
    route: bool

    def argument(self, index: int, keyword: str | None = None) -> Value | None:
        if keyword is not None and keyword in self.keywords:
            return self.keywords[keyword]
        if index < len(self.arguments):
            return self.arguments[index]
        return None


@dataclass
class StoreSeen:
    """``target[key] = value`` or ``target.attribute = value``."""

    node: ast.AST
    target: str | None  # dotted name of what was stored into, as written
    qualified: str | None
    key: Value | None
    key_text: str
    value: Value


@dataclass
class ReturnSeen:
    node: ast.Return
    value: Value
    function: ast.AST | None
    route: bool


@dataclass
class Flow:
    """Everything the walk observed, for the rules to read."""

    calls: dict[int, CallSeen] = field(default_factory=dict)
    stores: list[StoreSeen] = field(default_factory=list)
    returns: list[ReturnSeen] = field(default_factory=list)
    # Calls inside code the walk decided not to enter: the branch of an `if`
    # whose test is a literal `False`, statements after a `return`.
    skipped: set[int] = field(default_factory=set)
    # Whether a string returned from a route in this file is an HTML page.
    html_routes: bool = False
    # False when the walk gave up. Nothing was recorded then, so every question
    # about a call is answered "not seen", which the rules read as unknown.
    complete: bool = True

    def call(self, node: ast.Call) -> CallSeen | None:
        return self.calls.get(id(node))

    def unreachable(self, node: ast.Call) -> bool:
        """Whether a call can never run.

        Only true when the walk *chose* not to go there and never arrived by
        any other route. A call it simply did not look at — inside a lambda,
        a default argument — is not unreachable, it is unknown.
        """
        return id(node) in self.skipped and id(node) not in self.calls


EMPTY_FLOW = Flow(complete=False)


class _GaveUp(Exception):
    """The file is larger or stranger than the budget allows."""


@dataclass
class _State:
    names: dict[str, Value]
    # Names that may be the same object, after `b = a` on some path: each name
    # -> the others. A list changed through one may have changed for the rest.
    aliases: dict[str, frozenset[str]] = field(default_factory=dict)
    # `url = urlparse(target)`: "url" -> "target". A check on the parsed
    # address says something about the text it was parsed from.
    parsed: dict[str, str] = field(default_factory=dict)

    def copy(self) -> "_State":
        return _State(dict(self.names), dict(self.aliases), dict(self.parsed))

    def bind(self, name: str, value: Value) -> None:
        """``name = <something new>``: it stops being another name for anything."""
        self.names[name] = value
        self.forget(name)

    def forget(self, name: str) -> None:
        for other in self.aliases.pop(name, frozenset()):
            rest = self.aliases.get(other, frozenset()) - {name}
            if rest:
                self.aliases[other] = rest
            else:
                self.aliases.pop(other, None)
        for target in [key for key, source in self.parsed.items() if name in (key, source)]:
            del self.parsed[target]

    def link(self, name: str, other: str) -> None:
        """``name = other``, where the thing named may be changed in place."""
        group = {name, other} | self.aliases.get(other, frozenset())
        for member in group:
            self.aliases[member] = self.aliases.get(member, frozenset()) | (group - {member})

    def change(self, name: str, value: Value) -> None:
        """The object called ``name`` changed; under its other names it may have.

        "May": two names are linked when *some* path made them the same object,
        so the others become what they were or what this one now is.
        """
        self.names[name] = value
        for other in self.aliases.get(name, frozenset()):
            if other in self.names:
                self.names[other] = join(self.names[other], value)


@dataclass
class _Loop:
    breaks: list[_State] = field(default_factory=list)
    continues: list[_State] = field(default_factory=list)


@dataclass
class _Frame:
    function: ast.AST | None = None
    route: bool = False
    # The path of a route whose rule has no variable part: "/status".
    fixed_path: str | None = None
    in_class: bool = False
    depth: int = 0
    returned: list[Value] = field(default_factory=list)
    loops: list[_Loop] = field(default_factory=list)


def _merge(first: _State | None, second: _State | None) -> _State | None:
    """The state after two paths meet. ``None`` is a path that never arrives."""
    if first is None:
        return second
    if second is None:
        return first
    names = dict(first.names)
    for name, value in second.names.items():
        names[name] = join(names[name], value) if name in names else value
    # Two names that are one object on either path may be one object after it.
    aliases = dict(first.aliases)
    for name, others in second.aliases.items():
        aliases[name] = aliases.get(name, frozenset()) | others
    # What a name was parsed from is only relied on when both paths agree.
    parsed = {k: v for k, v in first.parsed.items() if second.parsed.get(k) == v}
    return _State(names, aliases, parsed)


def analyse(tree: ast.Module) -> Flow:
    """Walk a parsed file. Never raises: a walk that fails is a walk that knows nothing."""
    try:
        walker = _Walker(tree)
        walker.block(tree.body, _State({}), _Frame())
    except Exception:  # noqa: BLE001 - see below
        # Not only the two expected ways of giving up. This walk reads code
        # nobody here has seen, and a mistake in it must cost the extra
        # knowledge, not the scan: the rules then behave as if this module
        # did not exist, which is how they behaved before it did.
        return EMPTY_FLOW
    return walker.flow


class _Walker:
    def __init__(self, tree: ast.Module) -> None:
        self.flow = Flow()
        # Names given a value in more than one place in the file. A function
        # sees the *latest* value of an outer name when it runs, not the one at
        # the point it was defined, so only names bound exactly once are taken
        # into a function as known.
        # Whether the file is part of a web application at all. A parameter
        # called `request` is the HTTP request there, and a pytest fixture or
        # an outgoing API call everywhere else.
        self.rebound, self.shared, self.mutated, frameworks = _survey(tree)
        self.web = bool(frameworks)
        self.flow.html_routes = bool(frameworks & HTML_BY_DEFAULT)
        # What following a function gave, by what it was given.
        self.followed: dict[Hashable, Value] = {}
        self.imports: dict[str, str] = {}
        # Functions of this file, by name, with the names visible where they
        # were defined.
        self.functions: dict[str, tuple[ast.FunctionDef | ast.AsyncFunctionDef, _State]] = {}
        # A function can be called above the line it is defined on. Those of the
        # module are known from the start, with no outer names; the entry is
        # replaced when the definition itself is reached.
        for node in tree.body:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                self.functions[node.name] = (node, _State({}))
        self.steps = 0

    def _tick(self) -> None:
        self.steps += 1
        if self.steps > MAX_STEPS:
            raise _GaveUp

    # -- statements -----------------------------------------------------------

    def block(self, body: list[ast.stmt], state: _State, frame: _Frame) -> _State | None:
        """Run statements in order. ``None`` when control does not reach the end."""
        current: _State | None = state
        for position, statement in enumerate(body):
            if current is None:
                self.skip(body[position:])  # after a return: never runs
                break
            current = self.statement(statement, current, frame)
        return current

    def skip(self, nodes: Iterable[ast.AST]) -> None:
        """Remember the calls inside code that is not going to be walked."""
        for node in nodes:
            for inner in ast.walk(node):
                if isinstance(inner, ast.Call):
                    self.flow.skipped.add(id(inner))

    def statement(self, node: ast.stmt, state: _State, frame: _Frame) -> _State | None:  # noqa: PLR0911, PLR0912 - one branch per kind of statement
        self._tick()
        if isinstance(node, ast.Assign):
            value = self.evaluate(node.value, state, frame)
            for target in node.targets:
                self.assign(target, value, state, frame)
                if isinstance(target, ast.Name):
                    self.remember_origin(target.id, node.value, value, state)
            return state
        if isinstance(node, ast.AnnAssign):
            if node.value is not None:
                self.assign(node.target, self.evaluate(node.value, state, frame), state, frame)
            return state
        if isinstance(node, ast.AugAssign):
            current = self.evaluate(_as_load(node.target), state, frame)
            addition = self.evaluate(node.value, state, frame)
            self.assign(node.target, self.binary(node.op, current, addition), state, frame)
            return state
        if isinstance(node, ast.Expr):
            self.evaluate(node.value, state, frame)
            return state
        if isinstance(node, ast.If):
            return self.branch(node, state, frame)
        if isinstance(node, ast.Match):
            return self.match(node, state, frame)
        if isinstance(node, ast.For | ast.AsyncFor):
            iterated = self.evaluate(node.iter, state, frame)
            element = _element_of(iterated)
            return self.loop(
                node, state, frame, lambda inner: self.assign(node.target, element, inner, frame)
            )
        if isinstance(node, ast.While):
            self.evaluate(node.test, state, frame)
            return self.loop(node, state, frame, lambda inner: None)
        if isinstance(node, ast.Try) or node.__class__.__name__ == "TryStar":
            return self.attempt(node, state, frame)  # type: ignore[arg-type]
        if isinstance(node, ast.With | ast.AsyncWith):
            for item in node.items:
                entered = self.evaluate(item.context_expr, state, frame)
                if item.optional_vars is not None:
                    self.assign(item.optional_vars, entered, state, frame)
            return self.block(node.body, state, frame)
        if isinstance(node, ast.Return):
            value = NOTHING if node.value is None else self.evaluate(node.value, state, frame)
            frame.returned.append(value)
            self.flow.returns.append(ReturnSeen(node, value, frame.function, frame.route))
            return None
        if isinstance(node, ast.Raise):
            if node.exc is not None:
                self.evaluate(node.exc, state, frame)
            return None
        if isinstance(node, ast.Break):
            if frame.loops:
                frame.loops[-1].breaks.append(state.copy())
            return None
        if isinstance(node, ast.Continue):
            if frame.loops:
                frame.loops[-1].continues.append(state.copy())
            return None
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            self.define(node, state, method=frame.in_class)
            return state
        if isinstance(node, ast.ClassDef):
            # Methods are read as functions; the class body's own names stay in it.
            self.block(node.body, state.copy(), _Frame(depth=frame.depth, in_class=True))
            return state
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                self.imports[local] = alias.name if alias.asname else local
                state.names.pop(local, None)
            return state
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                local = alias.asname or alias.name
                self.imports[local] = f"{module}.{alias.name}".strip(".")
                state.names.pop(local, None)
            return state
        if isinstance(node, ast.Delete):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    state.names.pop(target.id, None)
                    state.forget(target.id)
            return state
        if isinstance(node, ast.Assert):
            self.evaluate(node.test, state, frame)
            return state
        return state  # pass, global, nonlocal

    def branch(self, node: ast.If, state: _State, frame: _Frame) -> _State | None:
        test = self.evaluate(node.test, state, frame)
        decided = _truth(test)

        taken: _State | None = None
        if decided is not False:
            inside = state.copy()
            self.learn(node.test, True, inside, frame)
            taken = self.block(node.body, inside, frame)
        else:
            self.skip(node.body)
        skipped: _State | None = None
        if decided is not True:
            otherwise = state.copy()
            self.learn(node.test, False, otherwise, frame)
            skipped = self.block(node.orelse, otherwise, frame)
        else:
            self.skip(node.orelse)
        return _merge(taken, skipped)

    def match(self, node: ast.Match, state: _State, frame: _Frame) -> _State | None:
        subject = self.evaluate(node.subject, state, frame)
        known = (
            next(iter(subject.constants))
            if subject.constants is not None and len(subject.constants) == 1
            else _NOT_KNOWN
        )
        result: _State | None = None
        for position, case in enumerate(node.cases):
            verdict = None if known is _NOT_KNOWN else _pattern_matches(case.pattern, known)
            if case.guard is not None:
                verdict = None if verdict is True else verdict
            if verdict is False:
                self.skip(case.body)
                continue
            result = _merge(result, self.block(case.body, state.copy(), frame))
            if verdict is True:
                # This case is certain to be the one; no later one runs.
                for later in node.cases[position + 1 :]:
                    self.skip(later.body)
                return result
        # No case was certain to match, so "none of them" is also a way through.
        return _merge(result, state)

    def loop(
        self,
        node: ast.For | ast.AsyncFor | ast.While,
        state: _State,
        frame: _Frame,
        bind: Callable[[_State], None],
    ) -> _State | None:
        exits = _Loop()
        frame.loops.append(exits)
        reached: _State = state.copy()  # zero iterations is always possible
        settled = False
        for _ in range(LOOP_PASSES):
            reached, settled = self._pass(node, reached, frame, exits, bind)
            if settled:
                break
        if not settled:
            # Still changing after that many passes. Rather than stop early and
            # miss what a later pass would have carried round, every name the
            # loop assigns is treated as any of the others, and the body is
            # read once more with that.
            assigned = {
                inner.id
                for statement in node.body
                for inner in ast.walk(statement)
                if isinstance(inner, ast.Name) and not isinstance(inner.ctx, ast.Load)
            } & reached.names.keys()
            everything = _gather(reached.names[name] for name in assigned)
            for name in assigned:
                reached.names[name] = join(reached.names[name].flat(), everything)
            reached, _ = self._pass(node, reached, frame, exits, bind)
        frame.loops.pop()
        finished: _State | None = reached
        if node.orelse:
            finished = self.block(node.orelse, reached, frame)
        for left in exits.breaks:
            finished = _merge(finished, left)
        return finished

    def _pass(
        self,
        node: ast.For | ast.AsyncFor | ast.While,
        reached: _State,
        frame: _Frame,
        exits: _Loop,
        bind: Callable[[_State], None],
    ) -> tuple[_State, bool]:
        """Read a loop body once more. Returns the state and whether it stopped changing."""
        inside = reached.copy()
        bind(inside)
        after: _State | None = self.block(node.body, inside, frame)
        for resumed in exits.continues:
            after = _merge(after, resumed)
        exits.continues.clear()
        merged = _merge(reached, after) or reached
        return merged, merged.names == reached.names

    def attempt(self, node: ast.Try, state: _State, frame: _Frame) -> _State | None:
        # An exception can leave the body after any statement, so a handler
        # starts from every state the body passed through, not only its last.
        interrupted = state.copy()
        completed: _State | None = state
        for position, statement in enumerate(node.body):
            if completed is None:
                self.skip(node.body[position:])
                break
            completed = self.statement(statement, completed, frame)
            interrupted = _merge(interrupted, completed) or interrupted
        if completed is not None and node.orelse:
            completed = self.block(node.orelse, completed, frame)
        result = completed
        for handler in node.handlers:
            caught = interrupted.copy()
            if handler.name:
                caught.names[handler.name] = self.opaque(handler)
            result = _merge(result, self.block(handler.body, caught, frame))
        if node.finalbody:
            if result is None:
                self.block(node.finalbody, interrupted.copy(), frame)
                return None
            return self.block(node.finalbody, result, frame)
        return result

    def define(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, state: _State, *, method: bool
    ) -> None:
        for decorator in node.decorator_list:
            self.evaluate(decorator, state, _Frame())
        closure = _State(
            {
                name: value
                for name, value in state.names.items()
                if name not in self.rebound
                # A list is the same list when the function runs, but not
                # necessarily with the same things in it.
                and not (name in self.mutated and _is_structured(value))
            }
        )
        if not method:
            # A method is reached through an object, never by its bare name.
            self.functions[node.name] = (node, closure)
        rules = self._routes_of(node)
        route = bool(rules)
        inner = closure.copy()
        from_request = False
        numeric = _numeric_parts(rules)
        for argument in _parameters(node):
            # `<int:page>`: converted before the function runs, so a number.
            value = PLAIN if argument.arg in numeric else self.parameter(argument, route)
            from_request = from_request or _has_input(value) or FLAG_REQUEST in value.flags
            inner.names[argument.arg] = value
        only = rules[0] if len(rules) == 1 else None
        fixed = only if only is not None and "<" not in only else None
        frame = _Frame(function=node, route=route, fixed_path=fixed)
        ended = self.block(node.body, inner, frame)
        if not method and not from_request:
            # This walk, with nothing known about the arguments, is also the
            # answer for every call that knows nothing about them.
            self.followed[(node.name, None, None)] = _outcome(frame.returned, ended)

    def parameter(self, argument: ast.arg, route: bool) -> Value:
        # A parameter of a route is a piece of the URL. A parameter called
        # `request`, in a file that uses a web framework, is the request.
        if argument.arg == "request" and self.web:
            return Value(flags=frozenset({FLAG_REQUEST}))
        annotation = dotted(argument.annotation) or ""
        if route and argument.arg not in {"self", "cls"}:
            if annotation.rpartition(".")[2] in NOT_TEXT:
                return PLAIN  # `item_id: int` — converted before the function runs
            return Value(frozenset({Taint(INPUT, argument.lineno, argument.col_offset)}))
        return self.opaque(argument)

    def _routes_of(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str | None]:
        """The URL rules a function is registered under; empty when it is not a route.

        A rule that is not a literal is ``None``: the function is a route, and
        nothing is known about its path.
        """
        rules: list[str | None] = []
        for decorator in node.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            if isinstance(target, ast.Attribute) and target.attr in ROUTE_DECORATORS:
                first = (
                    decorator.args[0]
                    if isinstance(decorator, ast.Call) and decorator.args
                    else None
                )
                literal = isinstance(first, ast.Constant) and isinstance(first.value, str)
                rules.append(first.value if literal else None)  # type: ignore[union-attr]
        return rules

    # -- assignment -----------------------------------------------------------

    def remember_origin(self, name: str, source: ast.expr, value: Value, state: _State) -> None:
        """Note what ``name`` is another name for, or was parsed from."""
        if isinstance(source, ast.Name) and source.id != name and source.id in state.names:
            state.link(name, source.id)
        elif (
            isinstance(source, ast.Call)
            and self.resolve(dotted(source.func)) in URL_PARSERS
            and source.args
            and isinstance(source.args[0], ast.Name)
            and source.args[0].id != name
        ):
            state.parsed[name] = source.args[0].id

    def assign(self, target: ast.expr, value: Value, state: _State, frame: _Frame) -> None:
        if isinstance(target, ast.Name):
            state.bind(target.id, value)
            if predictable(value) is not None:
                # Kept for one rule: a weak random number given a name that
                # says what it will be used for (`session_token = ...`).
                self.flow.stores.append(StoreSeen(target, target.id, None, None, "", value))
            return
        if isinstance(target, ast.Tuple | ast.List):
            parts = value.items
            if parts is not None and len(parts) == len(target.elts):
                for element, part in zip(target.elts, parts, strict=True):
                    self.assign(element, part, state, frame)
            else:
                spread = _element_of(value)
                for element in target.elts:
                    inner = element.value if isinstance(element, ast.Starred) else element
                    self.assign(inner, spread, state, frame)
            return
        if isinstance(target, ast.Subscript):
            key = (
                None
                if isinstance(target.slice, ast.Slice)
                else self.evaluate(target.slice, state, frame)
            )
            name = dotted(target.value)
            self.flow.stores.append(
                StoreSeen(target, name, self.resolve(name), key, _source_text(target.slice), value)
            )
            if isinstance(target.value, ast.Name) and target.value.id in state.names:
                holder = state.names[target.value.id]
                state.change(target.value.id, _stored(holder, key, value))
            else:
                self.evaluate(target.value, state, frame)
            return
        if isinstance(target, ast.Attribute):
            name = dotted(target)
            self.flow.stores.append(
                StoreSeen(target, name, self.resolve(name), None, target.attr, value)
            )
            self.evaluate(target.value, state, frame)
            return
        if isinstance(target, ast.Starred):
            self.assign(target.value, value, state, frame)

    # -- expressions ----------------------------------------------------------

    def opaque(self, node: ast.AST, *sources: Value) -> Value:
        """Something not understood, carrying whatever went into it."""
        taints: set[Taint] = {
            Taint(OPAQUE, getattr(node, "lineno", 0), getattr(node, "col_offset", 0))
        }
        for source in sources:
            taints |= source.all_taints()
        return Value(capped(taints))

    def evaluate(self, node: ast.expr, state: _State, frame: _Frame) -> Value:  # noqa: PLR0911, PLR0912 - one branch per kind of expression
        self._tick()
        if isinstance(node, ast.Constant):
            return _literal(node.value)
        if isinstance(node, ast.Name):
            return self.name(node, state)
        if isinstance(node, ast.JoinedStr):
            return self.formatted(node, state, frame)
        if isinstance(node, ast.FormattedValue):
            return self.evaluate(node.value, state, frame)
        if isinstance(node, ast.BinOp):
            left = self.evaluate(node.left, state, frame)
            right = self.evaluate(node.right, state, frame)
            return self.binary(node.op, left, right)
        if isinstance(node, ast.UnaryOp):
            operand = self.evaluate(node.operand, state, frame)
            if isinstance(node.op, ast.Not):
                return _booleans(fold(operator.not_, operand))
            if isinstance(node.op, ast.USub):
                return replace(operand.flat(), constants=fold(operator.neg, operand))
            return operand.flat()
        if isinstance(node, ast.BoolOp):
            values = [self.evaluate(value, state, frame) for value in node.values]
            return self.boolean(node.op, values)
        if isinstance(node, ast.Compare):
            return self.compare(node, state, frame)
        if isinstance(node, ast.IfExp):
            test = self.evaluate(node.test, state, frame)
            decided = _truth(test)
            if decided is True:
                self.skip([node.orelse])
                return self.evaluate(node.body, state, frame)
            if decided is False:
                self.skip([node.body])
                return self.evaluate(node.orelse, state, frame)
            return join(
                self.evaluate(node.body, state, frame), self.evaluate(node.orelse, state, frame)
            )
        if isinstance(node, ast.Call):
            return self.call(node, state, frame)
        if isinstance(node, ast.Attribute):
            return self.attribute(node, state, frame)
        if isinstance(node, ast.Subscript):
            return self.subscript(node, state, frame)
        if isinstance(node, ast.List | ast.Tuple):
            if any(isinstance(element, ast.Starred) for element in node.elts):
                return self.opaque(node, *(self.evaluate(e, state, frame) for e in node.elts))
            return Value(items=tuple(self.evaluate(e, state, frame) for e in node.elts))
        if isinstance(node, ast.Set):
            if any(isinstance(element, ast.Starred) for element in node.elts):
                return _gather(self.evaluate(e, state, frame) for e in node.elts)
            return Value(
                items=tuple(self.evaluate(e, state, frame) for e in node.elts),
                flags=frozenset({FLAG_SET}),
            )
        if isinstance(node, ast.Dict):
            return self.dictionary(node, state, frame)
        if isinstance(node, ast.Starred | ast.Await):
            return self.evaluate(node.value, state, frame)
        if isinstance(node, ast.NamedExpr):
            value = self.evaluate(node.value, state, frame)
            self.assign(node.target, value, state, frame)
            return value
        if isinstance(node, ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp):
            return self.comprehension(node, state, frame)
        if isinstance(node, ast.Lambda):
            return self.opaque(node)
        # Anything else: evaluate what is inside it and assume the result
        # depends on all of it.
        inner = [
            self.evaluate(child, state, frame)
            for child in ast.iter_child_nodes(node)
            if isinstance(child, ast.expr)
        ]
        return self.opaque(node, *inner)

    def name(self, node: ast.Name, state: _State) -> Value:
        if node.id in state.names:
            if node.id in self.shared:
                # Declared global or nonlocal somewhere: another function may
                # have assigned it since the line that is visible here.
                return self.opaque(node, state.names[node.id])
            return state.names[node.id]
        if node.id in {"True", "False", "None"}:  # pragma: no cover - constants since 3.8
            return PLAIN
        if self.imports.get(node.id) in REQUEST_OBJECTS:
            return Value(flags=frozenset({FLAG_REQUEST}))
        return self.opaque(node)

    def attribute(self, node: ast.Attribute, state: _State, frame: _Frame) -> Value:
        name = dotted(node)
        if name is not None and name.partition(".")[0] not in state.names:
            qualified = self.resolve(name) or name
            if qualified in REQUEST_OBJECTS:  # `flask.request`
                return Value(flags=frozenset({FLAG_REQUEST}))
            if frame.fixed_path is not None and qualified in REQUEST_PATHS:
                # The route matched, and its rule has no variable part, so the
                # path is the rule: the one piece of a request the caller does
                # not get to choose.
                return constant(frame.fixed_path)
            if self._is_module_path(name, state):
                return self.opaque(node)
        base = self.evaluate(node.value, state, frame)
        if FLAG_REQUEST in base.flags:
            return self.read_from_request(node, node.attr)
        carried = base.all_taints()
        if not carried:
            return self.opaque(node)
        flags = base.flags & {FLAG_PATH} if node.attr in {"parent", "parents"} else frozenset()
        return Value(capped(carried), flags=flags)

    def read_from_request(self, node: ast.AST, part: str | None) -> Value:
        """``request.<part>``, ``request.<part>()`` or ``request[...]``."""
        if part in REQUEST_NOT_INPUT:
            return self.opaque(node)
        safe = frozenset({REDIRECT}) if part in REQUEST_SAME_SITE else frozenset()
        line, column = getattr(node, "lineno", 0), getattr(node, "col_offset", 0)
        return Value(frozenset({Taint(INPUT, line, column, safe)}))

    def subscript(self, node: ast.Subscript, state: _State, frame: _Frame) -> Value:
        base = self.evaluate(node.value, state, frame)
        if isinstance(node.slice, ast.Slice):
            bounds = [
                constant(None) if part is None else self.evaluate(part, state, frame)
                for part in (node.slice.lower, node.slice.upper, node.slice.step)
            ]
            folded = fold(lambda value, a, b, c: value[a:b:c], base, *bounds)  # type: ignore[index]
            if folded is not None:
                return Value(constants=folded)
            return Value(capped(base.all_taints() | _taints_of(bounds)), flags=frozenset())
        index = self.evaluate(node.slice, state, frame)
        if FLAG_REQUEST in base.flags:
            return self.read_from_request(node, None)
        picked = _picked(base, index)
        if picked is not None:
            return picked
        folded = fold(operator.getitem, base, index)
        if folded is not None:
            return Value(constants=folded)
        carried = base.all_taints() | index.all_taints()
        if base.items is not None or base.entries is not None or base.constants is not None:
            # A known container read at an unknown place: any of its contents.
            return Value(capped(carried))
        return self.opaque(node, base, index) if not carried else Value(capped(carried))

    def dictionary(self, node: ast.Dict, state: _State, frame: _Frame) -> Value:
        entries: list[tuple[tuple[Hashable, ...], Value]] = []
        exact = True
        loose: list[Value] = []
        for key_node, value_node in zip(node.keys, node.values, strict=True):
            value = self.evaluate(value_node, state, frame)
            if key_node is None:  # **other
                exact = False
                loose.append(value)
                continue
            key = self.evaluate(key_node, state, frame)
            only = _only(key)
            if only is _NOT_KNOWN:
                exact = False
                loose += [key, value]
            else:
                entries.append(((only,), value))
        if not exact:
            everything = loose + [value for _key, value in entries]
            return replace(_gather(everything), flags=frozenset({FLAG_DICT}))
        return Value(entries=tuple(entries), flags=frozenset({FLAG_DICT}))

    def comprehension(
        self,
        node: ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp,
        state: _State,
        frame: _Frame,
    ) -> Value:
        inner = state.copy()
        for generator in node.generators:
            iterated = self.evaluate(generator.iter, inner, frame)
            self.assign(generator.target, _element_of(iterated), inner, frame)
            for condition in generator.ifs:
                self.evaluate(condition, inner, frame)
        if isinstance(node, ast.DictComp):
            produced = [
                self.evaluate(node.key, inner, frame),
                self.evaluate(node.value, inner, frame),
            ]
        else:
            produced = [self.evaluate(node.elt, inner, frame)]
        return _gather(produced)

    def formatted(self, node: ast.JoinedStr, state: _State, frame: _Frame) -> Value:
        parts = [self.evaluate(part, state, frame) for part in node.values]
        text = None
        if all(
            not isinstance(part, ast.FormattedValue)
            or (part.conversion == -1 and part.format_spec is None)
            for part in node.values
        ):
            text = fold(lambda *pieces: "".join(str(piece) for piece in pieces), *parts)
        if text is not None:
            return Value(constants=text)
        first = node.values[0] if node.values else None
        prefix = (
            first.value
            if isinstance(first, ast.Constant) and isinstance(first.value, str)
            else None
        )
        return Value(capped(_taints_of(parts)), prefix=prefix)

    def binary(self, op: ast.operator, left: Value, right: Value) -> Value:
        function = BINARY.get(type(op))
        folded = None if function is None else fold(guarded(function), left, right)
        if folded is not None:
            return Value(constants=folded)
        flags = frozenset()
        if isinstance(op, ast.Div) and FLAG_PATH in (left.flags | right.flags):
            flags = frozenset({FLAG_PATH})  # pathlib: base / name
        if isinstance(op, ast.Add) and left.items is not None and right.items is not None:
            return Value(items=left.items + right.items)
        prefix = None
        if isinstance(op, ast.Add):
            start = _only(left)
            prefix = start if isinstance(start, str) and start else left.prefix
        elif isinstance(op, ast.Mod):
            template = _only(left)
            prefix = template.partition("%")[0] if isinstance(template, str) else None
        return Value(
            capped(left.all_taints() | right.all_taints()), flags=flags, prefix=prefix or None
        )

    def boolean(self, op: ast.boolop, values: list[Value]) -> Value:
        # `a or b` is one of its operands, so it can be any of them.
        result = values[0]
        short = operator.truth if isinstance(op, ast.Or) else operator.not_
        for value in values[1:]:
            decided = _truth(result)
            if decided is not None and bool(short(decided)):
                break  # the operand already seen decides it
            result = value if decided is not None else join(result, value)
        return result

    def compare(self, node: ast.Compare, state: _State, frame: _Frame) -> Value:
        operands = [self.evaluate(node.left, state, frame)] + [
            self.evaluate(comparator, state, frame) for comparator in node.comparators
        ]
        outcome: frozenset[Hashable] | None = frozenset({True})
        for op, left, right in zip(node.ops, operands, operands[1:], strict=False):
            function = COMPARE.get(type(op))
            if function is None or outcome is None:
                outcome = None
                continue
            step = fold(function, left, _membership(right) if _is_membership(op) else right)
            if step is None:
                outcome = None
            elif step == frozenset({False}):
                return constant(False)  # one false link makes the chain false
            elif step != frozenset({True}):
                outcome = None
        # The result is a boolean. Whatever was compared, it cannot inject.
        return _booleans(outcome)

    # -- calls ----------------------------------------------------------------

    def resolve(self, name: str | None) -> str | None:
        """A dotted name with its first part replaced by what was imported."""
        if not name:
            return None
        head, _, tail = name.partition(".")
        origin = self.imports.get(head)
        if origin is None:
            return name
        return f"{origin}.{tail}" if tail else origin

    def _is_module_path(self, name: str, state: _State) -> bool:
        """Whether a dotted name is reached through an import and nothing else.

        The request object is imported too, and is the one import that must be
        read as an object: ``request.args.get`` is a method on request data.
        """
        head = name.partition(".")[0]
        if head not in self.imports or head in state.names:
            return False
        qualified = self.resolve(name) or name
        return not any(
            qualified == root or qualified.startswith(f"{root}.") for root in REQUEST_OBJECTS
        )

    def call(self, node: ast.Call, state: _State, frame: _Frame) -> Value:
        name = dotted(node.func)
        through_module = name is not None and self._is_module_path(name, state)
        qualified = self.resolve(name) if (through_module or "." not in (name or ".")) else name

        receiver: Value | None = None
        receiver_name: str | None = None
        method: str | None = None
        if isinstance(node.func, ast.Attribute):
            method = node.func.attr
            if not through_module:
                receiver = self.evaluate(node.func.value, state, frame)
                if isinstance(node.func.value, ast.Name):
                    receiver_name = node.func.value.id
        elif not isinstance(node.func, ast.Name):
            receiver = self.evaluate(node.func, state, frame)

        arguments = tuple(self.evaluate(argument, state, frame) for argument in node.args)
        if any(isinstance(argument, ast.Starred) for argument in node.args):
            arguments = (_gather(arguments),)
        keywords = {
            keyword.arg or "**": self.evaluate(keyword.value, state, frame)
            for keyword in node.keywords
        }
        self._see(node, name, qualified, receiver, arguments, keywords, frame)

        everything = [*arguments, *keywords.values()]
        tail = (qualified or name or "").rpartition(".")[2]

        # -- a result that cannot carry anything ---------------------------
        if method is None and tail in NUMERIC_FUNCTIONS and "." not in (name or "."):
            folded = (
                fold(guarded(PURE_FUNCTIONS[tail]), *arguments)
                if tail in PURE_FUNCTIONS and not keywords
                else None
            )
            return Value(constants=folded) if folded is not None else PLAIN

        # -- literals in, literals out -------------------------------------
        if method is None and tail in PURE_FUNCTIONS and "." not in (name or "."):
            folded = fold(guarded(PURE_FUNCTIONS[tail]), *arguments) if not keywords else None
            if folded is not None:
                return Value(constants=folded)
        if receiver is not None and method in PURE_METHODS and not keywords:
            folded = fold(method_of(method), receiver, *arguments)
            if folded is not None:
                return Value(constants=folded)

        # -- sources ---------------------------------------------------------
        if receiver is not None and FLAG_REQUEST in receiver.flags:
            return self.read_from_request(node, method)
        if (
            through_module
            and qualified is not None
            and qualified.startswith("random.")
            and tail in RANDOM_FUNCTIONS
        ):
            return Value(
                capped({Taint(RANDOM, node.lineno, node.col_offset)} | _taints_of(everything))
            )

        # -- sanitisers ------------------------------------------------------
        cleared = SANITISERS.get(qualified or "")
        from_framework = (qualified or "").split(".")[0] in WEB_FRAMEWORKS
        if from_framework and tail in SITE_ADDRESS_CALLS:
            cleared = frozenset({HTML, REDIRECT})
        elif cleared is None and (
            tail in HTML_ESCAPE_NAMES
            or (tail in HTML_SAFE_CALLS and from_framework)
            # template.render(context): the engine escapes what it is given —
            # unless the template itself was written by the caller.
            or (receiver is not None and method == "render" and not _has_input(receiver))
        ):
            cleared = frozenset({HTML})
        if cleared is not None:
            sources = everything if receiver is None else [receiver, *everything]
            return made_safe(self.opaque(node, *sources), cleared)
        if (
            receiver is not None
            and method == "replace"
            and len(arguments) >= 2
            and _replaces_a_quote(arguments[0], arguments[1])
        ):
            return made_safe(Value(capped(receiver.all_taints())), QUOTE_KINDS)

        # -- lookups: the answer is not the question --------------------------
        if (receiver is None and qualified in LOOKUP_CALLS) or (
            receiver is not None and method in LOOKUP_METHODS
        ):
            return self.opaque(node)

        # -- objects that stand for one of their arguments ------------------
        if (qualified in RESPONSE_FUNCTIONS or name in RESPONSE_FUNCTIONS) and arguments:
            body = arguments[0]
            return body.items[0] if body.items else body.flat()
        if qualified in PATH_CONSTRUCTORS:
            return Value(capped(_taints_of(everything)), flags=frozenset({FLAG_PATH}))
        if receiver is None and qualified in PURE_CALLS:
            return _gather(everything)
        if receiver is not None and method in PURE_METHODS:
            template = _only(receiver)
            return replace(
                _gather([receiver, *everything]),
                prefix=(
                    template.partition("{")[0] or None
                    if method == "format" and isinstance(template, str)
                    else None
                ),
            )

        # -- containers ------------------------------------------------------
        if method is None and name in {"list", "tuple"} and not everything:
            return Value(items=())
        if (
            method is None
            and name in {"list", "tuple", "set", "frozenset"}
            and len(arguments) == 1
            and not keywords
            and arguments[0].items is not None
        ):
            # A copy with the same things in it.
            flags = frozenset({FLAG_SET}) if name in {"set", "frozenset"} else frozenset()
            return Value(items=arguments[0].items, flags=flags)
        if method is None and name == "dict" and not everything:
            return Value(entries=(), flags=frozenset({FLAG_DICT}))
        if receiver is not None and method is not None:
            modelled = self.container(node, method, receiver, receiver_name, arguments, state)
            if modelled is not None:
                return modelled

        # -- a parser told to resolve external entities ----------------------
        if (
            method == "setFeature"
            and receiver_name in state.names
            and len(node.args) == 2
            and (dotted(node.args[0]) or "").endswith(
                ("feature_external_ges", "feature_external_pes")
            )
            and _truth(arguments[1]) is True
        ):
            holder = state.names[receiver_name]
            state.change(receiver_name, replace(holder, flags=holder.flags | {FLAG_ENTITIES}))
            return NOTHING

        # From here on the call is one that could change what it is given. A
        # list passed to it is, afterwards, a list of nobody-knows-what.
        for passed in [*node.args, *(keyword.value for keyword in node.keywords)]:
            if isinstance(passed, ast.Name) and passed.id in state.names:
                held = state.names[passed.id]
                if _is_structured(held):
                    state.change(passed.id, self.opaque(node, held))

        # -- a function of this file -----------------------------------------
        if isinstance(node.func, ast.Name) and node.func.id not in state.names:
            followed = self.follow(node.func.id, arguments, keywords, frame)
            if followed is not None:
                return followed

        # -- everything else: the result depends on what went in --------------
        if (
            receiver_name is not None
            and receiver_name in state.names
            and method in ABSORBING_METHODS
            and _taints_of(everything)
        ):
            holder = state.names[receiver_name].flat()
            state.change(
                receiver_name,
                replace(holder, taints=capped(holder.taints | _taints_of(everything))),
            )
        sources = [*everything] if receiver is None else [receiver, *everything]
        result = self.opaque(node, *sources)
        if receiver is not None and FLAG_PATH in receiver.flags:
            result = replace(result, flags=frozenset({FLAG_PATH}))
        return result

    def _see(  # noqa: PLR0913 - one argument per thing recorded
        self,
        node: ast.Call,
        name: str | None,
        qualified: str | None,
        receiver: Value | None,
        arguments: tuple[Value, ...],
        keywords: dict[str, Value],
        frame: _Frame,
    ) -> None:
        """Record a call. Seen twice — a loop, two callers — it is everything it was."""
        earlier = self.flow.calls.get(id(node))
        if earlier is None:
            self.flow.calls[id(node)] = CallSeen(
                node, name, qualified, receiver, arguments, dict(keywords),
                frame.function, frame.route,
            )  # fmt: skip
            return
        if earlier.receiver is not None and receiver is not None:
            earlier.receiver = join(earlier.receiver, receiver)
        if len(earlier.arguments) == len(arguments):
            earlier.arguments = tuple(
                join(a, b) for a, b in zip(earlier.arguments, arguments, strict=True)
            )
        else:
            earlier.arguments = (_gather([*earlier.arguments, *arguments]),)
        for key, value in keywords.items():
            earlier.keywords[key] = (
                join(earlier.keywords[key], value) if key in earlier.keywords else value
            )
        earlier.route = earlier.route or frame.route

    def container(  # noqa: PLR0911, PLR0912, PLR0913 - one branch per method modelled
        self,
        node: ast.Call,
        method: str,
        receiver: Value,
        receiver_name: str | None,
        arguments: tuple[Value, ...],
        state: _State,
    ) -> Value | None:
        """Lists and mappings whose contents are known element by element.

        Returns ``None`` when the call is not one of these, so that the general
        rule ("the result depends on what went in") applies instead.
        """
        bound = receiver_name is not None and receiver_name in state.names

        def rebind(value: Value) -> None:
            if receiver_name is not None and bound:
                state.change(receiver_name, value)

        if receiver.items is not None and FLAG_SET in receiver.flags:
            if method == "add" and len(arguments) == 1 and bound:
                rebind(replace(receiver, items=(*receiver.items, arguments[0])))
                return NOTHING
            if method in {"update", "discard", "remove", "pop", "clear"} and bound:
                rebind(_gather([receiver, *arguments]))
                return _gather([receiver]) if method == "pop" else NOTHING
            return None
        if receiver.items is not None:
            items = receiver.items
            if method == "append" and len(arguments) == 1 and bound:
                rebind(replace(receiver, items=(*items, arguments[0])))
                return NOTHING
            if method == "extend" and len(arguments) == 1 and bound:
                extra = arguments[0].items
                rebind(
                    replace(receiver, items=items + extra)
                    if extra is not None
                    else _gather([receiver, arguments[0]])
                )
                return NOTHING
            if method == "insert" and len(arguments) == 2 and bound:
                position = _only(arguments[0])
                if isinstance(position, int) and not isinstance(position, bool):
                    changed = list(items)
                    changed.insert(position, arguments[1])
                    rebind(replace(receiver, items=tuple(changed)))
                else:
                    rebind(_gather([receiver, arguments[1]]))
                return NOTHING
            if method == "pop" and len(arguments) <= 1 and bound:
                position = _only(arguments[0]) if arguments else -1
                if (
                    isinstance(position, int)
                    and not isinstance(position, bool)
                    and -len(items) <= position < len(items)
                ):
                    changed = list(items)
                    taken = changed.pop(position)
                    rebind(replace(receiver, items=tuple(changed)))
                    return taken
                rebind(receiver.flat())
                return Value(capped(receiver.all_taints()))
            if method == "clear" and bound:
                rebind(replace(receiver, items=()))
                return NOTHING
            if method == "copy":
                return receiver
            if method in {"index", "count"}:
                return PLAIN
            if method in {"remove", "reverse", "sort"} and bound:
                rebind(receiver.flat())
                return NOTHING
            return None

        keys = tuple(_only(argument) for argument in arguments)
        if FLAG_DICT in receiver.flags and receiver.entries is not None:
            stored = dict(receiver.entries)
            if method == "get" and 1 <= len(arguments) <= 2:
                if keys[0] is _NOT_KNOWN:
                    return _gather([receiver, *arguments[1:]])
                fallback = arguments[1] if len(arguments) == 2 else NOTHING
                return stored.get((keys[0],), fallback)
            if method == "pop" and 1 <= len(arguments) <= 2 and bound:
                if keys[0] is _NOT_KNOWN:
                    rebind(receiver.flat())
                    return _gather([receiver, *arguments[1:]])
                fallback = arguments[1] if len(arguments) == 2 else self.opaque(node)
                taken = stored.pop((keys[0],), fallback)
                rebind(replace(receiver, entries=tuple(stored.items())))
                return taken
            if method == "setdefault" and len(arguments) == 2 and bound:
                if keys[0] is _NOT_KNOWN:
                    rebind(_gather([receiver, arguments[1]]))
                    return _gather([receiver, arguments[1]])
                stored.setdefault((keys[0],), arguments[1])
                rebind(replace(receiver, entries=tuple(stored.items())))
                return stored[(keys[0],)]
            if method in {"keys", "values", "items", "copy"}:
                return receiver.flat() if method != "copy" else receiver
            if method in {"update", "clear", "popitem"} and bound:
                rebind(_gather([receiver, *arguments]) if method == "update" else receiver.flat())
                return NOTHING
            return None

        # A keyed store that is not a dict: `settings.set(section, option, value)`
        # and `settings.get(section, option)`. Tracked only when every key is a
        # literal.
        if bound and FLAG_DICT not in receiver.flags:
            if method == "set" and len(arguments) >= 3 and _NOT_KNOWN not in keys[:-1]:
                stored = dict(receiver.entries or ())
                stored[tuple(keys[:-1])] = arguments[-1]  # type: ignore[arg-type]
                rebind(replace(receiver, entries=tuple(stored.items())))
                return NOTHING
            if (
                method == "get"
                and len(arguments) >= 2
                and receiver.entries is not None
                and _NOT_KNOWN not in keys
            ):
                found = dict(receiver.entries).get(tuple(keys))  # type: ignore[arg-type]
                if found is not None:
                    return found
                # Not one of the keys that were set here: whatever the object
                # held before, which is as trustworthy as the object itself.
                return self.opaque(node, Value(receiver.taints))
        return None

    def follow(
        self,
        name: str,
        arguments: tuple[Value, ...],
        keywords: dict[str, Value],
        frame: _Frame,
    ) -> Value | None:
        """Read a function of this file with the arguments it was given here."""
        entry = self.functions.get(name)
        if (
            entry is None
            or name in self.rebound  # two definitions: no telling which one this is
            or frame.depth >= MAX_CALL_DEPTH
        ):
            return None
        function, closure = entry
        positional = [*function.args.posonlyargs, *function.args.args]
        if function.args.vararg or function.args.kwarg or len(arguments) > len(positional):
            return None  # not worth guessing how the arguments land

        # Followed with the arguments it was given only when they say something:
        # request data, or literals. Otherwise the function is read once with
        # nothing known about its arguments and that reading is reused, which is
        # what keeps a file of small functions calling each other affordable.
        given = [*arguments, *keywords.values()]
        exact = bool(given) and _says_something(given)
        key: Hashable = (
            (name, arguments, tuple(sorted(keywords.items(), key=lambda item: item[0])))
            if exact
            else (name, None, None)
        )
        if key in self.followed:
            return self.followed[key]

        inner = closure.copy()
        for argument in _parameters(function):
            inner.names[argument.arg] = self.opaque(argument)
        if exact:
            for argument, value in zip(positional, arguments, strict=False):
                inner.names[argument.arg] = value
            for keyword, value in keywords.items():
                if keyword != "**":
                    inner.names[keyword] = value
        # Not a route: what a helper returns is not what the browser receives.
        called = _Frame(function=function, depth=frame.depth + 1)
        ended = self.block(function.body, inner, called)
        outcome = _outcome(called.returned, ended)
        self.followed[key] = outcome
        return outcome

    # -- what an `if` establishes ----------------------------------------------

    def learn(self, test: ast.expr, holds: bool, state: _State, frame: _Frame) -> None:
        """Record what is known in a branch where ``test`` is ``holds``.

        This is how a check that rejects bad input is recognised: after

            if '../' in name:
                return 'invalid'

        the code that follows runs only when the check did *not* fire, so there
        ``name`` contains no ``../``. Only checks that mean something for one
        kind of use are understood; an emptiness test is not validation.

        What is learnt is about the **variable that was checked**, and nothing
        else. Two fields read from one request body are different values, and
        a check on one of them says nothing about the other — so the fact is
        attached to the name, not to the place the data came from.
        """
        facts: list[_Fact] = []
        self._facts(test, holds, state, frame, facts)
        for fact in facts:
            kinds: frozenset[str] = frozenset()
            if fact.kind == "lacks" and not fact.inner:
                text = str(fact.detail)
                if ".." in text:
                    kinds = frozenset({PATH})
                elif text in QUOTES:
                    kinds = QUOTE_KINDS
            elif fact.kind == "whole":
                kinds = ALL_KINDS
            elif fact.kind == "host":
                kinds = frozenset({REDIRECT})
            elif fact.kind == "prefix":
                kinds = frozenset({PATH, REDIRECT})
            if kinds:
                _make_safe(state, fact.names, kinds)

        # A value that starts with a quote, ends with one and has none between
        # is one string literal. Evaluating a string literal runs nothing.
        for quote in QUOTES:
            wrapped = [
                {
                    fact.names
                    for fact in facts
                    if fact.kind == kind and fact.detail == quote and fact.inner == inner
                }
                for kind, inner in (("starts", False), ("ends", False), ("lacks", True))
            ]
            for names in wrapped[0] & wrapped[1] & wrapped[2]:
                _make_safe(state, names, frozenset({CODE}))

    def _facts(  # noqa: PLR0911, PLR0912 - one branch per kind of check
        self,
        test: ast.expr,
        holds: bool,
        state: _State,
        frame: _Frame,
        facts: list["_Fact"],
    ) -> None:
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            self._facts(test.operand, not holds, state, frame, facts)
            return
        if isinstance(test, ast.BoolOp):
            # `a and b` being true makes both true; `a or b` being false makes
            # both false. The other two cases establish nothing about either.
            if isinstance(test.op, ast.And) == holds:
                for part in test.values:
                    self._facts(part, holds, state, frame, facts)
            return

        def checked(node: ast.expr) -> frozenset[str]:
            """The variable a check is about, when it is about exactly one."""
            subject = _unwrapped(node)
            if isinstance(subject, ast.Name) and subject.id in state.names:
                return frozenset({subject.id})
            return frozenset()

        def address(node: ast.expr) -> frozenset[str]:
            """The variable holding the address whose host ``node`` is."""
            if not isinstance(node, ast.Attribute) or node.attr not in HOST_ATTRIBUTES:
                return frozenset()
            holder = node.value
            if isinstance(holder, ast.Name):
                names = {holder.id}
                if holder.id in state.parsed:
                    names.add(state.parsed[holder.id])
                return frozenset(names & state.names.keys())
            if (
                isinstance(holder, ast.Call)
                and self.resolve(dotted(holder.func)) in URL_PARSERS
                and holder.args
            ):
                return checked(holder.args[0])  # urlparse(target).netloc
            return frozenset()

        def add(kind: str, detail: object, names: frozenset[str], inner: bool = False) -> None:
            if names:
                facts.append(_Fact(kind, detail, names, inner))

        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            op, left, right = test.ops[0], test.left, test.comparators[0]
            contains = isinstance(op, ast.In) and not holds or isinstance(op, ast.NotIn) and holds
            member = isinstance(op, ast.In) and holds or isinstance(op, ast.NotIn) and not holds
            equal = isinstance(op, ast.Eq) and holds or isinstance(op, ast.NotEq) and not holds
            needle = _only(self.evaluate(left, state, frame))
            if contains and isinstance(needle, str):
                # `'../' not in value`, or `"'" not in value[1:-1]`
                inner = _inside_the_ends(right)
                add(
                    "lacks",
                    needle,
                    checked(inner if inner is not None else right),
                    inner is not None,
                )
                return
            allowed = self.evaluate(right, state, frame)
            literal = (
                allowed.constants is not None
                if equal
                else _membership(allowed).constants is not None and allowed.constants is None
            )
            if (member or equal) and literal:
                # `value in ('a', 'b')` or `value == 'a'`
                add("whole", None, checked(left))
                if member:
                    add("host", None, address(_unwrapped(left)))
            return

        if (
            isinstance(test, ast.Call)
            and holds
            and (dotted(test.func) or "").rpartition(".")[2] in REDIRECT_VALIDATORS
        ):
            subject = test.args[0] if test.args else None
            for keyword in test.keywords:
                if keyword.arg == "url":
                    subject = keyword.value
            if subject is not None:
                add("host", None, checked(subject))
            return
        if isinstance(test, ast.Call) and isinstance(test.func, ast.Attribute) and holds:
            method, subject = test.func.attr, test.func.value
            if method in {"startswith", "endswith"} and len(test.args) == 1:
                argument = self.evaluate(test.args[0], state, frame)
                only = _only(argument)
                if only in QUOTES:
                    add("starts" if method == "startswith" else "ends", only, checked(subject))
                elif method == "startswith" and not _has_input(argument):
                    add("prefix", None, checked(subject))
                return
            if method in WHOLE_VALUE_CHECKS and not test.args:
                add("whole", None, checked(subject))
                return
            if method == "is_relative_to" and len(test.args) == 1:
                add("prefix", None, checked(subject))
                return
            if method == "fullmatch" and test.args:
                # re.fullmatch(pattern, value) or compiled.fullmatch(value)
                through_re = self.resolve(dotted(test.func)) == "re.fullmatch"
                if through_re and len(test.args) >= 2:
                    add("whole", None, checked(test.args[1]))
                elif not through_re:
                    add("whole", None, checked(test.args[0]))


@dataclass(frozen=True)
class _Fact:
    """Something an ``if`` established about one or more variables."""

    kind: str
    detail: object
    names: frozenset[str]
    # True for a check on ``value[1:-1]``: everything between the two ends.
    inner: bool = False


# --- helpers -------------------------------------------------------------------

_LITERAL_TYPES = (str, bytes, int, float, bool)
_NOT_KNOWN: Hashable = object()


def _numeric_parts(rules: list[str | None]) -> frozenset[str]:
    """Parameters that every rule naming them converts to something that is not text.

    ``/items/<int:item_id>/<name>`` -> ``{"item_id"}``. A parameter that is a
    number under one rule and text under another is text.
    """
    numeric: set[str] = set()
    text: set[str] = set()
    for rule in rules:
        for part in (rule or "").split("<")[1:]:
            converter, colon, name = part.partition(">")[0].partition(":")
            if colon and converter.partition("(")[0].strip() in NOT_TEXT:
                numeric.add(name.strip())
            else:
                text.add((name if colon else converter).strip())
    return frozenset(numeric - text)


def _outcome(returned: list[Value], ended: object) -> Value:
    """What a call gives back: any of its returns, or None if it can fall off the end."""
    results = list(returned)
    if ended is not None or not results:
        results.append(NOTHING)
    outcome = results[0]
    for result in results[1:]:
        outcome = join(outcome, result)
    return outcome


def _says_something(values: list[Value]) -> bool:
    """Whether arguments are worth following a function with."""
    taints = _taints_of(values)
    return not taints or any(taint.origin != OPAQUE for taint in taints)


def _survey(
    tree: ast.Module,
) -> tuple[frozenset[str], frozenset[str], frozenset[str], frozenset[str]]:
    """One pass over the file for what the walk needs to know before it starts.

    * names bound in more than one place;
    * names declared ``global`` or ``nonlocal`` — changed from somewhere else;
    * names of things that are changed in place somewhere (``items.append``,
      ``table[key] = ...``) or handed to a call that could do so;
    * which web frameworks are imported.
    """
    seen: set[str] = set()
    again: set[str] = set()
    shared: set[str] = set()
    mutated: set[str] = set()
    web: set[str] = set()
    pending: list[ast.AST] = [tree]
    while pending:
        node = pending.pop()
        kind = type(node)
        if kind is ast.Name:
            if type(node.ctx) is not ast.Load:  # type: ignore[attr-defined]
                name = node.id  # type: ignore[attr-defined]
                (again if name in seen else seen).add(name)
            continue
        if kind in (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef):
            name = node.name  # type: ignore[attr-defined]
            (again if name in seen else seen).add(name)
        elif kind in (ast.Global, ast.Nonlocal):
            shared.update(node.names)  # type: ignore[attr-defined]
        elif kind is ast.Import:
            web.update(alias.name.split(".")[0] for alias in node.names)  # type: ignore[attr-defined]
        elif kind is ast.ImportFrom:
            web.add((node.module or "").split(".")[0])  # type: ignore[attr-defined]
        elif kind is ast.Call:
            function = node.func  # type: ignore[attr-defined]
            if (
                type(function) is ast.Attribute
                and type(function.value) is ast.Name
                and function.attr in MUTATING_METHODS
            ):
                mutated.add(function.value.id)
            for argument in node.args:  # type: ignore[attr-defined]
                if type(argument) is ast.Name:
                    mutated.add(argument.id)
            for keyword in node.keywords:  # type: ignore[attr-defined]
                if type(keyword.value) is ast.Name:
                    mutated.add(keyword.value.id)
        elif kind is ast.Subscript:
            target = node.value  # type: ignore[attr-defined]
            if type(node.ctx) is not ast.Load and type(target) is ast.Name:  # type: ignore[attr-defined]
                mutated.add(target.id)
        elif kind is ast.AugAssign and type(node.target) is ast.Name:  # type: ignore[attr-defined]
            mutated.add(node.target.id)  # type: ignore[attr-defined]
        pending.extend(ast.iter_child_nodes(node))
    return (
        frozenset(again | shared),
        frozenset(shared),
        frozenset(mutated),
        frozenset(web & WEB_FRAMEWORKS),
    )


def dotted(node: ast.AST | None) -> str | None:
    """``a.b.c`` for a name or an attribute chain; ``None`` for anything else."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = dotted(node.value)
        return f"{parent}.{node.attr}" if parent else None
    return None


def _as_load(node: ast.expr) -> ast.expr:
    """The target of ``x += 1`` read as an expression."""
    fields = {name: getattr(node, name) for name in node._fields}
    copy = ast.copy_location(type(node)(**fields), node)
    if hasattr(copy, "ctx"):
        copy.ctx = ast.Load()  # type: ignore[attr-defined]
    return copy


def _parameters(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.arg]:
    arguments = node.args
    found = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
    found += [extra for extra in (arguments.vararg, arguments.kwarg) if extra is not None]
    return found


def _source_text(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:  # noqa: BLE001 - the text is only used to look for a word
        return ""


def _literal(value: object) -> Value:
    if value is None or type(value) in _LITERAL_TYPES:
        return constant(value)
    return PLAIN  # Ellipsis, complex


def _only(value: Value) -> Hashable:
    """The single literal a value is known to be, or ``_NOT_KNOWN``."""
    if value.constants is not None and len(value.constants) == 1:
        return next(iter(value.constants))
    return _NOT_KNOWN


def _truth(value: Value) -> bool | None:
    """Whether a value is true, when every alternative agrees."""
    if value.constants is not None:
        verdicts = {bool(item) for item in value.constants}
        return verdicts.pop() if len(verdicts) == 1 else None
    if value.items is not None:
        return bool(value.items)
    if value.entries is not None and FLAG_DICT in value.flags:
        return bool(value.entries)
    return None


def _booleans(constants: frozenset[Hashable] | None) -> Value:
    return PLAIN if constants is None else Value(constants=constants)


def _taints_of(values: Iterable[Value]) -> frozenset[Taint]:
    found: set[Taint] = set()
    for value in values:
        found |= value.all_taints()
    return frozenset(found)


def _has_input(value: Value) -> bool:
    return any(taint.origin == INPUT for taint in value.all_taints())


def _gather(values: Iterable[Value]) -> Value:
    """One unstructured value holding everything in ``values``."""
    return Value(capped(_taints_of(values)))


def _element_of(value: Value) -> Value:
    """What a loop variable is when iterating over ``value``."""
    if value.items:
        element = value.items[0]
        for item in value.items[1:]:
            element = join(element, item)
        return element
    if value.constants is not None and all(isinstance(item, str) for item in value.constants):
        letters = {letter for item in value.constants for letter in str(item)}
        if len(letters) <= MAX_CONSTANTS:
            return Value(constants=frozenset(letters))
        return PLAIN
    return Value(capped(value.all_taints()))


def _picked(base: Value, index: Value) -> Value | None:
    """One element of a container whose contents are known."""
    key = _only(index)
    if key is _NOT_KNOWN:
        return None
    if FLAG_SET in base.flags:
        return None
    if base.items is not None and isinstance(key, int) and not isinstance(key, bool):
        return base.items[key] if -len(base.items) <= key < len(base.items) else None
    if base.entries is not None and FLAG_DICT in base.flags:
        return dict(base.entries).get((key,))
    return None


def _stored(holder: Value, key: Value | None, value: Value) -> Value:
    """``holder`` after ``holder[key] = value``."""
    only = _NOT_KNOWN if key is None else _only(key)
    if only is not _NOT_KNOWN:
        if holder.entries is not None and FLAG_DICT in holder.flags:
            entries = dict(holder.entries)
            entries[(only,)] = value
            return replace(holder, entries=tuple(entries.items()))
        if (
            holder.items is not None
            and FLAG_SET not in holder.flags
            and isinstance(only, int)
            and not isinstance(only, bool)
            and -len(holder.items) <= only < len(holder.items)
        ):
            items = list(holder.items)
            items[only] = value
            return replace(holder, items=tuple(items))
    flat = holder.flat()
    extra = value.all_taints() | (key.all_taints() if key is not None else frozenset())
    return replace(flat, taints=capped(flat.taints | extra))


def _make_safe(state: _State, names: frozenset[str], kinds: frozenset[str]) -> None:
    """The variables that were checked are, from here on, safe for ``kinds``."""
    for name in names:
        if name in state.names:
            state.change(name, made_safe(state.names[name], kinds))


def _is_structured(value: Value) -> bool:
    """Whether a value is a container whose contents are individually known."""
    return value.items is not None or value.entries is not None


def _inside_the_ends(node: ast.expr) -> ast.expr | None:
    """``value`` for the expression ``value[1:-1]``; ``None`` for anything else."""
    if (
        isinstance(node, ast.Subscript)
        and isinstance(node.slice, ast.Slice)
        and node.slice.step is None
        and isinstance(node.slice.lower, ast.Constant)
        and node.slice.lower.value == 1
        and isinstance(node.slice.upper, ast.UnaryOp)
        and isinstance(node.slice.upper.op, ast.USub)
        and isinstance(node.slice.upper.operand, ast.Constant)
        and node.slice.upper.operand.value == 1
    ):
        return node.value
    return None


def _unwrapped(node: ast.expr) -> ast.expr:
    """``str(x).lower().strip()`` -> ``x``: wrappers that keep it the same value."""
    while True:
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"lower", "upper", "strip", "casefold"}
            and not node.args
        ):
            node = node.func.value
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "str"
            and len(node.args) == 1
        ):
            node = node.args[0]
        else:
            return node


def _replaces_a_quote(old: Value, new: Value) -> bool:
    quote, replacement = _only(old), _only(new)
    return quote in QUOTES and isinstance(replacement, str) and str(quote) not in replacement


def _is_membership(op: ast.cmpop) -> bool:
    return isinstance(op, ast.In | ast.NotIn)


def _membership(value: Value) -> Value:
    """A list of literals as one tuple, so ``x in [...]`` can be worked out."""
    if value.items is None:
        return value
    members = [_only(item) for item in value.items]
    if _NOT_KNOWN in members:
        return PLAIN
    return constant(tuple(members))


def _pattern_matches(pattern: ast.pattern, subject: Hashable) -> bool | None:
    """Whether a ``case`` pattern matches a known subject. ``None``: cannot tell."""
    if isinstance(pattern, ast.MatchValue):
        if isinstance(pattern.value, ast.Constant):
            return bool(pattern.value.value == subject)
        return None
    if isinstance(pattern, ast.MatchSingleton):
        return pattern.value is subject
    if isinstance(pattern, ast.MatchOr):
        verdicts = [_pattern_matches(option, subject) for option in pattern.patterns]
        if any(verdict is True for verdict in verdicts):
            return True
        return False if all(verdict is False for verdict in verdicts) else None
    if isinstance(pattern, ast.MatchAs):
        return True if pattern.pattern is None else _pattern_matches(pattern.pattern, subject)
    return None


__all__ = [
    "ALL_KINDS",
    "FILE_CALLS",
    "SUBPROCESS_CALLS",
    "XPATH_CALLS",
    "CLEAN",
    "CODE",
    "COMMAND",
    "DATA",
    "EMPTY_FLOW",
    "FLAG_DICT",
    "FLAG_ENTITIES",
    "FLAG_PATH",
    "HTML",
    "INPUT",
    "LDAP",
    "PATH",
    "REDIRECT",
    "SQL",
    "TAINTED",
    "TRUST",
    "UNKNOWN",
    "XPATH",
    "CallSeen",
    "Flow",
    "ReturnSeen",
    "StoreSeen",
    "Taint",
    "Value",
    "analyse",
    "classify",
    "dotted",
    "predictable",
]
