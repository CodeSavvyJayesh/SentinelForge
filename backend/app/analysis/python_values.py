"""What the flow walk knows about one value, and how two such things combine.

Kept apart from the walk itself (:mod:`app.analysis.python_flow`) so the part
that decides whether something is *safe* can be read on its own: a value is
dangerous for a kind of use when a reason to distrust it is still live for
that kind, and joining two values never removes a reason.
"""

import ast
import itertools
import operator
from collections.abc import Callable, Hashable
from dataclasses import dataclass, replace

# --- where a value came from ------------------------------------------------

INPUT = "input"  # read from the HTTP request
RANDOM = "random"  # produced by the predictable `random` module
OPAQUE = "opaque"  # the result of something not understood

# --- what a value could be used to attack ------------------------------------

COMMAND = "command"
CODE = "code"
SQL = "sql"
PATH = "path"
XPATH = "xpath"
LDAP = "ldap"
REDIRECT = "redirect"
HTML = "html"
TRUST = "trust"
DATA = "data"  # deserialisers and XML parsers
ALL_KINDS: frozenset[str] = frozenset(
    {COMMAND, CODE, SQL, PATH, XPATH, LDAP, REDIRECT, HTML, TRUST, DATA}
)

TAINTED = "tainted"  # request data reaches it
UNKNOWN = "unknown"  # could not be shown either way
CLEAN = "clean"  # built only from literals in the source

MAX_CONSTANTS = 8  # how many alternatives a value may have before it is "not known"
MAX_COMBINATIONS = 64
MAX_TEXT = 4096
MAX_INTEGER_BITS = 256
MAX_TAINTS = 48
MAX_STEPS = 200_000
MAX_CALL_DEPTH = 3
# How many times a loop body is read before the walk stops waiting for it to
# settle and assumes the worst about every name it assigns.
LOOP_PASSES = 6


@dataclass(frozen=True)
class Taint:
    """One reason not to trust a value: where it came from, and what it is safe for."""

    origin: str
    line: int
    column: int
    # Kinds of use this has been made safe for, by a sanitiser or a check.
    safe: frozenset[str] = frozenset()

    @property
    def label(self) -> tuple[str, int, int]:
        return (self.origin, self.line, self.column)


@dataclass(frozen=True)
class Value:
    """What is known about one value at one point in the program."""

    taints: frozenset[Taint] = frozenset()
    # Every value it can be, when that is known; None when it is not.
    constants: frozenset[Hashable] | None = None
    # A list or tuple whose elements are individually known.
    items: tuple["Value", ...] | None = None
    # A mapping whose keys are literals: ((key, ...), value) pairs.
    entries: tuple[tuple[tuple[Hashable, ...], "Value"], ...] | None = None
    # Facts about an object rather than about its content.
    flags: frozenset[str] = frozenset()
    # Text a string is known to begin with, when the rest is not known:
    # "/users/" for `"/users/" + name`.
    prefix: str | None = None

    def all_taints(self) -> frozenset[Taint]:
        """Its own taints and those of everything it contains."""
        if self.items is None and self.entries is None:
            return self.taints
        found = set(self.taints)
        for item in self.items or ():
            found |= item.all_taints()
        for _key, entry in self.entries or ():
            found |= entry.all_taints()
        return frozenset(found)

    def flat(self) -> "Value":
        """The same value with its structure forgotten and nothing else lost."""
        if self.items is None and self.entries is None and self.constants is None:
            return self
        return Value(taints=capped(self.all_taints()), flags=self.flags)


NOTHING = Value(constants=frozenset({None}))
PLAIN = Value()  # no known content, no reason for distrust: a number, a boolean

FLAG_DICT = "dict"
FLAG_PATH = "path"
FLAG_ENTITIES = "external-entities"
# The request itself. It carries no taint: what is *read from it* does. Handing
# the object to a function says nothing about what that function returns, and
# assuming it returned request data reported every view of a real framework
# that passes `request` to a helper.
FLAG_REQUEST = "request"
# A set: its elements are known, their order and position are not.
FLAG_SET = "set"


def constant(value: Hashable) -> Value:
    return Value(constants=frozenset({value}))


def classify(value: Value, kind: str) -> tuple[str, Taint | None]:
    """How dangerous ``value`` is for one kind of use, and the input responsible."""
    live = [taint for taint in value.all_taints() if kind not in taint.safe]
    inputs = [taint for taint in live if taint.origin == INPUT]
    if inputs:
        return TAINTED, min(inputs, key=lambda taint: (taint.line, taint.column))
    if any(taint.origin == OPAQUE for taint in live):
        return UNKNOWN, None
    return CLEAN, None


def predictable(value: Value) -> Taint | None:
    """The weak random number this value was made from, if it was."""
    found = [taint for taint in value.all_taints() if taint.origin == RANDOM]
    return min(found, key=lambda taint: (taint.line, taint.column)) if found else None


def join(first: Value, second: Value) -> Value:
    """A value that is ``first`` on one path and ``second`` on another."""
    if first == second:
        return first
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

    entries = None
    if first.entries is not None and second.entries is not None:
        left, right = dict(first.entries), dict(second.entries)
        if left.keys() == right.keys():
            entries = tuple((key, join(left[key], right[key])) for key in left)

    taints = first.taints | second.taints
    # Structure that could not be kept must not take its contents with it.
    if items is None:
        for value in (first, second):
            for item in value.items or ():
                taints |= item.all_taints()
    if entries is None:
        for value in (first, second):
            for _key, entry in value.entries or ():
                taints |= entry.all_taints()
    prefix = first.prefix if first.prefix == second.prefix else None
    return Value(capped(taints), constants, items, entries, first.flags | second.flags, prefix)


def capped(taints: frozenset[Taint] | set[Taint]) -> frozenset[Taint]:
    """Keep the set small without ever making a value look safer."""
    if len(taints) <= MAX_TAINTS:
        return frozenset(taints)
    kept = {taint for taint in taints if taint.origin != OPAQUE}
    opaque = [taint for taint in taints if taint.origin == OPAQUE]
    if opaque:
        # One stand-in, safe only for what every one of them was safe for.
        safe = frozenset.intersection(*(taint.safe for taint in opaque))
        kept.add(Taint(OPAQUE, 0, 0, safe))
    return frozenset(kept)


def made_safe(value: Value, kinds: frozenset[str]) -> Value:
    """``value`` after something made it safe for ``kinds``."""
    return retaint(value, lambda taint: replace(taint, safe=taint.safe | kinds))


def retaint(value: Value, change: Callable[[Taint], Taint]) -> Value:
    if not value.taints and value.items is None and value.entries is None:
        return value
    return replace(
        value,
        taints=frozenset(change(taint) for taint in value.taints),
        items=None if value.items is None else tuple(retaint(i, change) for i in value.items),
        entries=(
            None
            if value.entries is None
            else tuple((key, retaint(entry, change)) for key, entry in value.entries)
        ),
    )


BINARY: dict[type, Callable[[object, object], object]] = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Div: operator.truediv,
    ast.Pow: operator.pow,
    ast.BitAnd: operator.and_,
    ast.BitOr: operator.or_,
    ast.BitXor: operator.xor,
    ast.LShift: operator.lshift,
    ast.RShift: operator.rshift,
}
COMPARE: dict[type, Callable[[object, object], object]] = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.Is: operator.is_,
    ast.IsNot: operator.is_not,
    ast.In: lambda left, right: left in right,  # type: ignore[operator]
    ast.NotIn: lambda left, right: left not in right,  # type: ignore[operator]
}


def method_of(name: str) -> Callable[..., object]:
    def apply(receiver: object, *arguments: object) -> object:
        return getattr(receiver, name)(*arguments)

    return guarded(apply)


def guarded(function: Callable[..., object]) -> Callable[..., object]:
    """Refuse an operation on literals whose result would be enormous."""

    def apply(*operands: object) -> object:
        for operand in operands:
            if (
                isinstance(operand, int)
                and not isinstance(operand, bool)
                and operand.bit_length() > MAX_INTEGER_BITS
            ):
                raise OverflowError
        if function in (operator.pow, operator.lshift) and not all(
            isinstance(o, int) and abs(o) <= MAX_INTEGER_BITS for o in operands[1:]
        ):
            raise OverflowError
        if function is operator.mul:
            sizes = [len(o) if isinstance(o, str | bytes | tuple) else None for o in operands]
            counts = [o for o in operands if isinstance(o, int) and not isinstance(o, bool)]
            if any(size is not None for size in sizes) and any(
                (size or 0) * abs(count) > MAX_TEXT for size in sizes for count in counts
            ):
                raise OverflowError
        return function(*operands)

    return apply


def fold(function: Callable[..., object], *values: Value) -> frozenset[Hashable] | None:
    """Apply an operation to every combination of known literals.

    ``None`` when any operand is not a known literal, when there are too many
    combinations, or when the operation fails for any of them — in which case
    nothing is claimed about the result.
    """
    alternatives = [value.constants for value in values]
    if any(options is None for options in alternatives):
        return None
    combinations = 1
    for options in alternatives:
        combinations *= len(options or ())
    if combinations == 0 or combinations > MAX_COMBINATIONS:
        return None
    results: set[Hashable] = set()
    for operands in itertools.product(*(options or () for options in alternatives)):
        try:
            result = function(*operands)
            if isinstance(result, list):
                result = tuple(result)  # `'a/b'.split('/')`: kept as a tuple of literals
            hash(result)
        except Exception:  # noqa: BLE001 - any failure means "not known", never a crash
            return None
        if isinstance(result, str | bytes | tuple) and len(result) > MAX_TEXT:
            return None
        if isinstance(result, int) and not isinstance(result, bool):
            if result.bit_length() > MAX_INTEGER_BITS * 2:
                return None
        elif isinstance(result, dict | set):
            return None
        results.add(result)  # type: ignore[arg-type]
    return frozenset(results) if len(results) <= MAX_CONSTANTS else None


__all__ = [
    "ALL_KINDS",
    "BINARY",
    "CLEAN",
    "CODE",
    "COMMAND",
    "COMPARE",
    "DATA",
    "FLAG_DICT",
    "FLAG_ENTITIES",
    "FLAG_PATH",
    "FLAG_REQUEST",
    "FLAG_SET",
    "HTML",
    "INPUT",
    "LDAP",
    "LOOP_PASSES",
    "MAX_CALL_DEPTH",
    "MAX_CONSTANTS",
    "MAX_STEPS",
    "NOTHING",
    "OPAQUE",
    "PATH",
    "PLAIN",
    "RANDOM",
    "REDIRECT",
    "SQL",
    "TAINTED",
    "TRUST",
    "UNKNOWN",
    "XPATH",
    "Taint",
    "Value",
    "capped",
    "classify",
    "constant",
    "fold",
    "guarded",
    "join",
    "made_safe",
    "method_of",
    "predictable",
    "retaint",
]
