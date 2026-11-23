"""Read Java source into a small syntax tree, for the flow walk.

There is no Java parser in the project and this does not add one. Java's
grammar is regular enough at the level the flow walk needs — classes, fields,
methods, statements and expressions — that a hand-written reader of about six
hundred lines covers it, and a reader we wrote is one whose failures we
control: anything it does not understand becomes an :class:`Opaque` node or a
skipped method, never an exception that takes the scan down.

Nothing is compiled, loaded or run. The text is read, and that is all.

What it does not try to understand, and reads as opaque: lambdas, method
references, switch *expressions*, anonymous class bodies, local classes,
records and enums (their bodies are skipped). The flow walk treats an opaque
value as one whose origin is unknown, which is the cautious reading.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# --- tokens -----------------------------------------------------------------

IDENT = "ident"
NUMBER = "number"
STRING = "string"
CHAR = "char"
OP = "op"
ANNOTATION = "annotation"
END = "end"

MAX_SOURCE = 400_000  # characters; larger files are read by the patterns only
MAX_TOKENS = 120_000
MAX_DEPTH = 120  # nesting of expressions and statements


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    line: int
    # Offset of the first character after this token, to tell `>>` from `> >`.
    end: int
    start: int
    value: object = None


_TOKEN = re.compile(
    r"""
    (?P<space>[ \t\f\r\n]+)
  | (?P<comment>//[^\n]*|/\*.*?\*/)
  | (?P<text_block>\"\"\"[ \t\f]*\r?\n(?:\\.|[^\\])*?\"\"\")
  | (?P<string>"(?:\\.|[^"\\\n])*")
  | (?P<char>'(?:\\.|[^'\\\n])+')
  | (?P<number>(?:0[xX][0-9a-fA-F_.]+(?:[pP][+-]?\d+)?
              |0[bB][01_]+
              |(?:\d[\d_]*)?\.?\d[\d_]*(?:[eE][+-]?\d+)?)[lLfFdD]?)
  | (?P<ident>(?:[^\W\d]|\$)(?:\w|\$)*)
  | (?P<op>>>>=|<<=|>>=|\.\.\.|->|::|\+\+|--|&&|\|\||[=!<>]=|[-+*/%&|^]=
          |[-+*/%&|^!~?:;,.(){}\[\]<>=@])
    """,
    re.VERBOSE | re.DOTALL,
)

_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "s": " ", "0": "\0"}


def _unescape(body: str) -> str:
    out: list[str] = []
    index = 0
    while index < len(body):
        char = body[index]
        if char == "\\" and index + 1 < len(body):
            following = body[index + 1]
            if following == "u":
                digits = body[index + 2 : index + 6]
                if re.fullmatch(r"[0-9a-fA-F]{4}", digits):
                    out.append(chr(int(digits, 16)))
                    index += 6
                    continue
            out.append(_ESCAPES.get(following, following))
            index += 2
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _number(text: str) -> object:
    cleaned = text.replace("_", "")
    try:
        if cleaned.lower().startswith("0x"):
            if "." in cleaned or "p" in cleaned.lower():
                return float.fromhex(cleaned.rstrip("fFdD"))
            return int(cleaned.rstrip("lL"), 16)
        cleaned = cleaned.rstrip("lLfFdD")
        if cleaned.lower().startswith("0b"):
            return int(cleaned[2:], 2)
        if re.fullmatch(r"\d+", cleaned):
            return int(cleaned)
        return float(cleaned)
    except ValueError:
        return None


class SyntaxProblem(Exception):
    """The reader met something it does not understand here."""


def tokenize(source: str) -> list[Token]:
    if len(source) > MAX_SOURCE:
        raise SyntaxProblem("file too large")
    tokens: list[Token] = []
    position = 0
    line = 1
    length = len(source)
    while position < length:
        match = _TOKEN.match(source, position)
        if match is None:
            raise SyntaxProblem(f"unreadable character on line {line}")
        kind = match.lastgroup
        text = match.group()
        start = position
        position = match.end()
        if kind == "string":
            tokens.append(Token(STRING, text, line, position, start, _unescape(text[1:-1])))
        elif kind == "text_block":
            body = text[3:-3].split("\n", 1)[1] if "\n" in text else ""
            tokens.append(Token(STRING, text, line, position, start, _unescape(body)))
        elif kind == "char":
            value = _unescape(text[1:-1])
            tokens.append(Token(CHAR, text, line, position, start, value[:1]))
        elif kind == "number":
            tokens.append(Token(NUMBER, text, line, position, start, _number(text)))
        elif kind == "ident":
            tokens.append(Token(IDENT, text, line, position, start))
        elif kind == "op":
            tokens.append(Token(OP, text, line, position, start))
        line += text.count("\n")
        if len(tokens) > MAX_TOKENS:
            raise SyntaxProblem("too many tokens")
    tokens.append(Token(END, "", line, position, position))
    return tokens


# --- the tree -----------------------------------------------------------------
# Expressions


@dataclass(frozen=True)
class Node:
    line: int


@dataclass(frozen=True)
class Literal(Node):
    value: object  # str, int, float, bool, None; a char is a one-letter str
    is_char: bool = False


@dataclass(frozen=True)
class Name(Node):
    name: str


@dataclass(frozen=True)
class Field(Node):
    target: Node
    name: str


@dataclass(frozen=True)
class Call(Node):
    target: Node | None  # None: an unqualified call, `doSomething(x)`
    name: str
    args: tuple[Node, ...]
    last_line: int = 0


@dataclass(frozen=True)
class New(Node):
    type_name: str
    args: tuple[Node, ...]
    anonymous: bool = False
    last_line: int = 0


@dataclass(frozen=True)
class NewArray(Node):
    type_name: str
    items: tuple[Node, ...] | None  # None: `new String[n]`


@dataclass(frozen=True)
class ArrayInit(Node):
    items: tuple[Node, ...]


@dataclass(frozen=True)
class Index(Node):
    target: Node
    index: Node


@dataclass(frozen=True)
class Binary(Node):
    op: str
    left: Node
    right: Node
    last_line: int = 0


@dataclass(frozen=True)
class Unary(Node):
    op: str
    operand: Node
    postfix: bool = False


@dataclass(frozen=True)
class Conditional(Node):
    test: Node
    then: Node
    otherwise: Node


@dataclass(frozen=True)
class Assign(Node):
    op: str  # "=", "+=", ...
    target: Node
    value: Node


@dataclass(frozen=True)
class Cast(Node):
    type_name: str
    operand: Node


@dataclass(frozen=True)
class InstanceOf(Node):
    operand: Node
    type_name: str


@dataclass(frozen=True)
class Opaque(Node):
    """Something read past without being understood: a lambda, a switch expression."""


# Statements


@dataclass(frozen=True)
class Block(Node):
    body: tuple[Node, ...]


@dataclass(frozen=True)
class Local(Node):
    type_name: str
    names: tuple[tuple[str, int, Node | None], ...]  # name, array dimensions, initial value


@dataclass(frozen=True)
class ExpressionStatement(Node):
    expression: Node


@dataclass(frozen=True)
class If(Node):
    test: Node
    then: Node
    otherwise: Node | None


@dataclass(frozen=True)
class While(Node):
    test: Node
    body: Node
    do: bool = False


@dataclass(frozen=True)
class For(Node):
    init: tuple[Node, ...]
    test: Node | None
    update: tuple[Node, ...]
    body: Node


@dataclass(frozen=True)
class ForEach(Node):
    type_name: str
    name: str
    iterable: Node
    body: Node


@dataclass(frozen=True)
class Catch(Node):
    type_name: str
    name: str
    body: Block


@dataclass(frozen=True)
class Try(Node):
    resources: tuple[Node, ...]
    body: Block
    catches: tuple[Catch, ...]
    finally_: Block | None


@dataclass(frozen=True)
class Case(Node):
    labels: tuple[Node, ...] | None  # None: default
    body: tuple[Node, ...]
    arrow: bool = False


@dataclass(frozen=True)
class Switch(Node):
    subject: Node
    cases: tuple[Case, ...]


@dataclass(frozen=True)
class Return(Node):
    value: Node | None


@dataclass(frozen=True)
class Jump(Node):
    kind: str  # break, continue, throw
    value: Node | None = None


@dataclass(frozen=True)
class Skip(Node):
    """A statement with no effect the walk follows: a local class, an empty `;`."""


# Declarations


@dataclass(frozen=True)
class Parameter:
    type_name: str
    name: str
    annotations: tuple[str, ...] = ()


@dataclass
class Method:
    name: str
    parameters: tuple[Parameter, ...]
    body: Block | None  # None: abstract, or its body could not be read
    line: int
    last_line: int
    owner: ClassDecl
    is_static: bool = False
    is_constructor: bool = False
    readable: bool = True


@dataclass
class FieldDecl:
    name: str
    type_name: str
    value: Node | None
    is_static: bool
    is_final: bool
    line: int


@dataclass
class ClassDecl:
    name: str
    kind: str  # class, interface, enum, record
    supertypes: tuple[str, ...]
    methods: list[Method] = field(default_factory=list)
    fields: dict[str, FieldDecl] = field(default_factory=dict)
    nested: list[ClassDecl] = field(default_factory=list)
    outer: ClassDecl | None = None


@dataclass
class CompilationUnit:
    classes: list[ClassDecl]

    def all_classes(self) -> list[ClassDecl]:
        found: list[ClassDecl] = []
        pending = list(self.classes)
        while pending:
            current = pending.pop(0)
            found.append(current)
            pending.extend(current.nested)
        return found


# --- the reader ----------------------------------------------------------------

MODIFIERS = frozenset(
    {
        "public",
        "private",
        "protected",
        "static",
        "final",
        "abstract",
        "native",
        "synchronized",
        "transient",
        "volatile",
        "strictfp",
        "default",
        "sealed",
        "non-sealed",
    }
)
TYPE_KEYWORDS = frozenset({"class", "interface", "enum", "record"})
STATEMENT_KEYWORDS = frozenset(
    {
        "if",
        "else",
        "for",
        "while",
        "do",
        "try",
        "catch",
        "finally",
        "switch",
        "case",
        "return",
        "break",
        "continue",
        "throw",
        "new",
        "synchronized",
        "assert",
        "yield",
        "instanceof",
        "this",
        "super",
        "true",
        "false",
        "null",
    }
)
ASSIGNMENT_OPS = frozenset(
    {"=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", ">>>="}
)
BINARY_PRECEDENCE = {
    "||": 1,
    "&&": 2,
    "|": 3,
    "^": 4,
    "&": 5,
    "==": 6,
    "!=": 6,
    "<": 7,
    ">": 7,
    "<=": 7,
    ">=": 7,
    "instanceof": 7,
    "<<": 8,
    ">>": 8,
    ">>>": 8,
    "+": 9,
    "-": 9,
    "*": 10,
    "/": 10,
    "%": 10,
}


class Reader:
    def __init__(self, tokens: list[Token]) -> None:
        self.tokens = tokens
        self.position = 0
        self.depth = 0

    # -- moving about

    @property
    def token(self) -> Token:
        return self.tokens[self.position]

    def peek(self, ahead: int = 1) -> Token:
        index = min(self.position + ahead, len(self.tokens) - 1)
        return self.tokens[index]

    def at(self, text: str) -> bool:
        token = self.token
        return token.kind in (OP, IDENT) and token.text == text

    def take(self) -> Token:
        token = self.token
        if token.kind != END:
            self.position += 1
        return token

    def expect(self, text: str) -> Token:
        if not self.at(text):
            raise SyntaxProblem(
                f"expected {text!r} on line {self.token.line}, found {self.token.text!r}"
            )
        return self.take()

    def accept(self, text: str) -> bool:
        if self.at(text):
            self.take()
            return True
        return False

    def identifier(self) -> str:
        token = self.token
        if token.kind != IDENT:
            raise SyntaxProblem(f"expected a name on line {token.line}, found {token.text!r}")
        self.take()
        return token.text

    def skip_balanced(self, opening: str, closing: str) -> None:
        """From an opening bracket to just past its partner."""
        self.expect(opening)
        level = 1
        while level:
            token = self.take()
            if token.kind == END:
                raise SyntaxProblem("unbalanced brackets")
            if token.kind == OP and token.text == opening:
                level += 1
            elif token.kind == OP and token.text == closing:
                level -= 1

    def enter(self) -> None:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise SyntaxProblem("nested too deeply")

    def leave(self) -> None:
        self.depth -= 1

    # -- annotations and types

    def annotations(self) -> list[str]:
        found: list[str] = []
        while self.at("@") and not (self.peek().kind == IDENT and self.peek().text == "interface"):
            self.take()
            found.append(self.qualified_name())
            if self.at("("):
                self.skip_balanced("(", ")")
        return found

    def qualified_name(self) -> str:
        parts = [self.identifier()]
        while self.at(".") and self.peek().kind == IDENT:
            self.take()
            parts.append(self.identifier())
        return ".".join(parts)

    def type_arguments(self) -> None:
        """Past `<...>`, where `>>` may close two at once."""
        self.expect("<")
        level = 1
        while level:
            token = self.take()
            if token.kind == END or (
                token.kind == OP and token.text in {";", "{", "}", "(", ")", "="}
            ):
                raise SyntaxProblem("not type arguments")
            if token.kind == OP and token.text == "<":
                level += 1
            elif token.kind == OP and token.text == ">":
                level -= 1

    def type_name(self) -> str:
        """A type, as its dotted name with arguments left out: `java.util.List`."""
        self.annotations()
        parts = [self.identifier()]
        if self.at("<"):
            self.type_arguments()
        while self.at(".") and (self.peek().kind == IDENT or self.peek().text == "@"):
            self.take()
            self.annotations()
            parts.append(self.identifier())
            if self.at("<"):
                self.type_arguments()
        name = ".".join(parts)
        self.annotations()
        while self.at("[") and self.peek().text == "]":
            self.take()
            self.take()
            name += "[]"
            self.annotations()
        if self.at("..."):
            self.take()
            name += "[]"
        return name

    def try_type_then_name(self) -> tuple[str, str] | None:
        """If a declaration starts here, its type and first name; else nothing moves."""
        saved = self.position
        try:
            while self.token.kind == IDENT and self.token.text in ("final",):
                self.take()
            self.annotations()
            if self.token.kind != IDENT or self.token.text in STATEMENT_KEYWORDS:
                raise SyntaxProblem("not a type")
            type_name = self.type_name()
            if self.token.kind != IDENT or self.token.text in STATEMENT_KEYWORDS:
                raise SyntaxProblem("not a declaration")
            following = self.peek()
            if following.kind == OP and following.text in {"=", ";", ",", "[", ":"}:
                return type_name, self.identifier()
            raise SyntaxProblem("not a declaration")
        except SyntaxProblem:
            self.position = saved
            return None

    # -- a compilation unit

    def unit(self) -> CompilationUnit:
        classes: list[ClassDecl] = []
        while self.token.kind != END:
            if self.at("package") or self.at("import"):
                while not self.at(";") and self.token.kind != END:
                    self.take()
                self.accept(";")
                continue
            if self.at(";"):
                self.take()
                continue
            declared = self.maybe_class(None)
            if declared is None:
                self.take()  # something at the top level we do not follow
            else:
                classes.append(declared)
        return CompilationUnit(classes)

    def modifiers(self) -> set[str]:
        found: set[str] = set()
        while True:
            self.annotations()
            token = self.token
            if token.kind == IDENT and token.text in MODIFIERS:
                found.add(token.text)
                self.take()
                continue
            if token.kind == IDENT and token.text == "non" and self.peek().text == "-":
                self.take()
                self.take()
                self.take()
                continue
            return found

    def maybe_class(self, outer: ClassDecl | None) -> ClassDecl | None:
        saved = self.position
        self.modifiers()
        if self.at("@") and self.peek().text == "interface":
            self.take()
        if not (self.token.kind == IDENT and self.token.text in TYPE_KEYWORDS):
            self.position = saved
            return None
        # `record` and `enum` are also ordinary names: `record.put(k, v)`.
        following = self.peek()
        if following.kind != IDENT or (
            self.token.text == "record" and self.peek(2).text not in ("(", "<")
        ):
            self.position = saved
            return None
        kind = self.take().text
        name = self.identifier()
        supertypes: list[str] = []
        if self.at("<"):
            self.type_arguments()
        if kind == "record" and self.at("("):
            self.skip_balanced("(", ")")
        while self.token.kind == IDENT and self.token.text in ("extends", "implements", "permits"):
            self.take()
            supertypes.append(self.type_name().split(".")[-1])
            while self.accept(","):
                supertypes.append(self.type_name().split(".")[-1])
        declared = ClassDecl(name, kind, tuple(supertypes), outer=outer)
        if kind in ("enum", "record"):
            self.skip_balanced("{", "}")
            return declared
        self.class_body(declared)
        return declared

    def class_body(self, declared: ClassDecl) -> None:
        self.expect("{")
        while not self.at("}"):
            if self.token.kind == END:
                raise SyntaxProblem("class body never closed")
            if self.at(";"):
                self.take()
                continue
            self.member(declared)
        self.expect("}")

    def member(self, declared: ClassDecl) -> None:
        start = self.position
        nested = self.maybe_class(declared)
        if nested is not None:
            declared.nested.append(nested)
            return
        self.position = start
        modifiers = self.modifiers()
        if self.at("{"):  # an initialiser block
            self.skip_balanced("{", "}")
            return
        if self.at("<"):  # a generic method
            self.type_arguments()
        line = self.token.line
        # A constructor: the class's own name, then a parameter list.
        if (
            self.token.kind == IDENT
            and self.token.text == declared.name
            and self.peek().text == "("
        ):
            self.take()
            self.method_rest(declared, declared.name, modifiers, line, constructor=True)
            return
        type_name = self.type_name()
        name = self.identifier()
        if self.at("("):
            self.method_rest(declared, name, modifiers, line)
            return
        # One or more fields.
        while True:
            while self.at("[") and self.peek().text == "]":
                self.take()
                self.take()
            value = None
            if self.accept("="):
                value = self.initialiser_or_opaque()
            declared.fields[name] = FieldDecl(
                name, type_name, value, "static" in modifiers, "final" in modifiers, line
            )
            if not self.accept(","):
                break
            line = self.token.line
            name = self.identifier()
        self.expect(";")

    def initialiser_or_opaque(self) -> Node:
        saved = self.position
        try:
            return self.variable_initialiser()
        except SyntaxProblem:
            self.position = saved
            line = self.token.line
            level = 0
            while not (level == 0 and (self.at(";") or self.at(","))):
                token = self.take()
                if token.kind == END:
                    raise
                if token.kind == OP and token.text in "({[":
                    level += 1
                elif token.kind == OP and token.text in ")}]":
                    level -= 1
            return Opaque(line)

    def method_rest(
        self,
        declared: ClassDecl,
        name: str,
        modifiers: set[str],
        line: int,
        *,
        constructor: bool = False,
    ) -> None:
        parameters = self.parameters()
        while self.at("[") and self.peek().text == "]":
            self.take()
            self.take()
        if self.accept("throws"):
            self.type_name()
            while self.accept(","):
                self.type_name()
        if self.accept("default"):  # an annotation member's default
            while not self.at(";"):
                self.take()
        method = Method(
            name, parameters, None, line, line, declared, "static" in modifiers, constructor
        )
        if self.accept(";"):
            declared.methods.append(method)
            return
        body_start = self.position
        try:
            method.body = self.block()
        except SyntaxProblem:
            # The body could not be read: skip it whole, and say so.
            self.position = body_start
            self.skip_balanced("{", "}")
            method.readable = False
        method.last_line = self.tokens[self.position - 1].line
        declared.methods.append(method)

    def parameters(self) -> tuple[Parameter, ...]:
        self.expect("(")
        found: list[Parameter] = []
        while not self.at(")"):
            annotations: list[str] = []
            while True:
                annotations.extend(self.annotations())
                if self.at("final"):
                    self.take()
                    continue
                break
            type_name = self.type_name()
            if self.at("this"):  # a receiver parameter
                self.take()
                self.accept(",")
                continue
            name = self.identifier()
            while self.at("[") and self.peek().text == "]":
                self.take()
                self.take()
                type_name += "[]"
            found.append(Parameter(type_name, name, tuple(annotations)))
            if not self.accept(","):
                break
        self.expect(")")
        return tuple(found)

    # -- statements

    def block(self) -> Block:
        line = self.expect("{").line
        body: list[Node] = []
        while not self.at("}"):
            if self.token.kind == END:
                raise SyntaxProblem("block never closed")
            body.append(self.statement())
        self.expect("}")
        return Block(line, tuple(body))

    def statement(self) -> Node:
        self.enter()
        try:
            return self._statement()
        finally:
            self.leave()

    def _statement(self) -> Node:
        token = self.token
        line = token.line
        if self.at("{"):
            return self.block()
        if self.at(";"):
            self.take()
            return Skip(line)
        if self.at("@") or (
            token.kind == IDENT and token.text in TYPE_KEYWORDS | {"abstract", "final", "static"}
        ):
            saved = self.position
            if self.maybe_class(None) is not None:
                return Skip(line)  # a local class: not followed
            self.position = saved
        if (
            token.kind == IDENT
            and self.peek().text == ":"
            and token.text not in ("default", "case")
        ):
            self.take()
            self.take()  # a label
            return self.statement()
        if token.kind == IDENT:
            keyword = token.text
            if keyword == "if":
                self.take()
                test = self.parenthesised()
                then = self.statement()
                otherwise = self.statement() if self.accept("else") else None
                return If(line, test, then, otherwise)
            if keyword == "while":
                self.take()
                test = self.parenthesised()
                return While(line, test, self.statement())
            if keyword == "do":
                self.take()
                body = self.statement()
                self.expect("while")
                test = self.parenthesised()
                self.expect(";")
                return While(line, test, body, do=True)
            if keyword == "for":
                return self.for_statement()
            if keyword == "try":
                return self.try_statement()
            if keyword == "switch" and self.peek().text == "(":
                return self.switch_statement()
            if keyword == "return":
                self.take()
                value = None if self.at(";") else self.expression()
                self.expect(";")
                return Return(line, value)
            if keyword in ("break", "continue"):
                self.take()
                if self.token.kind == IDENT:
                    self.take()
                self.expect(";")
                return Jump(line, keyword)
            if keyword == "throw":
                self.take()
                value = self.expression()
                self.expect(";")
                return Jump(line, "throw", value)
            if keyword == "yield" and self.peek().kind != OP:
                self.take()
                value = self.expression()
                self.expect(";")
                return Return(line, value)
            if keyword == "synchronized" and self.peek().text == "(":
                self.take()
                self.parenthesised()
                return self.block()
            if keyword == "assert":
                while not self.at(";"):
                    self.take()
                self.take()
                return Skip(line)
        declaration = self.local_declaration(require_semicolon=True)
        if declaration is not None:
            return declaration
        expression = self.expression()
        self.expect(";")
        return ExpressionStatement(line, expression)

    def local_declaration(self, *, require_semicolon: bool) -> Local | None:
        line = self.token.line
        started = self.try_type_then_name()
        if started is None:
            return None
        type_name, name = started
        names: list[tuple[str, int, Node | None]] = []
        while True:
            dimensions = 0
            while self.at("[") and self.peek().text == "]":
                self.take()
                self.take()
                dimensions += 1
            value = self.variable_initialiser() if self.accept("=") else None
            names.append((name, dimensions, value))
            if not self.accept(","):
                break
            name = self.identifier()
        if require_semicolon:
            self.expect(";")
        return Local(line, type_name, tuple(names))

    def variable_initialiser(self) -> Node:
        if self.at("{"):
            return self.array_initialiser()
        return self.expression()

    def array_initialiser(self) -> ArrayInit:
        line = self.expect("{").line
        items: list[Node] = []
        while not self.at("}"):
            items.append(self.variable_initialiser())
            if not self.accept(","):
                break
        self.expect("}")
        return ArrayInit(line, tuple(items))

    def parenthesised(self) -> Node:
        self.expect("(")
        value = self.expression()
        self.expect(")")
        return value

    def for_statement(self) -> Node:
        line = self.take().line
        self.expect("(")
        saved = self.position
        started = self.try_type_then_name()
        if started is not None and self.at(":"):
            self.take()
            iterable = self.expression()
            self.expect(")")
            return ForEach(line, started[0], started[1], iterable, self.statement())
        self.position = saved
        init: list[Node] = []
        if not self.at(";"):
            declaration = self.local_declaration(require_semicolon=False)
            if declaration is not None:
                init.append(declaration)
            else:
                init.append(ExpressionStatement(line, self.expression()))
                while self.accept(","):
                    init.append(ExpressionStatement(line, self.expression()))
        self.expect(";")
        test = None if self.at(";") else self.expression()
        self.expect(";")
        update: list[Node] = []
        while not self.at(")"):
            update.append(ExpressionStatement(line, self.expression()))
            if not self.accept(","):
                break
        self.expect(")")
        return For(line, tuple(init), test, tuple(update), self.statement())

    def try_statement(self) -> Node:
        line = self.take().line
        resources: list[Node] = []
        if self.accept("("):
            while not self.at(")"):
                declaration = self.local_declaration(require_semicolon=False)
                if declaration is None:
                    resources.append(ExpressionStatement(self.token.line, self.expression()))
                else:
                    resources.append(declaration)
                if not self.accept(";"):
                    break
            self.expect(")")
        body = self.block()
        catches: list[Catch] = []
        while self.at("catch"):
            catch_line = self.take().line
            self.expect("(")
            self.modifiers()
            type_name = self.type_name()
            while self.accept("|"):
                self.type_name()
            name = self.identifier()
            self.expect(")")
            catches.append(Catch(catch_line, type_name, name, self.block()))
        finally_ = self.block() if self.accept("finally") else None
        return Try(line, tuple(resources), body, tuple(catches), finally_)

    def switch_statement(self) -> Node:
        line = self.take().line
        subject = self.parenthesised()
        self.expect("{")
        cases: list[Case] = []
        while not self.at("}"):
            case_line = self.token.line
            labels: tuple[Node, ...] | None
            if self.accept("default"):
                labels = None
            else:
                self.expect("case")
                found = [self.ternary()]
                while self.accept(","):
                    found.append(self.ternary())
                labels = tuple(found)
            if self.accept("->"):
                if self.at("{"):
                    body: tuple[Node, ...] = (self.block(),)
                else:
                    body = (self.statement(),)
                cases.append(Case(case_line, labels, body, arrow=True))
                continue
            self.expect(":")
            statements: list[Node] = []
            while not (self.at("case") or self.at("default") or self.at("}")):
                if self.token.kind == END:
                    raise SyntaxProblem("switch never closed")
                statements.append(self.statement())
            cases.append(Case(case_line, labels, tuple(statements)))
        self.expect("}")
        return Switch(line, subject, tuple(cases))

    # -- expressions

    def expression(self) -> Node:
        self.enter()
        try:
            return self.assignment()
        finally:
            self.leave()

    def assignment(self) -> Node:
        if self.lambda_ahead():
            return self.skip_lambda()
        left = self.ternary()
        token = self.token
        if token.kind == OP and token.text in ASSIGNMENT_OPS:
            self.take()
            value = self.variable_initialiser() if self.at("{") else self.assignment()
            return Assign(token.line, token.text, left, value)
        return left

    def lambda_ahead(self) -> bool:
        token = self.token
        if token.kind == IDENT and self.peek().text == "->":
            return True
        if not self.at("("):
            return False
        level = 0
        index = self.position
        while index < len(self.tokens):
            current = self.tokens[index]
            if current.kind == END:
                return False
            if current.kind == OP and current.text == "(":
                level += 1
            elif current.kind == OP and current.text == ")":
                level -= 1
                if level == 0:
                    following = self.tokens[index + 1] if index + 1 < len(self.tokens) else current
                    return following.kind == OP and following.text == "->"
            index += 1
        return False

    def skip_lambda(self) -> Node:
        line = self.token.line
        if self.at("("):
            self.skip_balanced("(", ")")
        else:
            self.take()
        self.expect("->")
        if self.at("{"):
            self.skip_balanced("{", "}")
        else:
            self.expression()
        return Opaque(line)

    def ternary(self) -> Node:
        test = self.binary(1)
        if self.at("?"):
            line = self.take().line
            then = self.ternary() if not self.lambda_ahead() else self.skip_lambda()
            self.expect(":")
            otherwise = self.ternary() if not self.lambda_ahead() else self.skip_lambda()
            return Conditional(line, test, then, otherwise)
        return test

    def binary_operator(self) -> str | None:
        token = self.token
        if token.kind == IDENT and token.text == "instanceof":
            return "instanceof"
        if token.kind != OP:
            return None
        if token.text in ("<", ">"):
            # `>>` and `>>>` come as separate `>` tokens with nothing between.
            if token.text == ">" and self.peek().text == ">" and self.peek().start == token.end:
                third = self.peek(2)
                if third.text == ">" and third.start == self.peek().end:
                    return ">>>"
                return ">>"
            if token.text == "<" and self.peek().text == "<" and self.peek().start == token.end:
                return "<<"
            return token.text
        return token.text if token.text in BINARY_PRECEDENCE else None

    def binary(self, minimum: int) -> Node:
        left = self.unary()
        while True:
            op = self.binary_operator()
            if op is None or BINARY_PRECEDENCE[op] < minimum:
                return left
            line = self.token.line
            for _ in range({">>": 2, "<<": 2, ">>>": 3}.get(op, 1)):
                self.take()
            if op == "instanceof":
                self.accept("final")
                type_name = self.type_name()
                if self.token.kind == IDENT and self.token.text not in STATEMENT_KEYWORDS:
                    self.take()  # a pattern variable
                left = InstanceOf(line, left, type_name)
                continue
            right = self.binary(BINARY_PRECEDENCE[op] + 1)
            left = Binary(line, op, left, right, self.tokens[self.position - 1].line)

    def unary(self) -> Node:
        token = self.token
        if token.kind == OP and token.text in ("+", "-", "!", "~", "++", "--"):
            self.take()
            return Unary(token.line, token.text, self.unary())
        if self.at("(") and self.cast_ahead():
            self.take()
            type_name = self.type_name()
            while self.accept("&"):
                self.type_name()
            self.expect(")")
            if self.lambda_ahead():
                return Cast(token.line, type_name, self.skip_lambda())
            return Cast(token.line, type_name, self.unary())
        return self.postfix(self.primary())

    def cast_ahead(self) -> bool:
        saved = self.position
        try:
            self.take()
            if self.token.kind != IDENT or self.token.text in STATEMENT_KEYWORDS:
                return False
            self.type_name()
            while self.accept("&"):
                self.type_name()
            if not self.at(")"):
                return False
            following = self.peek()
            if following.kind in (IDENT, STRING, CHAR, NUMBER):
                return following.text != "instanceof"
            return following.kind == OP and following.text in ("(", "!", "~")
        except SyntaxProblem:
            return False
        finally:
            self.position = saved

    def arguments(self) -> tuple[Node, ...]:
        self.expect("(")
        found: list[Node] = []
        while not self.at(")"):
            found.append(self.expression())
            if not self.accept(","):
                break
        self.expect(")")
        return tuple(found)

    def postfix(self, node: Node) -> Node:
        while True:
            token = self.token
            if self.at("."):
                self.take()
                if self.at("<"):
                    self.type_arguments()
                if self.at("new"):  # inner.new Inner()
                    node = self.primary()
                    continue
                name = self.identifier()
                if self.at("("):
                    args = self.arguments()
                    node = Call(token.line, node, name, args, self.tokens[self.position - 1].line)
                else:
                    node = Field(token.line, node, name)
            elif self.at("["):
                self.take()
                index = self.expression()
                self.expect("]")
                node = Index(token.line, node, index)
            elif self.at("++") or self.at("--"):
                self.take()
                node = Unary(token.line, token.text, node, postfix=True)
            elif self.at("::"):
                self.take()
                self.take()
                node = Opaque(token.line)
            else:
                return node

    def primary(self) -> Node:
        token = self.token
        line = token.line
        if token.kind == STRING:
            self.take()
            return Literal(line, token.value)
        if token.kind == CHAR:
            self.take()
            return Literal(line, token.value, is_char=True)
        if token.kind == NUMBER:
            self.take()
            return Literal(line, token.value)
        if self.at("("):
            self.take()
            value = self.expression()
            self.expect(")")
            return value
        if token.kind != IDENT:
            raise SyntaxProblem(f"unexpected {token.text!r} on line {line}")
        word = token.text
        if word == "true" or word == "false":
            self.take()
            return Literal(line, word == "true")
        if word == "null":
            self.take()
            return Literal(line, None)
        if word == "new":
            return self.creation()
        if word == "switch" and self.peek().text == "(":
            self.take()
            self.skip_balanced("(", ")")
            self.skip_balanced("{", "}")
            return Opaque(line)
        self.take()
        if self.at("("):
            args = self.arguments()
            return Call(line, None, word, args, self.tokens[self.position - 1].line)
        if self.at("[") and self.peek().text == "]":
            # `String[].class` or `String[]::new`
            while self.at("[") and self.peek().text == "]":
                self.take()
                self.take()
            if self.accept("::"):
                self.take()
            else:
                self.expect(".")
                self.expect("class")
            return Opaque(line)
        if self.at("<") and self.generic_type_ahead():
            # `List<String>::new` or a generic type in an expression
            self.type_arguments()
        return Name(line, word)

    def generic_type_ahead(self) -> bool:
        saved = self.position
        try:
            self.type_arguments()
            return self.at("::")
        except SyntaxProblem:
            return False
        finally:
            self.position = saved

    def creation(self) -> Node:
        line = self.expect("new").line
        self.annotations()
        if self.at("<"):
            self.type_arguments()
        parts = [self.identifier()]
        if self.at("<"):
            self.type_arguments()
        while self.at("."):
            self.take()
            self.annotations()
            parts.append(self.identifier())
            if self.at("<"):
                self.type_arguments()
        type_name = ".".join(parts)
        if self.at("["):
            dimensions = 0
            while self.at("["):
                self.take()
                if not self.at("]"):
                    self.expression()
                self.expect("]")
                dimensions += 1
            if self.at("{"):
                return NewArray(line, type_name, self.array_initialiser().items)
            return NewArray(line, type_name, None)
        args = self.arguments()
        last_line = self.tokens[self.position - 1].line
        if self.at("{"):
            self.skip_balanced("{", "}")
            return New(line, type_name, args, anonymous=True, last_line=last_line)
        return New(line, type_name, args, last_line=last_line)


def parse(source: str) -> CompilationUnit:
    """The classes in a Java file. Raises :class:`SyntaxProblem` if it cannot be read."""
    reader = Reader(tokenize(source))
    try:
        return reader.unit()
    except RecursionError as error:  # pragma: no cover - MAX_DEPTH comes first
        raise SyntaxProblem("nested too deeply") from error
