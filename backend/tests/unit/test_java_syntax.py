"""The Java reader: what it understands, and that it fails only in the one way it says."""

import contextlib
import random

import pytest

from app.analysis import java_syntax as js


def tokens(source: str) -> list[tuple[str, object]]:
    return [
        (token.kind, token.value if token.value is not None else token.text)
        for token in js.tokenize(source)
    ][:-1]


def method(source: str, name: str = "f") -> js.Method:
    unit = js.parse(source)
    for declared in unit.all_classes():
        for found in declared.methods:
            if found.name == name:
                return found
    raise AssertionError(f"no method {name}")


def body(statements: str) -> tuple[js.Node, ...]:
    found = method("class A { void f(String p) { " + statements + " } }")
    assert found.body is not None
    return found.body.body


# --- tokens -------------------------------------------------------------------


def test_string_escapes_are_decoded() -> None:
    assert tokens(r'"a\"b\nA"') == [(js.STRING, 'a"b\nA')]


def test_a_text_block_is_one_string() -> None:
    source = 'String s = """\n    SELECT *\n    FROM t""";'
    assert (js.STRING, "    SELECT *\n    FROM t") in tokens(source)


def test_comments_are_not_tokens() -> None:
    assert tokens("a /* b */ // c\n d") == [(js.IDENT, "a"), (js.IDENT, "d")]


def test_a_char_literal_is_one_character() -> None:
    assert tokens("'\\n' 'x'") == [(js.CHAR, "\n"), (js.CHAR, "x")]


def test_numbers_of_every_kind() -> None:
    assert [value for _, value in tokens("10 0x1F 0b101 1_000 2.5f 1e3 0x1p3 7L")] == [
        10,
        31,
        5,
        1000,
        2.5,
        1000.0,
        8.0,
        7,
    ]


def test_unicode_names_are_names() -> None:
    assert tokens("café") == [(js.IDENT, "café")]


def test_a_line_number_counts_lines_inside_strings_and_comments() -> None:
    found = js.tokenize('/*\n\n*/ "a" \n b')
    assert [token.line for token in found[:-1]] == [3, 4]


# --- declarations ----------------------------------------------------------------


def test_classes_methods_fields_and_nesting() -> None:
    unit = js.parse(
        """
        package p;
        import java.util.*;
        @SuppressWarnings("x")
        public class Outer extends Base implements Thing, Other<String> {
            private static final String NAME = "n";
            int a = 1, b;
            Outer(int a) { this.a = a; }
            public <T> List<T> pick(@RequestParam("q") final String q, String... rest)
                    throws Exception { return null; }
            abstract void later();
            static class Inner { void g() {} }
            enum Colour { RED, GREEN; void h() {} }
        }
        """
    )
    outer = unit.classes[0]
    assert outer.name == "Outer"
    assert outer.supertypes == ("Base", "Thing", "Other")
    assert set(outer.fields) == {"NAME", "a", "b"}
    assert outer.fields["NAME"].is_static and outer.fields["NAME"].is_final
    names = [found.name for found in outer.methods]
    assert names == ["Outer", "pick", "later"]
    assert outer.methods[0].is_constructor
    pick = outer.methods[1]
    assert [(p.type_name, p.name, p.annotations) for p in pick.parameters] == [
        ("String", "q", ("RequestParam",)),
        ("String[]", "rest", ()),
    ]
    assert outer.methods[2].body is None
    assert [nested.name for nested in outer.nested] == ["Inner", "Colour"]


def test_a_method_body_it_cannot_read_is_skipped_and_said_so() -> None:
    # A pattern in a switch label is newer Java than the reader follows.
    unit = js.parse(
        "class A { void f(Object o) { switch (o) { case String s -> x(); default -> y(); } }"
        " void g() { z(); } }"
    )
    first, second = unit.classes[0].methods
    assert not first.readable and first.body is None
    assert second.readable and second.body is not None


def test_record_and_enum_are_also_ordinary_names() -> None:
    statements = body("record.put(k, v); enum = 3;")
    assert isinstance(statements[0], js.ExpressionStatement)
    assert isinstance(statements[1].expression, js.Assign)  # type: ignore[attr-defined]


def test_annotations_inside_types_are_skipped() -> None:
    unit = js.parse(
        "class A { Class<?> @Nullable [] g() { return null; } void h(a.@Nullable B b) {} }"
    )
    assert [found.name for found in unit.classes[0].methods] == ["g", "h"]


def test_a_local_class_is_skipped_not_misread() -> None:
    statements = body('@SuppressWarnings("u") class Local { int x() { return 1; } } int y = 2;')
    assert isinstance(statements[0], js.Skip)
    assert isinstance(statements[1], js.Local)


# --- statements and expressions -------------------------------------------------------


def test_a_declaration_and_an_expression_are_told_apart() -> None:
    statements = body("java.util.List<String> a = x; a.b.c = 1; x[i] = 2; Map<K, List<V>> m;")
    assert isinstance(statements[0], js.Local) and statements[0].type_name == "java.util.List"
    assert isinstance(statements[1], js.ExpressionStatement)
    assert isinstance(statements[2], js.ExpressionStatement)
    assert isinstance(statements[3], js.Local) and statements[3].type_name == "Map"


def test_a_cast_and_a_parenthesised_value_are_told_apart() -> None:
    cast, plain = body("Object a = (String) m.get(k); int b = (x) + 1;")
    assert isinstance(cast, js.Local) and isinstance(cast.names[0][2], js.Cast)
    assert isinstance(plain, js.Local) and isinstance(plain.names[0][2], js.Binary)


def test_shift_and_generics_are_told_apart() -> None:
    (statement,) = body("int a = b >> 2 >>> 1;")
    value = statement.names[0][2]  # type: ignore[attr-defined]
    assert isinstance(value, js.Binary) and value.op == ">>>"
    assert isinstance(value.left, js.Binary) and value.left.op == ">>"


def test_precedence_of_arithmetic_and_comparison() -> None:
    (statement,) = body("boolean a = (7 * 18) + n > 200 && c;")
    value = statement.names[0][2]  # type: ignore[attr-defined]
    assert value.op == "&&"
    assert value.left.op == ">" and value.left.left.op == "+"


def test_lambdas_switch_expressions_and_anonymous_bodies_are_opaque() -> None:
    statements = body(
        "Runnable r = () -> { go(); }; int k = switch (x) { case 1 -> 2; default -> 3; };"
        " Object o = new Object() { public String toString() { return p; } };"
        " f(x -> x + 1, String::valueOf, String[]::new);"
    )
    assert isinstance(statements[0].names[0][2], js.Opaque)  # type: ignore[attr-defined]
    assert isinstance(statements[1].names[0][2], js.Opaque)  # type: ignore[attr-defined]
    created = statements[2].names[0][2]  # type: ignore[attr-defined]
    assert isinstance(created, js.New) and created.anonymous


def test_every_kind_of_statement() -> None:
    statements = body(
        """
        if (a) b(); else { c(); }
        while (x) { break; }
        do { continue; } while (y);
        for (int i = 0, j = 1; i < n; i++, j--) { }
        for (String s : list) { }
        try (InputStream in = open()) { r(); }
        catch (IOException | RuntimeException e) { } finally { }
        switch (k) { case 'A': case 'B': q(); break; default: w(); }
        switch (k) { case 1, 2 -> q(); default -> { w(); } }
        label: for (;;) { break label; }
        synchronized (this) { s(); }
        throw new RuntimeException("x");
        """
    )
    kinds = [type(statement).__name__ for statement in statements]
    assert kinds == [
        "If",
        "While",
        "While",
        "For",
        "ForEach",
        "Try",
        "Switch",
        "Switch",
        "For",
        "Block",
        "Jump",
    ]
    arrow = statements[7]
    assert all(case.arrow for case in arrow.cases)  # type: ignore[attr-defined]


def test_array_creation_and_initialisers() -> None:
    first, second, third = body(
        'String[] a = {p, "b"}; String[] b = new String[] {"x"}; int[][] c = new int[2][3];'
    )
    assert isinstance(first.names[0][2], js.ArrayInit)  # type: ignore[attr-defined]
    assert isinstance(second.names[0][2], js.NewArray)  # type: ignore[attr-defined]
    assert third.names[0][2].items is None  # type: ignore[attr-defined]


def test_a_spring_framework_style_file_reads() -> None:
    source = """
    @RestController
    public class Files {
        private final Path root;
        @GetMapping("/f/{name}")
        public ResponseEntity<byte[]> read(@PathVariable String name) throws IOException {
            var target = root.resolve(name).normalize();
            return ResponseEntity.ok(Files.readAllBytes(target));
        }
    }
    """
    found = method(source, "read")
    assert found.readable and found.parameters[0].annotations == ("PathVariable",)


# --- failure ------------------------------------------------------------------------


def test_too_large_a_file_is_refused_before_reading(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(js, "MAX_SOURCE", 10)
    with pytest.raises(js.SyntaxProblem):
        js.parse("class A { void f() {} }")


def test_deep_nesting_is_refused_not_a_crash() -> None:
    source = "class A { int f() { return " + "(" * 5000 + "1" + ")" * 5000 + "; } }"
    unit = js.parse(source)
    assert not unit.classes[0].methods[0].readable


SAMPLE = """
public class Sample extends HttpServlet {
    private static final String PREFIX = "/files/";
    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String param = request.getParameter("p");
        java.util.Map<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("a", param);
        String bar = (String) map.get("a");
        int num = 86;
        bar = (7 * 42) - num > 200 ? "safe" : bar;
        switch ("ABC".charAt(1)) { case 'A': bar = param; break; default: bar = "x"; }
        response.getWriter().printf(java.util.Locale.US, bar, new Object[] {"a", param});
    }
}
"""


def test_a_damaged_file_raises_only_the_readers_own_error() -> None:
    """Truncated and shuffled Java must never surface any other exception."""
    rng = random.Random(7)  # noqa: S311 - a repeatable choice of damage, not a secret
    for _ in range(300):
        cut = rng.randrange(len(SAMPLE))
        damaged = SAMPLE[:cut]
        if rng.random() < 0.5:
            pieces = SAMPLE.split()
            rng.shuffle(pieces)
            damaged = " ".join(pieces[: rng.randrange(len(pieces))])
        with contextlib.suppress(js.SyntaxProblem):
            js.parse(damaged)
