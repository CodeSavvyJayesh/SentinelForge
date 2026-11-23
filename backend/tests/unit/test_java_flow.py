"""Java data flow: request data to the calls it can attack, and constants that cannot.

Every test is a small servlet or controller. The ones that expect nothing are
as important as the ones that expect a finding: they are the reasons a value
is *not* request data, or is known to be constant.
"""

from pathlib import Path

import pytest

from app.analysis import java_flow
from app.analysis.java_analysis import analyze_java, build_project, may_read_request

SERVLET = """
import javax.servlet.http.*;
public class T extends HttpServlet {{
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {{
        String param = request.getParameter("p");
        {body}
    }}
    {members}
}}
"""


def rules(body: str, members: str = "", *, others: dict[str, str] | None = None) -> list[str]:
    return [finding.rule_id for finding in findings(body, members, others=others)]


def findings(body: str, members: str = "", *, others: dict[str, str] | None = None) -> list:
    source = SERVLET.format(body=body, members=members)
    project = build_project([("T.java", source), *(others or {}).items()])
    return analyze_java(source, "T.java", ".java", project)


def line_of(text: str, body: str, members: str = "") -> int:
    source = SERVLET.format(body=body, members=members)
    return next(number for number, line in enumerate(source.splitlines(), start=1) if text in line)


# --- where request data comes from ----------------------------------------------


@pytest.mark.parametrize(
    "read",
    [
        'request.getParameter("p")',
        'request.getHeader("h")',
        "request.getQueryString()",
        'request.getParameterValues("p")[0]',
        'request.getParameterMap().get("p")[0]',
        "request.getCookies()[0].getValue()",
        'java.net.URLDecoder.decode(request.getHeaders("h").nextElement(), "UTF-8")',
        "request.getParameterNames().nextElement()",
    ],
)
def test_every_way_of_reading_the_request_is_request_data(read: str) -> None:
    assert rules(f"String v = {read}; response.getWriter().println(v);") == ["JV011"]


def test_what_the_server_decides_is_not_request_data() -> None:
    body = "response.getWriter().println(request.getContextPath() + request.getMethod());"
    assert rules(body) == []


def test_a_spring_request_parameter_is_request_data() -> None:
    source = """
    @RestController class C {
        @GetMapping("/f") String f(@RequestParam("n") String name) throws Exception {
            java.nio.file.Path path = java.nio.file.Paths.get("/data", name);
            return new String(java.nio.file.Files.readAllBytes(path));
        }
    }
    """
    found = analyze_java(source, "C.java")
    # Where the path is made, and where the file is read with it.
    assert [(finding.rule_id, finding.line_start) for finding in found] == [
        ("JV008", 4),
        ("JV008", 5),
    ]


def test_a_parameter_of_unknown_origin_is_not_request_data() -> None:
    """Asserting it was would report every helper that takes a string."""
    source = (
        "class C { void f(String name, java.io.PrintWriter out) {"
        " new java.io.File(name).delete(); } }"
    )
    assert analyze_java(source, "C.java") == []


# --- what it can attack -------------------------------------------------------------


def test_a_command() -> None:
    # JV001 is the older pattern for the same line; the engine keeps the stronger of the two.
    assert rules('Runtime.getRuntime().exec("ls " + param);') == ["JV001", "JV007"]
    assert rules('Runtime r = Runtime.getRuntime(); r.exec(new String[] {"sh", "-c", param});') == [
        "JV007"
    ]
    assert rules('String[] env = {param}; Runtime.getRuntime().exec("ls", env);') == ["JV007"]


def test_a_process_builder() -> None:
    body = (
        "java.util.List<String> args = new java.util.ArrayList<String>();"
        ' args.add("echo"); args.add(param); new ProcessBuilder(args).start();'
    )
    assert rules(body) == ["JV007"]
    assert rules('ProcessBuilder pb = new ProcessBuilder(); pb.command("echo", param);') == [
        "JV007"
    ]


def test_a_file_path() -> None:
    assert rules('new java.io.File("/tmp", param).delete();') == ["JV008"]
    assert rules("new java.io.FileInputStream(param).close();") == ["JV008"]
    assert rules('java.nio.file.Files.newInputStream(java.nio.file.Paths.get("/d/" + param));') == [
        "JV008"
    ]


def test_copying_uploaded_content_to_a_fixed_path_is_not_a_path_problem() -> None:
    body = (
        'java.nio.file.Files.copy(request.getInputStream(), java.nio.file.Paths.get("/up/a.bin"));'
    )
    assert rules(body) == []
    body = (
        'java.nio.file.Files.copy(request.getInputStream(), java.nio.file.Paths.get("/up", param));'
    )
    assert "JV008" in rules(body)


def test_an_ldap_filter_and_its_arguments() -> None:
    joined = (
        "javax.naming.directory.DirContext ctx = connect();"
        ' ctx.search("ou=users", "(uid=" + param + ")", null);'
    )
    assert rules(joined) == ["JV009"]
    bound = (
        "javax.naming.directory.DirContext ctx = connect();"
        ' ctx.search("ou=users", "(uid={0})", new Object[] {param}, null);'
    )
    assert rules(bound) == [], "a filter argument is escaped by the directory"


def test_an_xpath_expression() -> None:
    body = (
        "javax.xml.xpath.XPath xp = javax.xml.xpath.XPathFactory.newInstance().newXPath();"
        ' xp.evaluate("/u[@n=\'" + param + "\']", doc);'
    )
    assert rules(body) == ["JV010"]


def test_the_response_page() -> None:
    assert rules('response.getWriter().write("<p>" + param);') == ["JV011"]
    assert rules("java.io.PrintWriter out = response.getWriter(); out.format(param, 1);") == [
        "JV011"
    ]
    assert rules('response.getWriter().printf("%s", new Object[] {"a", param});') == ["JV011"]


def test_the_session() -> None:
    assert rules('request.getSession().setAttribute("k", param);') == ["JV012"]
    assert rules(
        'javax.servlet.http.HttpSession s = request.getSession(); s.putValue(param, "v");'
    ) == ["JV012"]


def test_a_print_to_something_other_than_the_response_is_not_xss() -> None:
    assert rules("System.out.println(param);") == []


# --- what makes request data safe ---------------------------------------------------


@pytest.mark.parametrize(
    "escape",
    [
        "org.owasp.esapi.ESAPI.encoder().encodeForHTML(param)",
        "org.springframework.web.util.HtmlUtils.htmlEscape(param)",
        "org.apache.commons.lang.StringEscapeUtils.escapeHtml(param)",
        "org.owasp.encoder.Encode.forHtml(param)",
    ],
)
def test_html_escaping_makes_it_safe_for_the_page(escape: str) -> None:
    assert rules(f"response.getWriter().println({escape});") == []


def test_escaping_for_one_place_is_not_escaping_for_another() -> None:
    body = (
        "String safe = org.owasp.esapi.ESAPI.encoder().encodeForHTML(param);"
        " response.getWriter().println(safe); new java.io.File(safe).delete();"
    )
    assert rules(body) == ["JV008"]


def test_joining_escaped_and_unescaped_text_is_not_escaped() -> None:
    body = (
        "response.getWriter().println("
        "org.springframework.web.util.HtmlUtils.htmlEscape(param) + param);"
    )
    assert rules(body) == ["JV011"]


# --- constants the walk can see through ---------------------------------------------


def test_a_map_entry_put_under_another_key() -> None:
    template = (
        "java.util.HashMap<String, Object> m = new java.util.HashMap<String, Object>();"
        ' m.put("keyA", "a_Value"); m.put("keyB", param);'
        ' String bar = (String) m.get("{key}"); response.getWriter().println(bar);'
    )
    assert rules(template.replace("{key}", "keyA")) == []
    assert rules(template.replace("{key}", "keyB")) == ["JV011"]


def test_a_list_with_an_element_removed() -> None:
    template = (
        "java.util.List<String> l = new java.util.ArrayList<String>();"
        ' l.add("safe"); l.add(param); l.add("moresafe"); l.remove(0);'
        " response.getWriter().println(l.get({index}));"
    )
    assert rules(template.replace("{index}", "1")) == []
    assert rules(template.replace("{index}", "0")) == ["JV011"]


@pytest.mark.parametrize(("number", "expected"), [(106, []), (60, ["JV011"])])
def test_a_condition_decided_by_arithmetic(number: int, expected: list[str]) -> None:
    body = (
        f"int num = {number};"
        ' String bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;'
        " response.getWriter().println(bar);"
    )
    assert rules(body) == expected


def test_an_if_decided_by_arithmetic() -> None:
    body = (
        'String bar; int num = 86; if ((7 * 42) - num > 200) bar = "always"; else bar = param;'
        " response.getWriter().println(bar);"
    )
    assert rules(body) == []


@pytest.mark.parametrize(("position", "expected"), [(1, []), (0, ["JV011"]), (2, ["JV011"])])
def test_a_switch_on_a_known_character(position: int, expected: list[str]) -> None:
    body = (
        f'String bar; String guess = "ABC"; char target = guess.charAt({position});'
        " switch (target) { case 'A': bar = param; break; case 'B': bar = \"bob\"; break;"
        " case 'C': case 'D': bar = param; break; default: bar = \"x\"; break; }"
        " response.getWriter().println(bar);"
    )
    assert rules(body) == expected


def test_a_switch_on_something_unknown_takes_every_branch() -> None:
    body = (
        'String bar = "x"; switch (param.length()) {'
        ' case 1: bar = param; break; default: bar = "y"; }'
        " response.getWriter().println(bar);"
    )
    assert rules(body) == ["JV011"]


def test_a_string_builder_keeps_what_was_appended() -> None:
    body = (
        'StringBuilder b = new StringBuilder("a"); b.append(param);'
        " response.getWriter().println(b.toString());"
    )
    assert rules(body) == ["JV011"]


def test_a_loop_that_reads_a_cookie() -> None:
    body = (
        'String v = "none"; javax.servlet.http.Cookie[] cs = request.getCookies();'
        " for (javax.servlet.http.Cookie c : cs) {"
        ' if (c.getName().equals("x")) { v = c.getValue(); break; } }'
        " response.getWriter().println(v);"
    )
    assert rules(body) == ["JV011"]


def test_a_property_set_on_an_object_is_given_back_by_its_own_getter_only() -> None:
    body = (
        'javax.servlet.http.Cookie k = new javax.servlet.http.Cookie("name", "value");'
        " k.setPath(request.getRequestURI());"
        " response.getWriter().println(k.getName());"
    )
    assert rules(body) == []
    assert rules(body.replace("k.getName()", "k.getPath()")) == ["JV011"]


# --- calls into other methods and files ------------------------------------------------


def test_a_method_in_the_same_class_is_followed() -> None:
    members = (
        "private static String pass(String s) { return s; }"
        ' private static String fixed(String s) { return "k"; }'
    )
    assert rules("response.getWriter().println(pass(param));", members) == ["JV011"]
    assert rules("response.getWriter().println(fixed(param));", members) == []


def test_an_inner_class_is_followed() -> None:
    members = (
        "private class Test { public String doSomething(HttpServletRequest r, String p) {"
        ' String bar = "safe!"; return bar; } }'
    )
    assert (
        rules("response.getWriter().println(new Test().doSomething(request, param));", members)
        == []
    )


def test_an_interface_is_followed_to_every_class_that_implements_it() -> None:
    others = {
        "Thing.java": "public interface Thing { String doSomething(String i); }",
        "ThingOne.java": (
            "public class ThingOne implements Thing {"
            " public String doSomething(String i) { return i; } }"
        ),
        "ThingTwo.java": (
            "public class ThingTwo implements Thing {"
            " public String doSomething(String i) { return new StringBuilder(i).toString(); } }"
        ),
        "Factory.java": (
            "public class Factory { public static Thing make() { return new ThingOne(); } }"
        ),
    }
    tainted = "Thing t = Factory.make(); response.getWriter().println(t.doSomething(param));"
    constant = (
        'Thing t = Factory.make(); String g = "static";'
        " response.getWriter().println(t.doSomething(g));"
    )
    assert rules(tainted, others=others) == ["JV011"]
    assert rules(constant, others=others) == []


def test_a_wrapper_that_keeps_the_request_in_a_field() -> None:
    others = {
        "Wrapper.java": """
        public class Wrapper {
            private HttpServletRequest request;
            public Wrapper(HttpServletRequest request) { this.request = request; }
            public String getTheParameter(String p) { return request.getParameter(p); }
            public String getTheValue(String p) { return "bar"; }
        }
        """
    }
    read = 'Wrapper w = new Wrapper(request); response.getWriter().println(w.{call}("x"));'
    assert rules(read.replace("{call}", "getTheParameter"), others=others) == ["JV011"]
    assert rules(read.replace("{call}", "getTheValue"), others=others) == []


def test_a_helper_with_a_sink_is_reported_when_called_with_request_data() -> None:
    members = (
        "private void show(HttpServletResponse r, String s) throws Exception"
        " { r.getWriter().println(s); }"
    )
    found = findings("show(response, param);", members)
    assert [finding.rule_id for finding in found] == ["JV011"]
    assert found[0].line_start == line_of(
        "r.getWriter().println(s)", "show(response, param);", members
    )


def test_recursion_does_not_loop() -> None:
    members = 'private String r(String s) { return r(s + "x"); }'
    assert rules("response.getWriter().println(r(param));", members) == ["JV011"]


# --- SQL: reported where it is built, withdrawn when it is constant ---------------------


def test_a_query_built_from_request_data_is_reported_once() -> None:
    body = (
        'String sql = "SELECT * FROM users WHERE name = \'" + param + "\'";'
        " java.sql.Statement st = connect(); st.executeQuery(sql);"
    )
    found = findings(body)
    assert [finding.rule_id for finding in found] == ["SQL001"]
    assert found[0].line_start == line_of('String sql = "SELECT', body)


def test_a_query_built_from_a_constant_is_withdrawn() -> None:
    body = (
        'String bar = "safe!"; String sql = "SELECT * FROM users WHERE name = \'" + bar + "\'";'
        " java.sql.Statement st = connect(); st.executeQuery(sql);"
    )
    assert rules(body) == []


def test_a_query_built_from_a_static_constant_is_withdrawn() -> None:
    source = """
    class Repo {
        private static final String TABLE = "users";
        java.sql.ResultSet all(java.sql.Statement st) throws Exception {
            return st.executeQuery("SELECT * FROM " + TABLE + " WHERE active = 1");
        }
    }
    """
    assert analyze_java(source, "Repo.java") == []


def test_a_query_built_from_something_unknown_stays_reported() -> None:
    """Not request data, but not known to be constant either: the pattern's report stands."""
    source = """
    class Repo {
        java.sql.ResultSet find(java.sql.Statement st, String name) throws Exception {
            return st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
        }
    }
    """
    assert [finding.rule_id for finding in analyze_java(source, "Repo.java")] == ["SQL001"]


def test_a_query_in_a_file_the_reader_cannot_read_stays_reported() -> None:
    source = (
        'class Repo { void f() { String bar = "x";'
        ' String q = "SELECT * FROM t WHERE a = " + bar; ) }'
    )
    assert [finding.rule_id for finding in analyze_java(source, "Repo.java")] == ["SQL001"]


def test_a_query_in_a_method_the_reader_cannot_read_stays_reported() -> None:
    source = """
    class Repo {
        void f(Object o) {
            String bar = "x";
            String q = "SELECT * FROM t WHERE a = " + bar;
            switch (o) { case String s -> g(); default -> h(); }
        }
    }
    """
    assert [finding.rule_id for finding in analyze_java(source, "Repo.java")] == ["SQL001"]


def test_a_stored_procedure_call_is_reported_where_it_is_run() -> None:
    body = (
        'String sql = "{call " + param + "}";'
        " java.sql.Connection c = connect(); c.prepareCall(sql).execute();"
    )
    found = findings(body)
    assert [finding.rule_id for finding in found] == ["SQL001"]
    assert found[0].line_start == line_of("c.prepareCall(sql)", body)


def test_a_query_formatted_with_request_data_is_reported_where_it_is_run() -> None:
    body = (
        "String sql = String.format(\"SELECT * FROM t WHERE a = '%s'\", param);"
        " java.sql.Statement st = connect(); st.execute(sql);"
    )
    assert rules(body) == ["SQL001"]


def test_a_bound_parameter_is_not_reported() -> None:
    body = (
        'java.sql.PreparedStatement ps = connect().prepareStatement("SELECT * FROM t WHERE a = ?");'
        " ps.setString(1, param); ps.executeQuery();"
    )
    assert rules(body) == []


def test_a_query_through_spring_jdbc_template() -> None:
    body = (
        'String sql = "{call p(" + param + ")}";'
        " org.springframework.jdbc.core.JdbcTemplate jdbc = template(); jdbc.update(sql);"
    )
    assert rules(body) == ["SQL001"]


# --- the safety property and the budget --------------------------------------------------


def test_a_method_that_cannot_see_the_request_is_not_an_entry_point() -> None:
    source = """
    class Helper {
        void show(javax.servlet.http.HttpServletResponse response, String text) throws Exception {
            response.getWriter().println(text);
        }
        void handle(javax.servlet.http.HttpServletRequest request) { }
    }
    """
    assert analyze_java(source, "Helper.java") == []


def test_a_file_that_mentions_no_request_is_not_walked() -> None:
    source = "class A { void f(String s) throws Exception { new java.io.File(s).delete(); } }"
    assert not may_read_request(source)
    assert analyze_java(source, "A.java") == []


def test_a_walk_that_runs_out_of_budget_withdraws_nothing_and_adds_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(java_flow, "MAX_STEPS", 5)
    body = (
        'String bar = "safe"; String q = "SELECT * FROM t WHERE a = " + bar;'
        " response.getWriter().println(param);"
    )
    assert rules(body) == ["SQL001"]


def test_a_class_name_shared_by_many_files_is_not_followed() -> None:
    others = {
        f"T{index}.java": (
            f'public class Shared {{ public String get(String s) {{ return "{index}"; }} }}'
        )
        for index in range(java_flow.MAX_CANDIDATES + 1)
    }
    body = "Shared s = make(); response.getWriter().println(s.get(param));"
    assert rules(body, others=others) == ["JV011"], "not followed: the library assumption applies"


def test_files_are_parsed_only_when_needed() -> None:
    project = build_project(
        [
            ("T.java", SERVLET.format(body="response.getWriter().println(param);", members="")),
            ("Unused.java", "public class Unused { }"),
            ("Broken.java", "public class Broken { void f( }"),
        ]
    )
    analyze_java(project.sources["T.java"], "T.java", ".java", project)
    assert set(project.units) == {"T.java"}


def test_the_engine_follows_a_call_into_another_file(tmp_path: Path) -> None:
    from app.analysis.engine import analyze_workspace
    from app.core.config import get_settings

    (tmp_path / "Wrapper.java").write_text(
        "public class Wrapper { private HttpServletRequest request;"
        " public Wrapper(HttpServletRequest r) { this.request = r; }"
        " public String read(String p) { return request.getParameter(p); } }"
    )
    (tmp_path / "Page.java").write_text(
        SERVLET.format(
            body='Wrapper w = new Wrapper(request); response.getWriter().println(w.read("x"));',
            members="",
        )
    )
    result = analyze_workspace(tmp_path, get_settings())
    assert [(finding.rule_id, finding.file_path) for finding in result.findings] == [
        ("JV011", "Page.java")
    ]
    assert result.findings[0].analyzer == "java-flow"
