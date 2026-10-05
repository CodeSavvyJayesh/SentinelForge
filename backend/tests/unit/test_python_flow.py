"""Following a value through a function: what is known about each argument.

These tests ask the walk directly — "at this call, what is the first
argument?" — and expect one of three answers: request data reaches it
(``tainted``), it is built only from literals (``clean``), or neither could be
shown (``unknown``). The rules that turn those answers into findings are
tested in ``test_python_rules.py``.

The direction of every approximation is the thing under test. Where the walk
cannot tell, the answer has to be ``unknown`` or ``tainted``; a wrong ``clean``
is the one mistake that hides a vulnerability.
"""

import ast
import inspect
import operator
import sys
import textwrap
import time

import pytest

from app.analysis import python_flow as flow
from app.analysis import python_values as values
from app.analysis.python_values import (
    CLEAN,
    COMMAND,
    HTML,
    INPUT,
    OPAQUE,
    PATH,
    REDIRECT,
    SQL,
    TAINTED,
    UNKNOWN,
    XPATH,
    Taint,
    Value,
    classify,
    join,
)

FLASK = "from flask import request\nimport os\n\n"


def reaching(source: str, kind: str = COMMAND, call: str = "sink", index: int = 0) -> str:
    """How dangerous the argument of the (last) call to ``call`` is."""
    tree = ast.parse(textwrap.dedent(source))
    observed = flow.analyse(tree)
    assert observed.complete
    seen = [item for item in observed.calls.values() if item.name == call]
    assert seen, f"no call to {call} was observed"
    value = seen[-1].argument(index)
    assert value is not None
    return classify(value, kind)[0]


def view(body: str) -> str:
    """A Flask view with ``body`` inside it."""
    return FLASK + "def view():\n" + textwrap.indent(textwrap.dedent(body), "    ")


# --- the three answers --------------------------------------------------------


def test_request_data_is_tainted() -> None:
    assert reaching(view("sink(request.args.get('q'))")) == TAINTED


def test_a_literal_is_clean() -> None:
    assert reaching(view("sink('ls -la')")) == CLEAN


def test_a_name_nothing_is_known_about_is_unknown_not_clean() -> None:
    assert reaching(view("sink(mystery)")) == UNKNOWN


def test_a_parameter_of_an_ordinary_function_is_unknown() -> None:
    assert reaching("def run(command):\n    sink(command)\n") == UNKNOWN


def test_the_result_of_an_unknown_function_is_unknown_even_for_literal_arguments() -> None:
    """It might read a socket. Only functions known to be pure pass literals through."""
    assert reaching(view("sink(load_setting('command'))")) == UNKNOWN


def test_a_pure_library_function_of_a_literal_is_clean() -> None:
    source = "import base64\n" + view("sink(base64.b64decode('bHM='))")
    assert reaching(source) == CLEAN


def test_a_pure_library_function_of_request_data_is_tainted() -> None:
    source = "import base64\n" + view("sink(base64.b64decode(request.args['q']))")
    assert reaching(source) == TAINTED


# --- how values travel ----------------------------------------------------------


@pytest.mark.parametrize(
    "expression",
    [
        "param",
        "'echo ' + param",
        "param + ' now'",
        "f'echo {param}'",
        "'echo %s' % param",
        "'echo %s %s' % (param, 'x')",
        "'echo {}'.format(param)",
        "' '.join(['echo', param])",
        "param.strip().lower()",
        "param[1:-1]",
        "str(param)",
        "param.encode('utf-8').decode('utf-8')",
        "helper(param)",
        "[param][0]",
        "(param, 'x')[0]",
        "{'k': param}['k']",
        "param if flag else 'safe'",
        "other or param",
    ],
)
def test_taint_survives_every_ordinary_way_of_building_a_string(expression: str) -> None:
    assert reaching(view(f"param = request.form['p']\nsink({expression})")) == TAINTED


def test_reassignment_replaces_what_is_known() -> None:
    assert reaching(view("value = request.args['q']\nvalue = 'fixed'\nsink(value)")) == CLEAN


def test_augmented_assignment_adds_to_what_is_known() -> None:
    body = "text = 'echo '\ntext += request.args['q']\ntext += ' done'\nsink(text)"
    assert reaching(view(body)) == TAINTED


def test_literals_are_computed() -> None:
    body = """
        number = 106
        text = 'safe' if (7 * 18) + number > 200 else request.args['q']
        sink(text)
    """
    assert reaching(view(body)) == CLEAN


def test_the_other_side_of_a_computed_condition_is_taken_when_it_is_the_true_one() -> None:
    body = """
        number = 6
        text = 'safe' if (7 * 18) + number > 200 else request.args['q']
        sink(text)
    """
    assert reaching(view(body)) == TAINTED


def test_tuple_assignment_keeps_each_side_apart() -> None:
    body = "left, right = 'fixed', request.args['q']\nsink(left)"
    assert reaching(view(body)) == CLEAN
    body = "left, right = 'fixed', request.args['q']\nsink(right)"
    assert reaching(view(body)) == TAINTED


def test_unpacking_something_unknown_taints_every_name() -> None:
    assert reaching(view("left, right = request.args['q'].split(',')\nsink(left)")) == TAINTED


# --- branches -----------------------------------------------------------------------


def test_a_value_set_on_one_branch_only_is_still_possibly_that_value() -> None:
    body = """
        value = 'fixed'
        if flag:
            value = request.args['q']
        sink(value)
    """
    assert reaching(view(body)) == TAINTED


def test_a_branch_that_can_never_run_contributes_nothing() -> None:
    body = """
        marker = 'This should never happen'
        value = 'fixed'
        if 'should' not in marker:
            value = request.args['q']
        sink(value)
    """
    assert reaching(view(body)) == CLEAN


def test_a_branch_that_always_runs_replaces_the_value() -> None:
    body = """
        marker = 'This should always happen'
        value = 'fixed'
        if 'should' in marker:
            value = request.args['q']
        sink(value)
    """
    assert reaching(view(body)) == TAINTED


def test_match_takes_only_the_case_that_matches_a_known_subject() -> None:
    body = """
        guess = 'ABC'[1]
        match guess:
            case 'A':
                value = request.args['q']
            case 'B':
                value = 'bob'
            case 'C' | 'D':
                value = request.args['q']
            case _:
                value = 'other'
        sink(value)
    """
    assert reaching(view(body)) == CLEAN
    assert reaching(view(body.replace("'ABC'[1]", "'ABC'[2]"))) == TAINTED


def test_match_on_an_unknown_subject_takes_every_case() -> None:
    body = """
        match kind:
            case 'A':
                value = 'fixed'
            case _:
                value = request.args['q']
        sink(value)
    """
    assert reaching(view(body)) == TAINTED


def test_a_loop_carries_a_value_out_through_break() -> None:
    body = """
        value = ''
        for name in request.form.keys():
            if name.startswith('x'):
                value = name
                break
        sink(value)
    """
    assert reaching(view(body)) == TAINTED


def test_a_value_changed_late_in_a_loop_reaches_the_top_of_the_next_pass() -> None:
    body = """
        value = 'fixed'
        current = 'fixed'
        for item in items:
            sink(current)
            current = value
            value = request.args['q']
    """
    assert reaching(view(body)) == TAINTED


def test_a_loop_that_does_not_settle_is_assumed_to_mix_everything_it_assigns() -> None:
    """A chain longer than the walk is willing to follow must not come out clean."""
    names = [f"v{number}" for number in range(12)]
    body = "".join(f"{name} = 'fixed'\n" for name in names)
    body += "for item in items:\n    sink(v0)\n"
    body += "".join(f"    {a} = {b}\n" for a, b in zip(names, names[1:], strict=False))
    body += f"    {names[-1]} = request.args['q']\n"

    assert reaching(view(body)) == TAINTED


def test_a_loop_with_nothing_to_carry_round_is_read_twice_and_no_more() -> None:
    tree = ast.parse(view("for item in items:\n    sink('ls')\n"))
    counted = []
    walker = flow._Walker(tree)
    original = walker._pass

    def counting(*arguments: object) -> object:
        counted.append(1)
        return original(*arguments)  # type: ignore[arg-type]

    walker._pass = counting  # type: ignore[method-assign]
    walker.block(tree.body, flow._State({}), flow._Frame())

    assert len(counted) == 2


def test_an_exception_handler_sees_what_the_try_body_may_have_done() -> None:
    body = """
        value = 'fixed'
        try:
            value = request.args['q']
            risky()
        except ValueError:
            sink(value)
    """
    assert reaching(view(body)) == TAINTED


def test_code_after_a_try_that_always_returns_in_its_handler() -> None:
    body = """
        try:
            value = int(request.args['q'])
        except ValueError:
            return 'bad'
        sink(value)
    """
    # int() gives a number: nothing to inject.
    assert reaching(view(body)) == CLEAN


def test_a_with_block_binds_what_was_opened() -> None:
    body = "with wrap(request.args['q']) as handle:\n    sink(handle)"
    assert reaching(view(body)) == TAINTED


# --- containers ------------------------------------------------------------------------


def test_a_list_is_tracked_element_by_element() -> None:
    body = """
        items = []
        items.append('safe')
        items.append(request.args['q'])
        items.append('moresafe')
        items.pop(0)
        sink(items[{index}])
    """
    assert reaching(view(body.format(index=0))) == TAINTED
    assert reaching(view(body.format(index=1))) == CLEAN


def test_a_list_read_at_an_unknown_place_is_any_of_its_elements() -> None:
    body = "items = ['safe', request.args['q']]\nsink(items[position])"
    assert reaching(view(body)) == TAINTED


def test_a_dictionary_is_tracked_key_by_key() -> None:
    body = """
        table = {{}}
        table['a'] = 'safe'
        table['b'] = request.args['q']
        sink(table[{key!r}])
    """
    assert reaching(view(body.format(key="a"))) == CLEAN
    assert reaching(view(body.format(key="b"))) == TAINTED


def test_a_dictionary_written_at_an_unknown_key_is_tainted_everywhere() -> None:
    body = "table = {'a': 'safe'}\ntable[key] = request.args['q']\nsink(table['a'])"
    assert reaching(view(body)) == TAINTED


def test_a_keyed_store_is_tracked_by_its_literal_keys() -> None:
    body = """
        settings = make_settings()
        settings.set('section', 'a', 'safe')
        settings.set('section', 'b', request.args['q'])
        sink(settings.get('section', {key!r}))
    """
    source = view(body)
    assert reaching(source.format(key="a")) == CLEAN
    assert reaching(source.format(key="b")) == TAINTED


def test_writing_into_an_object_taints_what_is_read_back_from_it() -> None:
    body = """
        buffer = make_buffer()
        buffer.write('SELECT ')
        buffer.write(request.args['q'])
        sink(buffer.getvalue())
    """
    assert reaching(view(body)) == TAINTED


# --- sanitisers -------------------------------------------------------------------------


def test_a_sanitiser_makes_a_value_safe_for_its_own_kind_only() -> None:
    body = "import html\nvalue = html.escape(request.args['q'])\nsink(value)"
    assert reaching(view(body), HTML) == CLEAN
    assert reaching(view(body), COMMAND) == TAINTED
    assert reaching(view(body), SQL) == TAINTED


def test_shell_quoting_makes_a_value_safe_for_a_command_only() -> None:
    body = "import shlex\nvalue = shlex.quote(request.args['q'])\nsink(value)"
    assert reaching(view(body), COMMAND) == CLEAN
    assert reaching(view(body), HTML) == TAINTED


def test_a_number_cannot_carry_an_injection() -> None:
    for kind in (COMMAND, SQL, HTML, PATH):
        assert reaching(view("sink(int(request.args['q']))"), kind) == CLEAN


def test_a_project_escape_helper_is_recognised_by_its_name() -> None:
    body = "sink(escape_for_html(request.args['q']))"
    assert reaching(view(body), HTML) == CLEAN
    assert reaching(view(body), COMMAND) == TAINTED


def test_replacing_quotes_makes_a_value_safe_for_xpath_and_not_for_sql() -> None:
    body = """sink(request.args['q'].replace("'", "&apos;"))"""
    assert reaching(view(body), XPATH) == CLEAN
    assert reaching(view(body), SQL) == TAINTED


def test_replacing_something_else_is_not_a_sanitiser() -> None:
    assert reaching(view("sink(request.args['q'].replace('a', 'b'))"), XPATH) == TAINTED


def test_a_basename_is_safe_as_a_path() -> None:
    body = "import os.path\nsink(os.path.basename(request.args['q']))"
    assert reaching(view(body), PATH) == CLEAN


def test_a_sanitised_value_joined_with_an_unsanitised_one_is_not_safe() -> None:
    body = """
        import html
        raw = request.args['q']
        value = html.escape(raw) if flag else raw
        sink(value)
    """
    assert reaching(view(body), HTML) == TAINTED


# --- checks that reject bad input ------------------------------------------------------


def test_rejecting_dot_dot_makes_a_value_safe_as_a_path() -> None:
    body = """
        name = request.args['q']
        if '../' in name:
            return 'invalid'
        sink('/data/' + name)
    """
    assert reaching(view(body), PATH) == CLEAN
    assert reaching(view(body), COMMAND) == TAINTED


def test_the_check_only_counts_when_failing_it_leaves_the_function() -> None:
    body = """
        name = request.args['q']
        if '../' in name:
            log('suspicious')
        sink('/data/' + name)
    """
    assert reaching(view(body), PATH) == TAINTED


def test_inside_the_branch_where_the_check_failed_the_value_is_still_dangerous() -> None:
    body = """
        name = request.args['q']
        if '../' in name:
            sink(name)
    """
    assert reaching(view(body), PATH) == TAINTED


def test_a_positive_check_makes_the_value_safe_inside_its_branch() -> None:
    body = """
        name = request.args['q']
        if '..' not in name:
            sink(name)
    """
    assert reaching(view(body), PATH) == CLEAN


def test_an_emptiness_test_is_not_validation() -> None:
    body = """
        name = request.args['q']
        if not name:
            return 'missing'
        sink(name)
    """
    assert reaching(view(body), PATH) == TAINTED


def test_membership_in_a_list_of_literals_makes_a_value_safe_for_everything() -> None:
    body = """
        action = request.args['q']
        if action not in ('start', 'stop'):
            return 'unknown action'
        sink(action)
    """
    for kind in (COMMAND, SQL, PATH, HTML):
        assert reaching(view(body), kind) == CLEAN


def test_membership_in_something_that_is_not_a_list_of_literals_proves_nothing() -> None:
    body = """
        action = request.args['q']
        if action not in allowed_actions():
            return 'unknown action'
        sink(action)
    """
    assert reaching(view(body)) == TAINTED


def test_equality_with_a_literal_makes_the_whole_value_known() -> None:
    body = """
        mode = request.args['q']
        if mode != 'fast':
            return 'unsupported'
        sink(mode)
    """
    assert reaching(view(body)) == CLEAN


def test_a_check_on_one_part_of_a_value_does_not_vouch_for_the_rest() -> None:
    body = """
        from urllib.parse import urlparse
        target = request.args['q']
        if urlparse(target).scheme != 'https':
            return 'bad'
        sink(target)
    """
    assert reaching(view(body), REDIRECT) == TAINTED


def test_a_host_on_an_allow_list_makes_an_address_safe_to_redirect_to() -> None:
    body = """
        from urllib.parse import urlparse
        target = request.args['q']
        url = urlparse(target)
        if url.netloc not in ['example.com'] or url.scheme != 'https':
            return 'bad'
        sink(target)
    """
    assert reaching(view(body), REDIRECT) == CLEAN
    assert reaching(view(body), HTML) == TAINTED


def test_a_framework_validator_makes_an_address_safe_to_redirect_to() -> None:
    body = """
        target = request.args['q']
        if not url_has_allowed_host_and_scheme(url=target, allowed_hosts=hosts):
            target = '/'
        sink(target)
    """
    assert reaching(view(body), REDIRECT) == CLEAN


def test_a_resolved_path_checked_against_its_base_is_safe() -> None:
    body = """
        import pathlib
        base = pathlib.Path('/data')
        target = (base / request.args['q']).resolve()
        if not str(target).startswith(str(base)):
            return 'invalid'
        sink(target)
    """
    assert reaching(view(body), PATH) == CLEAN


def test_a_digits_only_check_makes_a_value_safe() -> None:
    body = """
        number = request.args['q']
        if not number.isdigit():
            return 'bad'
        sink(number)
    """
    assert reaching(view(body), SQL) == CLEAN


def test_a_full_match_makes_a_value_safe_and_a_partial_one_does_not() -> None:
    full = """
        import re
        name = request.args['q']
        if not re.fullmatch('[a-z]+', name):
            return 'bad'
        sink(name)
    """
    assert reaching(view(full)) == CLEAN
    assert reaching(view(full.replace("re.fullmatch", "re.search"))) == TAINTED


def test_a_value_shown_to_be_one_string_literal_is_safe_to_evaluate() -> None:
    body = """
        text = request.args['q']
        if not text.startswith("'") or not text.endswith("'") or "'" in text[1:-1]:
            return 'must be a plain string literal'
        sink(text)
    """
    assert reaching(view(body), values.CODE) == CLEAN
    # Dropping any one of the three conditions leaves it unproven.
    partial = body.replace(""" or "'" in text[1:-1]""", "")
    assert reaching(view(partial), values.CODE) == TAINTED


def test_a_quote_check_makes_a_value_safe_for_xpath_and_not_for_sql() -> None:
    body = """
        ident = request.args['q']
        if "'" in ident:
            return 'bad'
        sink(ident)
    """
    assert reaching(view(body), XPATH) == CLEAN
    assert reaching(view(body), SQL) == TAINTED


def test_a_check_and_an_unrelated_condition_joined_by_and_prove_nothing_when_false() -> None:
    """``if (a or b) and not valid(x): ...`` — falling through does not mean valid(x)."""
    body = """
        target = request.args['q']
        if flag and target not in ('a', 'b'):
            return 'bad'
        sink(target)
    """
    assert reaching(view(body)) == TAINTED


# --- the request ------------------------------------------------------------------------


def test_the_request_itself_is_not_data() -> None:
    """Handing it to a helper says nothing about what the helper returns."""
    assert reaching(view("sink(current_user(request))")) == UNKNOWN
    assert reaching(view("sink(current_user(request))"), HTML) == UNKNOWN


@pytest.mark.parametrize("part", ["method", "endpoint", "remote_addr", "is_secure", "blueprint"])
def test_parts_of_a_request_the_caller_does_not_write_are_not_input(part: str) -> None:
    assert reaching(view(f"sink(request.{part})")) == UNKNOWN


@pytest.mark.parametrize(
    "read",
    [
        "request.args['q']",
        "request.form.get('q')",
        "request.values.getlist('q')[0]",
        "request.cookies.get('q')",
        "request.headers['X-Q']",
        "request.get_json()['q']",
        "request.json['q']",
        "request.data",
        "request.query_string.decode()",
        "request.files['f'].filename",
        "request.view_args['q']",
    ],
)
def test_everything_the_caller_does_write_is_input(read: str) -> None:
    assert reaching(view(f"sink({read})")) == TAINTED


def test_the_path_of_a_request_can_only_name_a_place_on_this_site() -> None:
    assert reaching(view("sink(request.path)"), REDIRECT) == CLEAN
    assert reaching(view("sink(request.path)"), HTML) == TAINTED


def test_the_request_imported_under_another_name_is_still_the_request() -> None:
    source = "from flask import request as req\n\ndef view():\n    sink(req.args['q'])\n"
    assert reaching(source) == TAINTED


def test_the_request_reached_through_the_module_is_still_the_request() -> None:
    source = "import flask\n\ndef view():\n    sink(flask.request.args['q'])\n"
    assert reaching(source) == TAINTED


def test_a_parameter_called_request_is_the_request_in_a_web_application() -> None:
    source = (
        "from django.http import HttpResponse\n\ndef view(request):\n    sink(request.GET['q'])\n"
    )
    assert reaching(source) == TAINTED


def test_a_parameter_called_request_is_not_the_request_anywhere_else() -> None:
    """A pytest fixture and an outgoing API call are both called ``request``."""
    source = "import pytest\n\ndef test_x(request):\n    sink(request.param)\n"
    assert reaching(source) == UNKNOWN


def test_a_local_variable_called_request_is_not_the_request() -> None:
    body = "request = build()\nsink(request.args)"
    assert reaching(view(body)) == UNKNOWN


def test_the_parameters_of_a_route_come_from_the_url() -> None:
    source = (
        "from flask import Flask\napp = Flask(__name__)\n\n"
        "@app.route('/users/<name>')\ndef user(name):\n    sink(name)\n"
    )
    assert reaching(source) == TAINTED


def test_a_route_parameter_converted_to_a_number_is_not_text() -> None:
    source = (
        "from flask import Flask\napp = Flask(__name__)\n\n"
        "@app.route('/items/<int:item_id>')\ndef item(item_id):\n    sink(item_id)\n"
    )
    assert reaching(source) == CLEAN


def test_a_parameter_that_is_a_number_under_one_rule_and_text_under_another_is_text() -> None:
    source = (
        "from flask import Flask\napp = Flask(__name__)\n\n"
        "@app.route('/a/<int:page>')\n@app.route('/b/<page>')\ndef listing(page):\n    sink(page)\n"
    )
    assert reaching(source) == TAINTED


def test_an_annotated_number_in_a_route_is_not_text() -> None:
    source = (
        "from fastapi import FastAPI\napp = FastAPI()\n\n"
        "@app.get('/items')\ndef items(limit: int, query: str):\n    sink({name})\n"
    )
    assert reaching(source.format(name="limit")) == CLEAN
    assert reaching(source.format(name="query")) == TAINTED


def test_the_path_of_a_route_with_no_variable_part_is_the_rule_itself() -> None:
    source = (
        "from flask import Flask, request\napp = Flask(__name__)\n\n"
        "@app.route('/status/check')\ndef status():\n    sink(request.path.split('/')[1])\n"
    )
    assert reaching(source) == CLEAN


def test_the_path_of_a_route_with_a_variable_part_is_input() -> None:
    source = (
        "from flask import Flask, request\napp = Flask(__name__)\n\n"
        "@app.route('/status/<name>')\ndef status(name):\n    sink(request.path.split('/')[2])\n"
    )
    assert reaching(source, HTML) == TAINTED


# --- lookups, and functions of the same file -------------------------------------------


@pytest.mark.parametrize(
    "lookup",
    [
        "open(request.args['q']).read()",
        "cursor.execute(request.args['q'])",
        "tree.xpath(request.args['q'])",
        "subprocess.run(request.args['q'])",
    ],
)
def test_what_a_lookup_returns_is_not_what_it_was_asked(lookup: str) -> None:
    """A file's contents are not its name; they are unknown, not request data."""
    assert reaching("import subprocess\n" + view(f"sink({lookup})"), HTML) == UNKNOWN


def test_a_function_of_the_same_file_is_followed_with_its_arguments() -> None:
    source = FLASK + textwrap.dedent(
        """
        def wrap(text):
            return 'echo ' + text

        def view():
            sink(wrap(request.args['q']))
        """
    )
    assert reaching(source) == TAINTED
    assert reaching(source.replace("request.args['q']", "'fixed'")) == CLEAN


def test_a_function_that_ignores_its_argument_does_not_pass_it_on() -> None:
    source = FLASK + textwrap.dedent(
        """
        def constant(text):
            return 'bar'

        def view():
            sink(constant(request.args['q']))
        """
    )
    assert reaching(source) == CLEAN


def test_a_function_defined_below_its_caller_is_still_followed() -> None:
    source = FLASK + textwrap.dedent(
        """
        def view():
            sink(wrap(request.args['q']))

        def wrap(text):
            return 'echo ' + text
        """
    )
    assert reaching(source) == TAINTED


def test_request_data_passed_into_a_helper_is_seen_at_the_call_inside_it() -> None:
    source = FLASK + textwrap.dedent(
        """
        def run(command):
            sink(command)

        def view():
            run(request.args['q'])
        """
    )
    assert reaching(source) == TAINTED


def test_recursion_ends() -> None:
    source = FLASK + textwrap.dedent(
        """
        def again(text, depth):
            if depth:
                return again(text + 'x', depth - 1)
            return text

        def view():
            sink(again(request.args['q'], 3))
        """
    )
    assert reaching(source) in {TAINTED, UNKNOWN}


def test_a_method_is_not_followed_by_its_bare_name() -> None:
    """``clean(x)`` is not ``Helper.clean``; following it would vouch for the wrong code."""
    source = FLASK + textwrap.dedent(
        """
        class Helper:
            def clean(self, text):
                return 'fixed'

        def view():
            sink(clean(request.args['q']))
        """
    )
    assert reaching(source) == TAINTED


def test_a_name_defined_twice_is_not_followed() -> None:
    source = FLASK + textwrap.dedent(
        """
        def clean(text):
            return 'fixed'

        def clean(text):  # the one that actually runs
            return text

        def view():
            sink(clean(request.args['q']))
        """
    )
    assert reaching(source) == TAINTED


def test_an_outer_name_assigned_once_is_known_inside_a_function() -> None:
    source = "MODE = 'fixed'\n\ndef view():\n    sink(MODE)\n"
    assert reaching(source) == CLEAN


def test_an_outer_name_assigned_twice_is_not_known_inside_a_function() -> None:
    """A function sees the latest value when it runs, not the one where it was defined."""
    source = "MODE = 'fixed'\n\ndef view():\n    sink(MODE)\n\nMODE = load()\n"
    assert reaching(source) == UNKNOWN


def test_a_name_declared_global_is_not_known_inside_a_function() -> None:
    source = (
        "MODE = 'fixed'\n\ndef change():\n    global MODE\n    MODE = load()\n\n"
        "def view():\n    sink(MODE)\n"
    )
    assert reaching(source) == UNKNOWN


# --- code that cannot run -----------------------------------------------------------------


def observed(source: str) -> tuple[flow.Flow, dict[str, ast.Call]]:
    tree = ast.parse(textwrap.dedent(source))
    calls = {ast.unparse(node.func): node for node in ast.walk(tree) if isinstance(node, ast.Call)}
    return flow.analyse(tree), calls


def test_a_call_after_a_return_is_unreachable() -> None:
    walk, calls = observed("def f():\n    return 1\n    sink(x)\n")
    assert walk.unreachable(calls["sink"])


def test_a_call_in_a_branch_that_is_never_taken_is_unreachable() -> None:
    walk, calls = observed("DEBUG = False\nif DEBUG:\n    sink(x)\nelse:\n    other(x)\n")
    assert walk.unreachable(calls["sink"])
    assert not walk.unreachable(calls["other"])


def test_a_call_the_walk_did_not_look_at_is_not_called_unreachable() -> None:
    """Inside a lambda nothing is known. That is "unknown", never "cannot run"."""
    walk, calls = observed("handler = lambda value: sink(value)\n")
    assert walk.call(calls["sink"]) is None
    assert not walk.unreachable(calls["sink"])


def test_a_call_reached_on_any_path_is_not_unreachable() -> None:
    source = """
        def helper(flag):
            if flag:
                sink(1)

        def a():
            helper(False)

        def b():
            helper(True)
    """
    walk, calls = observed(source)
    assert not walk.unreachable(calls["sink"])


# --- weak randomness ----------------------------------------------------------------------


def weak(source: str, call: str = "sink") -> bool:
    tree = ast.parse(textwrap.dedent(source))
    seen = [item for item in flow.analyse(tree).calls.values() if item.name == call]
    value = seen[-1].argument(0)
    assert value is not None
    return values.predictable(value) is not None


def test_the_random_module_is_predictable_and_its_secure_relatives_are_not() -> None:
    assert weak("import random\nsink(str(random.getrandbits(64)))\n")
    assert weak("from random import randint\nsink(randint(0, 9))\n")
    assert not weak("import random\nsink(str(random.SystemRandom().getrandbits(64)))\n")
    assert not weak("import secrets\nsink(secrets.token_hex(16))\n")


# --- joining two values ---------------------------------------------------------------------

REQUEST_DATA = Taint(INPUT, 1, 0)
SOMETHING = Taint(OPAQUE, 2, 0)


def test_joining_never_loses_a_reason_for_distrust() -> None:
    tainted = Value(frozenset({REQUEST_DATA}))
    unknown = Value(frozenset({SOMETHING}))
    literal = values.constant("x")

    for first, second in [(tainted, literal), (literal, tainted), (tainted, unknown)]:
        assert REQUEST_DATA in join(first, second).all_taints()
    assert classify(join(unknown, literal), COMMAND)[0] == UNKNOWN
    assert classify(join(literal, values.constant("y")), COMMAND)[0] == CLEAN


def test_joining_containers_of_different_shapes_keeps_what_was_in_them() -> None:
    short = Value(items=(Value(frozenset({REQUEST_DATA})),))
    long = Value(items=(values.constant("a"), values.constant("b")))

    joined = join(short, long)

    assert joined.items is None
    assert REQUEST_DATA in joined.all_taints()


def test_joining_keeps_a_value_safe_only_for_what_both_sides_were_safe_for() -> None:
    escaped = Value(frozenset({Taint(INPUT, 1, 0, frozenset({HTML}))}))
    raw = Value(frozenset({Taint(INPUT, 1, 0)}))

    assert classify(join(escaped, raw), HTML)[0] == TAINTED
    assert classify(join(escaped, escaped), HTML)[0] == CLEAN


def test_too_many_alternatives_become_not_known_rather_than_a_guess() -> None:
    value = values.constant(0)
    for number in range(1, values.MAX_CONSTANTS + 2):
        value = join(value, values.constant(number))

    assert value.constants is None
    assert classify(value, COMMAND)[0] == CLEAN  # still built from literals


def test_capping_the_reasons_keeps_request_data_and_one_stand_in_for_the_rest() -> None:
    many = {Taint(OPAQUE, line, 0, frozenset({HTML})) for line in range(values.MAX_TAINTS + 5)}
    many.add(Taint(OPAQUE, 999, 0))  # one that is not safe for HTML
    many.add(REQUEST_DATA)

    kept = values.capped(many)

    assert REQUEST_DATA in kept
    assert len(kept) == 2
    stand_in = next(taint for taint in kept if taint.origin == OPAQUE)
    assert stand_in.safe == frozenset()  # safe only for what all of them were


# --- limits ---------------------------------------------------------------------------------


def test_a_walk_that_runs_out_of_steps_knows_nothing_rather_than_something_wrong(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(flow, "MAX_STEPS", 5)
    tree = ast.parse(view("a = 1\nb = 2\nc = 3\nsink('ls')"))

    walk = flow.analyse(tree)

    assert not walk.complete
    call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call))
    assert walk.call(call) is None
    assert not walk.unreachable(call)


def test_a_mistake_inside_the_walk_costs_the_knowledge_and_not_the_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken(*_arguments: object, **_keywords: object) -> None:
        raise KeyError("a bug in the walk")

    monkeypatch.setattr(flow._Walker, "statement", broken)

    assert not flow.analyse(ast.parse("x = 1\n")).complete


@pytest.mark.parametrize(
    "expression",
    ["'a' * 10 ** 9", "2 ** 10 ** 6", "1 << 10 ** 6", "'ab' * (10 ** 8)", "[0] * 10 ** 9"],
)
def test_arithmetic_on_literals_is_never_allowed_to_be_enormous(expression: str) -> None:
    started = time.monotonic()

    assert reaching(f"def f():\n    sink({expression})\n") == CLEAN

    assert time.monotonic() - started < 1.0


def test_an_operation_that_fails_on_literals_is_simply_not_known() -> None:
    assert reaching("def f():\n    sink(1 / 0)\n") == CLEAN
    assert reaching("def f():\n    sink('abc'[10])\n") == CLEAN
    assert reaching("def f():\n    sink('a' + 1)\n") == CLEAN


def test_a_file_of_small_functions_calling_each_other_stays_affordable() -> None:
    functions = ["def f0(x):\n    return x\n"]
    for number in range(1, 150):
        functions.append(
            f"def f{number}(x):\n"
            f"    return f{number - 1}(x) + f{number - 1}(x) + f{number - 1}(x)\n"
        )
    tree = ast.parse("\n".join(functions))
    started = time.monotonic()

    walk = flow.analyse(tree)

    assert time.monotonic() - started < 5.0
    assert walk.complete


# --- ways a "clean" could be wrong, each found by asking how ------------------------------


def test_a_check_on_one_field_says_nothing_about_another_from_the_same_request() -> None:
    """Both come from one ``get_json()``. Only the one that was checked is vouched for."""
    body = """
        data = request.get_json()
        action = data['action']
        target = data['target']
        if action not in ('start', 'stop'):
            return 'bad'
        sink(target)
    """
    assert reaching(view(body)) == TAINTED
    assert reaching(view(body.replace("sink(target)", "sink(action)"))) == CLEAN


def test_a_check_made_after_a_value_was_copied_does_not_reach_the_copy() -> None:
    body = """
        name = request.args['q']
        path = '/data/' + name
        if '../' in name:
            return 'bad'
        sink(path)
    """
    assert reaching(view(body), PATH) == TAINTED


def test_a_list_changed_through_another_name_is_changed() -> None:
    body = """
        command = ['ls']
        extra = command
        extra.append(request.args['q'])
        sink(command)
    """
    assert reaching(view(body)) == TAINTED


def test_a_name_stops_being_an_alias_when_it_is_assigned_something_else() -> None:
    body = """
        command = ['ls']
        extra = command
        extra = []
        extra.append(request.args['q'])
        sink(command)
    """
    assert reaching(view(body)) == CLEAN


def test_an_alias_made_on_only_one_branch_is_not_relied_on_but_not_ignored() -> None:
    body = """
        command = ['ls']
        other = ['x']
        if flag:
            other = command
        other.append(request.args['q'])
        sink(command)
    """
    # The two paths disagree about whether `other` is `command`; on the path
    # where it is, the list was changed. That path's value survives the join.
    assert reaching(view(body)) in {TAINTED, UNKNOWN}


def test_a_list_handed_to_an_unknown_function_may_come_back_changed() -> None:
    body = """
        command = ['ls']
        add_arguments(command)
        sink(command)
    """
    assert reaching(view(body)) == UNKNOWN


def test_a_list_handed_to_a_function_of_this_file_may_come_back_changed() -> None:
    source = FLASK + textwrap.dedent(
        """
        def fill(target):
            target.append(request.args['q'])

        def view():
            command = ['ls']
            fill(command)
            sink(command)
        """
    )
    assert reaching(source) in {TAINTED, UNKNOWN}


def test_a_module_level_list_that_is_changed_somewhere_is_not_known_inside_a_function() -> None:
    source = FLASK + textwrap.dedent(
        """
        COMMAND = ['ls']

        def configure():
            COMMAND.append(request.args['q'])

        def view():
            sink(COMMAND)
        """
    )
    assert reaching(source) == UNKNOWN


def test_a_module_level_tuple_that_nothing_changes_is_known_inside_a_function() -> None:
    source = FLASK + textwrap.dedent(
        """
        ALLOWED = ('start', 'stop')

        def view():
            action = request.args['q']
            if action not in ALLOWED:
                return 'bad'
            sink(action)
        """
    )
    assert reaching(source) == CLEAN


def test_membership_in_a_set_of_literals_counts() -> None:
    body = """
        action = request.args['q']
        if action not in {'start', 'stop'}:
            return 'bad'
        sink(action)
    """
    assert reaching(view(body)) == CLEAN


def test_a_set_with_request_data_in_it_is_not_an_allow_list() -> None:
    body = """
        allowed = {'start'}
        allowed.add(request.args['other'])
        action = request.args['q']
        if action not in allowed:
            return 'bad'
        sink(action)
    """
    assert reaching(view(body)) == TAINTED


def test_a_name_another_function_assigns_is_never_known() -> None:
    source = textwrap.dedent(
        """
        def outer():
            mode = 'fixed'

            def change():
                nonlocal mode
                mode = load()

            change()
            sink(mode)
        """
    )
    assert reaching(source) == UNKNOWN


def test_an_exception_handler_sees_a_value_the_try_body_later_overwrote() -> None:
    body = """
        value = 'fixed'
        try:
            value = request.args['q']
            risky()
            value = 'fixed again'
        except ValueError:
            sink(value)
    """
    assert reaching(view(body)) == TAINTED


def test_the_string_literal_check_needs_the_inside_checked_not_some_other_slice() -> None:
    body = """
        text = request.args['q']
        if not text.startswith("'") or not text.endswith("'") or "'" in text[5:]:
            return 'bad'
        sink(text)
    """
    assert reaching(view(body), values.CODE) == TAINTED


def test_a_host_check_on_an_address_parsed_inline_vouches_for_the_address() -> None:
    body = """
        from urllib.parse import urlparse
        target = request.args['q']
        if urlparse(target).netloc not in ('example.com',):
            return 'bad'
        sink(target)
    """
    assert reaching(view(body), REDIRECT) == CLEAN


def test_a_host_check_stops_counting_when_the_address_is_replaced_afterwards() -> None:
    body = """
        from urllib.parse import urlparse
        target = request.args['q']
        url = urlparse(target)
        target = request.args['other']
        if url.netloc not in ('example.com',):
            return 'bad'
        sink(target)
    """
    assert reaching(view(body), REDIRECT) == TAINTED


def test_running_out_of_stack_is_giving_up_not_crashing() -> None:
    tree = ast.parse("x = " + " + ".join(["1"] * 400) + "\n")
    limit = sys.getrecursionlimit()
    sys.setrecursionlimit(len(inspect.stack()) + 150)
    try:
        walk = flow.analyse(tree)
    finally:
        sys.setrecursionlimit(limit)

    assert not walk.complete


# --- found by breaking the walk on purpose and seeing no test fail -----------------------------


def test_a_dictionary_holding_request_data_is_itself_tainted() -> None:
    assert reaching(view("sink({'key': request.args['q']})")) == TAINTED


def test_dictionaries_with_different_keys_keep_their_contents_when_paths_meet() -> None:
    body = """
        if flag:
            table = {'a': request.args['q']}
        else:
            table = {'b': 'fixed'}
        sink(table)
    """
    assert reaching(view(body)) == TAINTED


def test_a_condition_that_is_always_true_leaves_nothing_of_the_other_path() -> None:
    body = """
        value = request.args['q']
        if 'should' in 'This should always happen':
            value = 'fixed'
        sink(value)
    """
    assert reaching(view(body)) == CLEAN


def test_a_case_that_is_certain_to_match_ends_the_match() -> None:
    body = """
        guess = 'ABC'[0]
        match guess:
            case 'A':
                value = 'fixed'
            case _:
                value = request.args['q']
        sink(value)
    """
    assert reaching(view(body)) == CLEAN


def test_a_loop_that_settles_keeps_what_it_did_not_touch_apart() -> None:
    """Widening is for loops that do not settle; this one does, on its second reading."""
    body = """
        steady = 'fixed'
        growing = request.args['q']
        for item in items:
            steady = 'still fixed'
            growing = growing + 'x'
        sink(steady)
    """
    assert reaching(view(body)) == CLEAN


def test_a_function_defined_differently_on_two_branches_is_not_followed() -> None:
    source = FLASK + textwrap.dedent(
        """
        if legacy:
            def clean(text):
                return text
        else:
            def clean(text):
                return 'fixed'

        def view():
            sink(clean(request.args['q']))
        """
    )
    assert reaching(source) == TAINTED


def test_a_quote_check_on_the_inside_alone_is_not_a_quote_check_on_the_value() -> None:
    body = """
        ident = request.args['q']
        if "'" in ident[1:-1]:
            return 'bad'
        sink(ident)
    """
    assert reaching(view(body), XPATH) == TAINTED


def test_a_prefix_taken_from_the_request_proves_nothing() -> None:
    body = """
        target = request.args['q']
        if not target.startswith(request.args['base']):
            return 'bad'
        sink(target)
    """
    assert reaching(view(body), PATH) == TAINTED


def test_a_store_made_from_request_data_is_tainted_at_keys_nobody_set() -> None:
    body = """
        settings = parse_settings(request.data)
        settings.set('section', 'a', 'fixed')
        sink(settings.get('section', {key!r}))
    """
    assert reaching(view(body).format(key="a")) == CLEAN
    assert reaching(view(body).format(key="other")) == TAINTED


@pytest.mark.parametrize(
    ("operation", "operands"),
    [
        (operator.pow, (2, 10**6)),
        (operator.lshift, (1, 10**6)),
        (operator.add, (1 << 300, 1)),
        (operator.mul, ("ab", 10**6)),
    ],
)
def test_an_operation_that_would_be_enormous_is_refused_before_it_is_tried(
    operation: object, operands: tuple[object, ...]
) -> None:
    with pytest.raises(OverflowError):
        values.guarded(operation)(*operands)  # type: ignore[arg-type]


def test_an_ordinary_operation_is_not_refused() -> None:
    assert values.guarded(operator.pow)(2, 10) == 1024
    assert values.guarded(operator.mul)("ab", 3) == "ababab"
