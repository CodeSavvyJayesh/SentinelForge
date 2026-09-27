"""What a proposed fix is allowed to come back as.

Every case below is something a 7B model does when asked for code inside JSON.
The stripping is not cosmetic: markdown fences and echoed line numbers produce
text that looks like code, passes a schema, and does not compile.
"""

import json

import pytest

from app.llm.contract import LlmContractError
from app.llm.patch_contract import parse, strip_gutters

CODE = "def digest(value):\n    return hashlib.sha256(value).hexdigest()"


def answer(replacement: str, rationale: str = "Replaced MD5 with SHA-256.") -> str:
    return json.dumps({"replacement": replacement, "rationale": rationale})


def test_a_clean_answer_passes_through() -> None:
    parsed = parse(answer(CODE))

    assert parsed.replacement == CODE
    assert parsed.rationale == "Replaced MD5 with SHA-256."
    assert parsed.fences_stripped is False
    assert parsed.gutters_stripped == 0


def test_markdown_fences_are_stripped_and_recorded() -> None:
    parsed = parse(answer(f"```python\n{CODE}\n```"))

    assert parsed.replacement == CODE
    assert parsed.fences_stripped is True


def test_an_unlabelled_fence_is_stripped_too() -> None:
    parsed = parse(answer(f"```\n{CODE}\n```"))

    assert parsed.replacement == CODE


def test_echoed_line_numbers_are_stripped() -> None:
    """The prompt shows ``   24 | code``; models return the same shape back."""
    numbered = "    4 | def digest(value):\n    5 |     return hashlib.sha256(value)"

    parsed = parse(answer(numbered))

    assert parsed.replacement == "def digest(value):\n    return hashlib.sha256(value)"
    assert parsed.gutters_stripped == 2


def test_a_gutter_is_only_stripped_when_every_line_has_one() -> None:
    """A line that merely looks like a gutter must not be eaten.

    ``    1 | 2`` inside a bitwise expression matches the gutter pattern
    exactly. If one match were enough to strip, this code would silently become
    ``    2`` — working code corrupted by the cleanup meant to protect it. So
    the rule is all-or-nothing, and this fixture is one that *partially*
    matches: a test where no line matches passes either way and proves nothing.
    """
    code = "flags = (\n    1 | 2\n)"

    stripped, count = strip_gutters(code)

    assert stripped == code
    assert count == 0


def test_a_blank_line_between_numbered_lines_does_not_block_stripping() -> None:
    numbered = "  1 | a = 1\n\n  3 | b = 2"

    stripped, count = strip_gutters(numbered)

    assert stripped == "a = 1\n\nb = 2"
    assert count == 2


def test_a_preamble_sentence_is_removed() -> None:
    parsed = parse(answer(f"Here is the corrected code:\n{CODE}"))

    assert parsed.replacement == CODE


def test_a_fence_inside_a_preamble_is_still_stripped() -> None:
    """Both habits at once, which is the common case."""
    parsed = parse(answer(f"Here's the fix:\n```python\n{CODE}\n```"))

    assert parsed.replacement == CODE
    assert parsed.fences_stripped is True


def test_a_list_of_lines_is_joined() -> None:
    """Some models answer "replacement" with an array rather than a string."""
    payload = json.dumps({"replacement": ["def digest(value):", "    return 1"], "rationale": "ok"})

    parsed = parse(payload)

    assert parsed.replacement == "def digest(value):\n    return 1"


def test_tabs_and_newlines_survive_sanitising() -> None:
    """Indentation is what makes Python code correct; it is not a control
    character to be stripped."""
    parsed = parse(answer("def f():\n\treturn 1"))

    assert parsed.replacement == "def f():\n\treturn 1"


def test_other_control_characters_are_removed() -> None:
    parsed = parse(answer("a = 1\x00\x07\nb = 2"))

    assert parsed.replacement == "a = 1\nb = 2"


# --- refusals -------------------------------------------------------------


def test_invalid_json_is_refused() -> None:
    with pytest.raises(LlmContractError, match="not valid JSON"):
        parse("I cannot help with that.")


def test_a_json_array_is_refused() -> None:
    with pytest.raises(LlmContractError, match="not a JSON object"):
        parse('["nope"]')


def test_a_missing_field_names_the_field() -> None:
    with pytest.raises(LlmContractError, match="rationale"):
        parse(json.dumps({"replacement": CODE}))


def test_an_empty_replacement_is_refused() -> None:
    with pytest.raises(LlmContractError):
        parse(answer(""))


def test_a_replacement_that_is_only_a_fence_is_refused() -> None:
    """After stripping there is nothing left, which is not a patch."""
    with pytest.raises(LlmContractError, match="no code to apply"):
        parse(answer("```python\n\n```"))


def test_an_enormous_replacement_is_refused() -> None:
    with pytest.raises(LlmContractError):
        parse(answer("x = 1\n" * 4000))
