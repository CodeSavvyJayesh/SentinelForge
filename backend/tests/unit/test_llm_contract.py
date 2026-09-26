"""What the model is allowed to say.

This is the security file of Phase 8. Every test here is a claim about output
that has already left a language model's hands and is on its way to a
developer's screen, where it will be read as security advice.

The one that matters most is citation checking. A model that invents a source
is indistinguishable, at a glance, from one that cites a real one — the text
looks identical. The only thing that can tell them apart is that we know
exactly which passages it was handed.
"""

import json

import pytest

from app.llm.contract import (
    MAX_FIELD_CHARS,
    LlmContractError,
    parse,
    sanitise,
)


def answer(**overrides) -> str:  # noqa: ANN003
    payload = {
        "summary": "MD5 is used to hash a password.",
        "impact": "An attacker with the database can recover passwords quickly.",
        "remediation": "Use a password hash such as scrypt or Argon2.",
        "citations": [1],
    }
    payload.update(overrides)
    return json.dumps(payload)


# --- the happy path -------------------------------------------------------


def test_a_well_formed_answer_survives_intact() -> None:
    parsed = parse(answer(), passage_count=3)
    assert parsed.summary == "MD5 is used to hash a password."
    assert parsed.citations == [1]
    assert parsed.dropped_citations == 0
    assert parsed.grounded is True


# --- invented citations ---------------------------------------------------


def test_a_citation_to_a_passage_that_was_never_given_is_dropped() -> None:
    """The model was handed two passages and cited a seventh. There is no
    seventh; the reference is to a source that does not exist."""
    parsed = parse(answer(citations=[1, 7]), passage_count=2)
    assert parsed.citations == [1]
    assert parsed.dropped_citations == 1


def test_a_zero_or_negative_citation_is_dropped() -> None:
    """Passages are numbered from 1. Zero is a model counting from zero, and a
    negative is noise — neither points at anything."""
    parsed = parse(answer(citations=[0, -1, 2]), passage_count=3)
    assert parsed.citations == [2]
    assert parsed.dropped_citations == 2


def test_an_answer_citing_nothing_real_is_marked_ungrounded() -> None:
    """Not rejected — flagged. An explanation with no sources may still be
    correct, and "the model wrote this without reference to anything" is
    precisely what a reader should be told rather than shielded from."""
    parsed = parse(answer(citations=[9, 10]), passage_count=2)
    assert parsed.citations == []
    assert parsed.grounded is False
    assert parsed.dropped_citations == 2


def test_duplicate_citations_are_collapsed() -> None:
    parsed = parse(answer(citations=[1, 1, 2]), passage_count=2)
    assert parsed.citations == [1, 2]


def test_inline_markers_pointing_nowhere_are_removed_from_the_prose() -> None:
    """A reader trusts "[7]" in a sentence exactly as much as one in a list.
    Renumbering it to match a surviving citation would be inventing an
    attribution, so it goes."""
    parsed = parse(
        answer(summary="MD5 is broken [7] and unsuitable here [1].", citations=[1]),
        passage_count=2,
    )
    assert "[7]" not in parsed.summary
    assert "[1]" in parsed.summary
    assert parsed.dropped_citations == 1


def test_a_partially_valid_inline_marker_keeps_only_the_real_numbers() -> None:
    parsed = parse(answer(summary="See [1, 9] for detail.", citations=[1]), passage_count=2)
    assert "[1]" in parsed.summary
    assert "9" not in parsed.summary


# --- links ----------------------------------------------------------------


def test_model_authored_links_are_stripped() -> None:
    """The only URLs a reader sees come from real passages in our own knowledge
    base. A link the model made up points wherever it felt like, dressed as
    security guidance."""
    parsed = parse(
        answer(remediation="Read https://totally-real-security.example/fix for details."),
        passage_count=1,
    )
    assert "http" not in parsed.remediation
    assert parsed.links_removed == 1


def test_link_stripping_counts_every_one() -> None:
    parsed = parse(
        answer(
            summary="See http://a.example",
            impact="And https://b.example",
            remediation="And ftp://c.example",
        ),
        passage_count=1,
    )
    assert parsed.links_removed == 3


# --- control characters ---------------------------------------------------


def test_control_characters_are_removed_but_paragraphs_survive() -> None:
    """Control characters belong to terminals, not to prose, and are how output
    smuggles formatting past a reader. Newlines are structure and stay."""
    cleaned, _ = sanitise("line one\n\nline two\x07\x1b[31mred\x00")
    assert "\n\n" in cleaned
    assert "\x07" not in cleaned
    assert "\x1b" not in cleaned
    assert "\x00" not in cleaned


# --- shape enforcement ----------------------------------------------------


def test_output_that_is_not_json_is_refused() -> None:
    with pytest.raises(LlmContractError, match="not valid JSON"):
        parse("Sure! Here's my analysis:", passage_count=1)


def test_a_json_array_is_refused() -> None:
    with pytest.raises(LlmContractError, match="not a JSON object"):
        parse('["summary"]', passage_count=1)


def test_a_missing_field_is_refused() -> None:
    """Storing two of three fields and calling it an explanation would be worse
    than failing: the queue retries a failure, and nobody reviews a gap."""
    with pytest.raises(LlmContractError, match="did not fit the required format"):
        parse(json.dumps({"summary": "x", "impact": "y"}), passage_count=1)


def test_an_enormous_field_is_refused() -> None:
    with pytest.raises(LlmContractError, match="did not fit the required format"):
        parse(answer(summary="x" * (MAX_FIELD_CHARS + 1)), passage_count=1)


def test_a_field_that_is_only_a_link_is_refused_rather_than_stored_empty() -> None:
    """Stripping the link leaves nothing. An empty remediation that renders as
    blank space is a worse answer than an honest failure."""
    with pytest.raises(LlmContractError, match="empty after cleaning"):
        parse(answer(remediation="https://example.invalid/fix"), passage_count=1)


def test_the_error_message_never_carries_the_model_output() -> None:
    """Pydantic embeds the offending value in its errors, and here that value is
    unvalidated model output of unknown length and content."""
    secret = "sup3r" + "-s3cret-value"
    with pytest.raises(LlmContractError) as caught:
        parse(
            json.dumps({"summary": secret * 400, "impact": "y", "remediation": "z"}),
            passage_count=1,
        )
    assert secret not in str(caught.value)


# --- tolerated sloppiness -------------------------------------------------


def test_a_field_returned_as_a_list_of_sentences_is_accepted() -> None:
    """Small models do this constantly. Failing a job over punctuation would
    make the feature unreliable for no gain in safety."""
    parsed = parse(answer(impact=["First point.", "Second point."]), passage_count=1)
    assert parsed.impact == "First point. Second point."


def test_citations_given_as_strings_are_understood() -> None:
    parsed = parse(answer(citations=["[1]", "passage 2", "nonsense"]), passage_count=2)
    assert parsed.citations == [1, 2]


def test_a_missing_citations_field_is_not_an_error() -> None:
    payload = json.loads(answer())
    del payload["citations"]
    parsed = parse(json.dumps(payload), passage_count=2)
    assert parsed.citations == []
    assert parsed.grounded is False
