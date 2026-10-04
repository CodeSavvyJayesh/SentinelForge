"""Reading an answer key that somebody else wrote."""

from pathlib import Path

import pytest

from app.analysis.rules import ALL_RULES
from app.evaluation import benchmark as benchmarks
from app.evaluation.benchmark import (
    ALL,
    DEVELOPMENT,
    HELD_OUT,
    BenchmarkError,
    TestCase,
    find_answer_key,
    load,
    parse,
    split_of,
)
from app.evaluation.mapping import NOT_IN_BENCHMARK, RULE_CATEGORY, reads, rules_for

HEADER = "# test name, category, real vulnerability, cwe, Benchmark version: 1.2, 2016-06-1\n"
# Every category either OWASP Benchmark uses. A rule assigned to a name that is
# not here would never be credited with anything and nobody would be told.
BENCHMARK_CATEGORIES = {
    "cmdi", "codeinj", "crypto", "deserialization", "hash", "ldapi", "pathtraver", "redirect",
    "securecookie", "sqli", "trustbound", "weakrand", "xpathi", "xss", "xxe",
}  # fmt: skip


def test_an_answer_key_is_read_line_by_line() -> None:
    loaded = parse(
        HEADER + "BenchmarkTest00001,pathtraver,true,22\nBenchmarkTest00002,hash,false,328\n"
    )

    assert loaded.cases == (
        TestCase("BenchmarkTest00001", "pathtraver", True, 22),
        TestCase("BenchmarkTest00002", "hash", False, 328),
    )
    assert loaded.version == "1.2"
    assert loaded.categories == ("hash", "pathtraver")


def test_windows_line_endings_a_byte_order_mark_and_blank_lines_change_nothing(
    tmp_path: Path,
) -> None:
    path = tmp_path / "expectedresults-1.2.csv"
    path.write_bytes(
        b"\xef\xbb\xbf# name, category, real vulnerability, cwe, Benchmark version: 0.1, 2026\r\n"
        b"\r\nCaseA , sqli , TRUE , 89\r\nCaseB,sqli,False,89\r\n\r\n"
    )

    loaded = load(path)

    assert [(case.name, case.vulnerable) for case in loaded.cases] == [
        ("CaseA", True),
        ("CaseB", False),
    ]
    assert loaded.version == "0.1"
    assert len(loaded.answer_key_sha256) == 64


def test_a_key_without_a_version_has_none() -> None:
    assert parse("CaseA,sqli,true,89\n").version is None


@pytest.mark.parametrize(
    ("line", "complaint"),
    [
        ("CaseA,sqli,true", "fewer than four fields"),
        ("../../etc/passwd,sqli,true,89", "unusable test name"),
        ("Case A,sqli,true,89", "unusable test name"),
        ("CaseA,SQL Injection,true,89", "unusable category"),
        ("CaseA,sqli,maybe,89", "true or false"),
        ("CaseA,sqli,true,eighty-nine", "unusable CWE"),
        ("CaseA,sqli,true,-89", "unusable CWE"),
        ("CaseA,sqli,true,٨٩", "unusable CWE"),
        ("CaseA,sqli,true,1234567", "unusable CWE"),
    ],
)
def test_a_line_that_is_not_an_answer_is_refused_by_number(line: str, complaint: str) -> None:
    with pytest.raises(BenchmarkError, match=complaint) as caught:
        parse(HEADER + "Good,sqli,true,89\n" + line + "\n")

    assert "Line 3" in str(caught.value)


def test_two_answers_for_one_test_are_refused_rather_than_one_being_picked() -> None:
    with pytest.raises(BenchmarkError, match="Line 2 .* repeats"):
        parse("CaseA,sqli,true,89\nCaseA,sqli,false,89\n")


def test_an_empty_key_is_refused() -> None:
    with pytest.raises(BenchmarkError, match="no test cases"):
        parse(HEADER + "\n\n")


def test_an_oversized_or_unreadable_key_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "expectedresults-1.csv"
    path.write_text("CaseA,sqli,true,89\n", encoding="utf-8")
    monkeypatch.setattr(benchmarks, "MAX_ANSWER_KEY_BYTES", 5)

    with pytest.raises(BenchmarkError, match="larger"):
        load(path)
    with pytest.raises(BenchmarkError, match="not a regular file"):
        load(tmp_path / "missing.csv")


def test_a_key_that_is_not_text_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "expectedresults-1.csv"
    path.write_bytes(b"\xff\xfe\x00\x00binary")

    with pytest.raises(BenchmarkError, match="not UTF-8"):
        load(path)


def test_too_many_test_cases_are_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(benchmarks, "MAX_TEST_CASES", 2)

    with pytest.raises(BenchmarkError, match="more test cases"):
        parse("A,sqli,true,89\nB,sqli,true,89\nC,sqli,true,89\n")
    assert len(parse("A,sqli,true,89\nB,sqli,true,89\n").cases) == 2


def test_the_answer_key_is_found_when_there_is_exactly_one(tmp_path: Path) -> None:
    (tmp_path / "expectedresults-1.2.csv").write_text("A,sqli,true,89\n", encoding="utf-8")
    (tmp_path / "notes.csv").write_text("x", encoding="utf-8")

    assert find_answer_key(tmp_path).name == "expectedresults-1.2.csv"


def test_no_answer_key_or_two_of_them_is_an_error_not_a_guess(tmp_path: Path) -> None:
    with pytest.raises(BenchmarkError, match="found none"):
        find_answer_key(tmp_path)

    (tmp_path / "expectedresults-1.1.csv").write_text("A,sqli,true,89\n", encoding="utf-8")
    (tmp_path / "expectedresults-1.2.csv").write_text("A,sqli,true,89\n", encoding="utf-8")
    with pytest.raises(BenchmarkError, match="found 2 of them"):
        find_answer_key(tmp_path)


# --- the split --------------------------------------------------------------


def test_the_split_is_pinned() -> None:
    """These values are the split. If this test changes, held-out is no longer held out."""
    assert split_of("BenchmarkTest00001") == DEVELOPMENT
    assert split_of("BenchmarkTest00002") == DEVELOPMENT
    assert split_of("BenchmarkTest00003") == HELD_OUT
    assert split_of("BenchmarkTest00006") == DEVELOPMENT
    assert split_of("BenchmarkTest00008") == HELD_OUT
    assert split_of("BenchmarkTest02740") == HELD_OUT


def test_the_split_is_two_halves_that_share_nothing_and_miss_nothing() -> None:
    names = [f"BenchmarkTest{number:05d}" for number in range(1, 2741)]
    loaded = parse("".join(f"{name},sqli,true,89\n" for name in names), "key")

    development = {case.name for case in loaded.half(DEVELOPMENT).cases}
    held_out = {case.name for case in loaded.half(HELD_OUT).cases}

    assert development | held_out == set(names)
    assert not development & held_out
    assert len(development) == 1351
    assert len(held_out) == 1389
    assert loaded.half(ALL) is loaded
    assert loaded.half(HELD_OUT).answer_key_sha256 == "key"


def test_the_split_does_not_depend_on_the_order_or_the_answers() -> None:
    forwards = parse("A,sqli,true,89\nB,sqli,false,89\nC,hash,true,328\nD,hash,false,328\n")
    backwards = parse("D,xss,true,79\nC,xss,true,79\nB,xss,true,79\nA,xss,true,79\n")

    assert {case.name for case in forwards.half(HELD_OUT).cases} == {
        case.name for case in backwards.half(HELD_OUT).cases
    }


def test_an_unknown_split_is_refused() -> None:
    with pytest.raises(BenchmarkError, match="Unknown split"):
        parse("A,sqli,true,89\n").half("test")


# --- which rule answers which question ---------------------------------------


def test_every_rule_is_assigned_to_a_category_or_declared_outside_the_benchmark() -> None:
    every_rule = {rule.id for rule in ALL_RULES}

    assert set(RULE_CATEGORY) | NOT_IN_BENCHMARK == every_rule
    assert not set(RULE_CATEGORY) & NOT_IN_BENCHMARK


def test_rules_are_only_assigned_to_categories_a_benchmark_has() -> None:
    assert set(RULE_CATEGORY.values()) <= BENCHMARK_CATEGORIES


def test_a_rule_answers_the_weakness_it_already_declared() -> None:
    """The table follows the rule catalogue; it is not free to be convenient."""
    declared = {rule.id: rule.cwe_id for rule in ALL_RULES}
    expected_cwes = {
        "cmdi": {"CWE-78"},
        "sqli": {"CWE-89"},
        "codeinj": {"CWE-94", "CWE-95"},
        "deserialization": {"CWE-502"},
        "hash": {"CWE-327", "CWE-328"},
        "weakrand": {"CWE-330", "CWE-338"},
        "xss": {"CWE-79"},
        "xxe": {"CWE-611"},
        "crypto": {"CWE-327"},
        "pathtraver": {"CWE-22"},
        "securecookie": {"CWE-614"},
        "redirect": {"CWE-601"},
        "ldapi": {"CWE-90"},
        "xpathi": {"CWE-643"},
        "trustbound": {"CWE-501"},
    }

    for rule_id, category in RULE_CATEGORY.items():
        assert declared[rule_id] in expected_cwes[category], rule_id


def test_a_rule_only_counts_for_a_language_it_reads() -> None:
    assert reads("PY003", ".py")
    assert not reads("PY003", ".java")
    assert reads("JV003", ".java")
    assert not reads("JV003", ".py")
    assert reads("SQL001", ".java")
    assert not reads("SQL001", ".py")
    assert reads("SEC001", ".anything")


def test_a_category_with_no_rule_for_the_language_has_no_rules() -> None:
    assert rules_for("cmdi", frozenset({".py"})) == ("PY002", "PY003")
    assert "JV001" in rules_for("cmdi", frozenset({".java"}))
    assert "PY003" not in rules_for("cmdi", frozenset({".java"}))
    assert rules_for("no-such-category", frozenset({".py"})) == ()
    assert rules_for("cmdi", frozenset()) == ()
