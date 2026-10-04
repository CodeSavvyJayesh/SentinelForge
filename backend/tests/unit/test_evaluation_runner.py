"""Marking the analyser against an answer key, end to end.

The benchmark here is a handful of files written for the test, each chosen so
that one cell of the table is known in advance. The real analyser reads them:
nothing about how a finding is produced is stubbed, because the point of the
evaluation is that it measures the scanner people use.
"""

import io
import json
import sys
from pathlib import Path

import pytest

from app.cli import evaluate as evaluate_command
from app.cli.main import main
from app.evaluation import benchmark as benchmarks
from app.evaluation import render, runner
from app.evaluation.benchmark import DEVELOPMENT, HELD_OUT, BenchmarkError, split_of
from app.evaluation.compare import compare, load_outcomes
from app.evaluation.metrics import Confusion
from app.evaluation.runner import analyser_sha256, commit_of, evaluate

SHELL = "import os\n\n\ndef handle(value):\n    os.system(value)\n"
SHELL_AND_HASH = (
    "import os\nimport hashlib\n\n\ndef handle(value):\n"
    "    os.system(value)\n    return hashlib.md5(value).hexdigest()\n"
)
HASH = "import hashlib\n\n\ndef handle(value):\n    return hashlib.md5(value).hexdigest()\n"
QUIET = "def handle(value):\n    return value\n"

# name -> (category, vulnerable, cwe, source)
CASES: dict[str, tuple[str, bool, int, str]] = {
    "Case01": ("cmdi", True, 78, SHELL),  # reported, vulnerable: TP
    "Case02": ("cmdi", False, 78, SHELL),  # reported, safe: FP
    "Case03": ("cmdi", True, 78, QUIET),  # silent, vulnerable: FN
    "Case04": ("cmdi", False, 78, QUIET),  # silent, safe: TN
    "Case05": ("cmdi", True, 78, SHELL_AND_HASH),  # TP, plus a finding of another kind
    "Case06": ("hash", True, 328, HASH),  # TP
    "Case07": ("hash", False, 328, QUIET),  # TN
    "Case08": ("crypto", True, 327, SHELL),  # no rule; the finding is of another kind
    "Case09": ("crypto", False, 327, QUIET),
}


def build(tmp_path: Path, cases: dict[str, tuple[str, bool, int, str]] | None = None) -> Path:
    root = tmp_path / "benchmark"
    (root / "testcode").mkdir(parents=True)
    lines = ["# test name, category, real vulnerability, cwe, Benchmark version: 9.9, 2026\n"]
    for name, (category, vulnerable, cwe, source) in (cases or CASES).items():
        lines.append(f"{name},{category},{str(vulnerable).lower()},{cwe}\n")
        (root / "testcode" / f"{name}.py").write_bytes(source.encode())
    (root / "expectedresults-9.9.csv").write_bytes("".join(lines).encode())
    return root


def marked(root: Path, split: str = "all") -> runner.Evaluation:
    loaded = benchmarks.load(benchmarks.find_answer_key(root))
    return evaluate(root, loaded, name="Synthetic", split=split)


def run(*arguments: object) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main([str(item) for item in arguments], stdout=out, stderr=err, environ={})
    return code, out.getvalue(), err.getvalue()


# --- marking ----------------------------------------------------------------


def test_each_test_case_lands_in_the_cell_it_was_written_for(tmp_path: Path) -> None:
    evaluation = marked(build(tmp_path))
    verdicts = {item.case.name: item.verdict for item in evaluation.outcomes}

    assert verdicts == {
        "Case01": "TP",
        "Case02": "FP",
        "Case03": "FN",
        "Case04": "TN",
        "Case05": "TP",
        "Case06": "TP",
        "Case07": "TN",
        "Case08": "FN",
        "Case09": "TN",
    }
    by_category = {item.category: item for item in evaluation.categories}
    assert by_category["cmdi"].confusion == Confusion(tp=2, fp=1, tn=1, fn=1)
    assert by_category["hash"].confusion == Confusion(tp=1, fp=0, tn=1, fn=0)
    assert by_category["crypto"].confusion == Confusion(tp=0, fp=0, tn=1, fn=1)
    assert evaluation.pooled == Confusion(tp=3, fp=1, tn=3, fn=2)
    assert by_category["cmdi"].cwe == 78


def test_the_rules_that_answered_are_recorded(tmp_path: Path) -> None:
    evaluation = marked(build(tmp_path))
    rules = {item.case.name: item.rules for item in evaluation.outcomes}

    assert rules["Case01"] == ("PY003",)
    assert rules["Case06"] == ("PY007",)
    assert rules["Case03"] == ()


def test_a_finding_of_another_kind_is_counted_and_not_scored(tmp_path: Path) -> None:
    """A weak hash in a file about command injection is not an answer about injection."""
    evaluation = marked(build(tmp_path))

    # Case05's hash finding and Case08's shell finding.
    assert evaluation.unscored_in_cases == {"PY003": 1, "PY007": 1}
    # ...and Case08 is still a miss: reporting *something* in the file is not
    # reporting the weak cipher it was asked about.
    assert {item.case.name: item.reported for item in evaluation.outcomes}["Case08"] is False


def test_a_category_with_no_rule_says_so(tmp_path: Path) -> None:
    by_category = {item.category: item for item in marked(build(tmp_path)).categories}

    assert by_category["crypto"].rules == ()
    assert not by_category["crypto"].has_rule
    assert by_category["cmdi"].rules == ("PY002", "PY003", "PY016")
    assert render.verdict(by_category["crypto"]) == "no rule"


def test_the_two_overall_figures_differ_by_the_categories_without_a_rule(tmp_path: Path) -> None:
    evaluation = marked(build(tmp_path))

    # cmdi 2/3 - 1/2, hash 1 - 0, crypto 0 - 0
    assert evaluation.average("score") == pytest.approx((1 / 6 + 1 + 0) / 3)
    assert evaluation.average("score", only_with_rule=True) == pytest.approx((1 / 6 + 1) / 2)
    assert evaluation.pooled_with_rule == Confusion(tp=3, fp=1, tn=2, fn=1)
    assert [item.category for item in evaluation.with_rule] == ["cmdi", "hash"]


def test_findings_outside_test_cases_are_counted_apart(tmp_path: Path) -> None:
    root = build(tmp_path)
    (root / "helpers").mkdir()
    (root / "helpers" / "utils.py").write_bytes(SHELL.encode())

    evaluation = marked(root)

    assert evaluation.findings_outside_cases == 1
    assert evaluation.pooled == Confusion(tp=3, fp=1, tn=3, fn=2)


def test_the_page_that_calls_a_test_is_not_the_test(tmp_path: Path) -> None:
    """Benchmarks ship ``Case01.html`` beside ``Case01.py``; only the code is judged."""
    root = build(tmp_path)
    (root / "templates").mkdir()
    (root / "templates" / "Case04.html").write_bytes(b"<form>os.system(value)</form>")

    evaluation = marked(root)

    assert {item.case.name: item.verdict for item in evaluation.outcomes}["Case04"] == "TN"


def test_a_test_case_whose_file_was_not_read_stops_the_run(tmp_path: Path) -> None:
    """Otherwise code nobody looked at would be recorded as a miss or a correct silence."""
    root = build(tmp_path)
    (root / "testcode" / "Case03.py").rename(root / "testcode" / "Other.py")

    with pytest.raises(BenchmarkError, match=r"1 test case\(s\) .* first is Case03"):
        marked(root)


def test_two_files_claiming_one_test_case_stop_the_run(tmp_path: Path) -> None:
    root = build(tmp_path)
    (root / "copy").mkdir()
    (root / "copy" / "Case01.java").write_bytes(b"class Case01 {}")

    with pytest.raises(BenchmarkError, match="Two source files"):
        marked(root)


def test_reaching_the_findings_limit_stops_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runner, "EVALUATION_MAX_FINDINGS", 2)

    with pytest.raises(BenchmarkError, match="findings limit"):
        marked(build(tmp_path))


def test_the_same_benchmark_gives_the_same_bytes_twice(tmp_path: Path) -> None:
    root = build(tmp_path)
    first, second = marked(root), marked(root)

    assert json.dumps(render.as_data(first)) == json.dumps(render.as_data(second))
    assert render.as_markdown(first) == render.as_markdown(second)
    assert render.as_cases(first) == render.as_cases(second)
    assert first.outcomes_sha256 == second.outcomes_sha256


def test_windows_line_endings_in_the_benchmark_change_no_verdict(tmp_path: Path) -> None:
    unix = marked(build(tmp_path / "unix"))
    windows_cases = {
        name: (category, vulnerable, cwe, source.replace("\n", "\r\n"))
        for name, (category, vulnerable, cwe, source) in CASES.items()
    }
    windows = marked(build(tmp_path / "windows", windows_cases))

    assert windows.outcomes_sha256 == unix.outcomes_sha256


def test_one_changed_verdict_changes_the_outcome_hash(tmp_path: Path) -> None:
    before = marked(build(tmp_path / "a"))
    changed = dict(CASES)
    changed["Case04"] = ("cmdi", False, 78, SHELL)
    after = marked(build(tmp_path / "b", changed))

    assert before.outcomes_sha256 != after.outcomes_sha256


# --- halves -------------------------------------------------------------------


def test_marking_one_half_marks_only_that_half(tmp_path: Path) -> None:
    root = build(tmp_path)
    development = marked(root, DEVELOPMENT)
    held_out = marked(root, HELD_OUT)
    whole = marked(root)

    assert {item.case.name for item in development.outcomes} == {
        name for name in CASES if split_of(name) == DEVELOPMENT
    }
    assert len(development.outcomes) + len(held_out.outcomes) == len(whole.outcomes)
    assert development.pooled + held_out.pooled == whole.pooled
    assert development.outcomes and held_out.outcomes


def test_a_half_does_not_count_the_other_halfs_findings(tmp_path: Path) -> None:
    root = build(tmp_path)
    whole = sum(marked(root).unscored_in_cases.values())
    halves = sum(marked(root, DEVELOPMENT).unscored_in_cases.values()) + sum(
        marked(root, HELD_OUT).unscored_in_cases.values()
    )

    assert halves == whole
    assert marked(root, DEVELOPMENT).findings_outside_cases == 0


def test_a_half_with_no_test_cases_is_an_error(tmp_path: Path) -> None:
    only = next(name for name in CASES if split_of(name) == DEVELOPMENT)
    root = build(tmp_path, {only: CASES[only]})

    with pytest.raises(BenchmarkError, match="No test cases"):
        marked(root, HELD_OUT)


# --- provenance -----------------------------------------------------------------

COMMIT = "0123456789abcdef0123456789abcdef01234567"


def git(root: Path, head: str) -> Path:
    (root / ".git" / "refs" / "heads").mkdir(parents=True)
    (root / ".git" / "HEAD").write_text(head, encoding="utf-8")
    return root / ".git"


def test_the_commit_is_read_from_a_branch_file(tmp_path: Path) -> None:
    folder = git(tmp_path, "ref: refs/heads/main\n")
    (folder / "refs" / "heads" / "main").write_text(COMMIT + "\n", encoding="utf-8")

    assert commit_of(tmp_path) == COMMIT


def test_the_commit_is_read_from_packed_refs(tmp_path: Path) -> None:
    folder = git(tmp_path, "ref: refs/heads/main\n")
    (folder / "packed-refs").write_text(
        f"# pack-refs with: peeled fully-peeled sorted\n{'f' * 40} refs/heads/other\n"
        f"{COMMIT} refs/heads/main\n",
        encoding="utf-8",
    )

    assert commit_of(tmp_path) == COMMIT


def test_a_detached_head_is_the_commit(tmp_path: Path) -> None:
    git(tmp_path, COMMIT + "\n")

    assert commit_of(tmp_path) == COMMIT


@pytest.mark.parametrize(
    "head",
    [
        "ref: refs/heads/missing\n",
        "ref: refs/../../outside\n",
        "ref: /etc/passwd\n",
        "not a head at all\n",
        "0123\n",
    ],
)
def test_anything_else_is_no_commit_rather_than_a_guess(tmp_path: Path, head: str) -> None:
    git(tmp_path, head)
    (tmp_path / "outside").write_text(COMMIT, encoding="utf-8")

    assert commit_of(tmp_path) is None


def test_a_branch_file_that_does_not_hold_a_commit_is_not_reported(tmp_path: Path) -> None:
    folder = git(tmp_path, "ref: refs/heads/main\n")
    (folder / "refs" / "heads" / "main").write_text("<script>alert(1)</script>", encoding="utf-8")

    assert commit_of(tmp_path) is None


def test_a_folder_that_is_not_a_checkout_has_no_commit(tmp_path: Path) -> None:
    assert commit_of(tmp_path) is None
    assert marked(build(tmp_path)).commit is None


def test_the_analyser_hash_ignores_line_endings_and_notices_a_changed_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def hash_of(folder: Path, files: dict[str, bytes]) -> str:
        folder.mkdir()
        for name, content in files.items():
            (folder / name).write_bytes(content)
        monkeypatch.setattr(runner.analysis_package, "__file__", str(folder / "__init__.py"))
        return analyser_sha256()

    unix = hash_of(tmp_path / "a", {"__init__.py": b"", "rules.py": b"RULE = 1\nOTHER = 2\n"})
    windows = hash_of(
        tmp_path / "b", {"__init__.py": b"", "rules.py": b"RULE = 1\r\nOTHER = 2\r\n"}
    )
    changed = hash_of(tmp_path / "c", {"__init__.py": b"", "rules.py": b"RULE = 2\nOTHER = 2\n"})
    renamed = hash_of(tmp_path / "d", {"__init__.py": b"", "other.py": b"RULE = 1\nOTHER = 2\n"})

    assert unix == windows
    assert len({unix, changed, renamed}) == 3


def test_the_real_analyser_has_a_hash(tmp_path: Path) -> None:
    evaluation = marked(build(tmp_path))

    assert len(evaluation.analyser_sha256) == 64
    assert evaluation.analyser_sha256 == analyser_sha256()
    assert evaluation.version == "9.9"
    assert evaluation.tool_version


# --- what is written ---------------------------------------------------------------


def test_the_data_holds_counts_and_derives_everything_else(tmp_path: Path) -> None:
    data = render.as_data(marked(build(tmp_path)))
    cmdi = next(item for item in data["categories"] if item["category"] == "cmdi")

    assert data["schema"] == 1
    assert data["benchmark"]["test_cases"] == 9
    assert data["benchmark"]["split"] == "all"
    assert (cmdi["tp"], cmdi["fn"], cmdi["fp"], cmdi["tn"]) == (2, 1, 1, 1)
    assert cmdi["recall"] == 0.6667
    assert cmdi["false_positive_rate"] == 0.5
    assert cmdi["score"] == 0.1667
    assert cmdi["rules"] == ["PY002", "PY003", "PY016"]
    assert data["overall"]["all_categories"]["categories"] == 3
    assert data["overall"]["categories_with_a_rule"]["categories"] == 2
    assert data["overall"]["all_categories"]["pooled"]["tp"] == 3
    assert data["unscored_findings"] == {
        "in_test_cases_by_rule": {"PY003": 1, "PY007": 1},
        "outside_test_cases": 0,
    }
    assert "compared_with_earlier_run" not in data


def test_an_undefined_ratio_is_null_in_data_and_a_dash_on_the_page(tmp_path: Path) -> None:
    evaluation = marked(build(tmp_path))
    data = render.as_data(evaluation)
    crypto = next(item for item in data["categories"] if item["category"] == "crypto")

    assert crypto["precision"] is None
    assert crypto["precision_interval"] is None
    assert crypto["f1"] == 0.0
    row = next(
        line for line in render.as_markdown(evaluation).splitlines() if "| crypto | 327" in line
    )
    assert "| – |" in row
    assert "no rule" in row


def test_the_table_states_where_the_numbers_came_from(tmp_path: Path) -> None:
    root = build(tmp_path)
    folder = git(root, "ref: refs/heads/main\n")
    (folder / "refs" / "heads" / "main").write_text(COMMIT, encoding="utf-8")

    page = render.as_markdown(marked(root))

    assert f"| Benchmark commit | `{COMMIT}` |" in page
    assert "| Benchmark | Synthetic, version 9.9 |" in page
    assert "| Test cases marked | 9 (the whole benchmark) |" in page
    assert "| Vulnerable / safe | 5 / 4 |" in page
    assert "| cmdi | 78 | 5 | 2 | 1 | 1 | 1 | 66.7 % | 50.0 % | 66.7 % | 66.7 % | +16.7 |" in page
    assert "| crypto | none: every vulnerable case is missed |" in page
    assert "| PY007 | 1 |" in page


def test_a_benchmark_name_cannot_write_markdown(tmp_path: Path) -> None:
    root = build(tmp_path)
    loaded = benchmarks.load(benchmarks.find_answer_key(root))
    evaluation = evaluate(root, loaded, name="x](http://evil) <script>|")

    page = render.as_markdown(evaluation)

    assert "<script>" not in page
    # The bracket and the bar are escaped, so there is no link and no extra cell.
    assert "x\\](http://evil) &lt;script&gt;\\|" in page


def test_formatting_of_a_score() -> None:
    assert render.points(0.2167) == "+21.7"
    assert render.points(-0.4615) == "-46.2"
    assert render.points(0.0) == "0.0"
    # Never "-0.0": a score that rounds to nothing is nothing.
    assert render.points(-0.0004) == "0.0"
    assert render.points(None) == "–"
    assert render.percent(None) == "–"
    assert render.percent(0.21705) == "21.7 %"


def test_the_reading_says_when_a_score_is_only_noise() -> None:
    def reading(confusion: Confusion, rules: tuple[str, ...] = ("PY003",)) -> str:
        return render.verdict(runner.CategoryResult("cmdi", 78, confusion, rules))

    assert reading(Confusion(tp=90, fn=10, fp=10, tn=90)) == "better than guessing"
    assert reading(Confusion(tp=10, fn=90, fp=90, tn=10)) == "worse than guessing"
    assert reading(Confusion(tp=2, fn=1, fp=1, tn=2)) == "not distinguishable from guessing"
    assert reading(Confusion(tp=0, fn=5, fp=0, tn=5)) == "not distinguishable from guessing"
    assert reading(Confusion(tp=90, fn=10, fp=10, tn=90), ()) == "no rule"
    assert reading(Confusion(tp=1, fn=1)) == "–"


def test_every_test_case_is_listed_with_its_verdict(tmp_path: Path) -> None:
    lines = render.as_cases(marked(build(tmp_path))).splitlines()

    assert lines[0] == "name,category,cwe,vulnerable,reported,verdict,rules,split"
    assert lines[1] == f"Case01,cmdi,78,yes,yes,TP,PY003,{split_of('Case01')}"
    assert f"Case03,cmdi,78,yes,no,FN,,{split_of('Case03')}" in lines
    assert len(lines) == 10


# --- comparing two runs --------------------------------------------------------------


def outcomes_file(tmp_path: Path, evaluation: runner.Evaluation) -> Path:
    path = tmp_path / "earlier.csv"
    path.write_text(render.as_cases(evaluation), encoding="utf-8", newline="")
    return path


def test_a_run_compared_with_itself_changed_nothing(tmp_path: Path) -> None:
    evaluation = marked(build(tmp_path))
    comparison = compare(load_outcomes(outcomes_file(tmp_path, evaluation)), evaluation)

    assert (comparison.fixed, comparison.broken, comparison.net) == (0, 0, 0)
    assert comparison.p_value is None
    assert comparison.cases == 9


def test_fixed_and_broken_cases_are_counted_separately(tmp_path: Path) -> None:
    evaluation = marked(build(tmp_path))
    earlier = {item.case.name: item.reported for item in evaluation.outcomes}
    earlier["Case01"] = False  # was a miss, now caught: fixed
    earlier["Case02"] = False  # was correctly silent, now a false alarm: broken
    earlier["Case03"] = True  # was caught, now missed: broken

    comparison = compare(earlier, evaluation)

    assert (comparison.fixed, comparison.broken, comparison.net) == (1, 2, -1)
    assert comparison.p_value == pytest.approx(1.0)


def test_a_comparison_needs_every_case_to_have_been_judged_before(tmp_path: Path) -> None:
    evaluation = marked(build(tmp_path))
    earlier = {item.case.name: item.reported for item in evaluation.outcomes}
    del earlier["Case07"]

    with pytest.raises(BenchmarkError, match="no outcome for 1 .* first is Case07"):
        compare(earlier, evaluation)


def test_a_whole_run_can_be_the_earlier_run_for_one_half(tmp_path: Path) -> None:
    root = build(tmp_path)
    earlier = load_outcomes(outcomes_file(tmp_path, marked(root)))

    comparison = compare(earlier, marked(root, HELD_OUT))

    assert comparison.cases == len(marked(root, HELD_OUT).outcomes)
    assert comparison.net == 0


@pytest.mark.parametrize(
    "content",
    [
        "name,verdict\nCase01,TP\n",
        "name,reported\nCase01,perhaps\n",
        "name,reported\n../x,yes\n",
        "name,reported\nCase01,yes\nCase01,no\n",
        "",
    ],
)
def test_an_outcomes_file_that_is_not_one_is_refused(tmp_path: Path, content: str) -> None:
    path = tmp_path / "earlier.csv"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(BenchmarkError):
        load_outcomes(path)


def test_a_missing_outcomes_file_is_refused(tmp_path: Path) -> None:
    with pytest.raises(BenchmarkError, match="not a regular file"):
        load_outcomes(tmp_path / "nothing.csv")


def test_the_comparison_is_written_into_both_documents(tmp_path: Path) -> None:
    evaluation = marked(build(tmp_path))
    earlier = {item.case.name: item.reported for item in evaluation.outcomes}
    for name in ("Case01", "Case05", "Case06"):
        earlier[name] = False
    comparison = compare(earlier, evaluation)

    data = render.as_data(evaluation, comparison)
    page = render.as_markdown(evaluation, comparison)

    assert data["compared_with_earlier_run"] == {
        "test_cases": 9,
        "fixed": 3,
        "broken": 0,
        "mcnemar_p_value": 0.25,
    }
    assert "3 correctly that the earlier run got wrong" in page
    assert "(net +3)" in page
    assert "p = 0.25" in page


# --- the command -----------------------------------------------------------------------


def test_the_command_marks_a_benchmark_and_exits_zero_whatever_the_score(tmp_path: Path) -> None:
    code, out, err = run("evaluate", build(tmp_path), "--name", "Synthetic")

    assert code == 0
    assert err == ""
    assert "against Synthetic 9.9" in out
    assert "9 test cases (all): 5 vulnerable, 4 safe" in out
    assert "cmdi" in out and "+16.7" in out
    assert "average over every category (3)" in out
    assert "average over categories with a rule (2)" in out
    assert "not scored: 2 finding(s) of another kind in test cases, 0 outside test cases" in out


def test_the_command_writes_three_files_with_unix_line_endings(tmp_path: Path) -> None:
    out_dir = tmp_path / "out" / "nested"
    code, _out, _err = run(
        "evaluate", build(tmp_path),
        "--json", out_dir / "r.json", "--markdown", out_dir / "r.md", "--cases", out_dir / "r.csv",
    )  # fmt: skip

    assert code == 0
    for name in ("r.json", "r.md", "r.csv"):
        content = (out_dir / name).read_bytes()
        assert content.endswith(b"\n")
        assert b"\r" not in content
    assert json.loads((out_dir / "r.json").read_text(encoding="utf-8"))["schema"] == 1


def test_check_passes_when_the_run_reproduces_the_record(tmp_path: Path) -> None:
    root = build(tmp_path)
    record = tmp_path / "record.json"
    run("evaluate", root, "--json", record)

    code, out, _err = run("evaluate", root, "--check", record)

    assert code == 0
    assert "REPRODUCED" in out


def test_check_fails_with_exit_one_and_names_what_changed(tmp_path: Path) -> None:
    root = build(tmp_path)
    record = tmp_path / "record.json"
    run("evaluate", root, "--json", record)
    (root / "testcode" / "Case04.py").write_bytes(SHELL.encode())

    code, out, _err = run("evaluate", root, "--check", record)

    assert code == 1
    assert "DIFFERENT from the recorded results" in out
    assert "cmdi: recorded TP/FN/FP/TN 2/1/1/1, now 2/1/2/0" in out
    assert "REPRODUCED" not in out


def test_check_notices_when_totals_agree_and_cases_do_not(tmp_path: Path) -> None:
    root = build(tmp_path)
    record = tmp_path / "record.json"
    run("evaluate", root, "--json", record)
    # Swap which of the two safe cmdi cases is the false alarm.
    (root / "testcode" / "Case02.py").write_bytes(QUIET.encode())
    (root / "testcode" / "Case04.py").write_bytes(SHELL.encode())

    code, out, _err = run("evaluate", root, "--check", record)

    assert code == 1
    assert "individual test cases were judged differently" in out


def test_check_notices_a_different_answer_key_and_a_different_half(tmp_path: Path) -> None:
    root = build(tmp_path)
    record = tmp_path / "record.json"
    run("evaluate", root, "--json", record)

    code, out, _err = run("evaluate", root, "--check", record, "--split", "held-out")

    assert code == 1
    assert "a different half of the benchmark was marked (recorded all, now held-out)" in out

    with (root / "expectedresults-9.9.csv").open("ab") as handle:
        handle.write(b"\n")
    code, out, _err = run("evaluate", root, "--check", record)
    assert code == 1
    assert "the answer key is a different file" in out


def test_check_reports_categories_that_came_or_went() -> None:
    def data(categories: list[str]) -> dict[str, object]:
        return {
            "benchmark": {"answer_key_sha256": "k", "split": "all", "test_cases": 1},
            "analyser": {"sha256": "a"},
            "categories": [
                {"category": name, "tp": 1, "fn": 0, "fp": 0, "tn": 0} for name in categories
            ],
            "outcomes_sha256": "o",
        }

    differences = evaluate_command.differences_from(data(["cmdi", "hash"]), data(["cmdi", "xss"]))

    assert differences == [
        "xss: not in the recorded results",
        "hash: recorded, and not in this run",
    ]
    assert evaluate_command.differences_from(data(["cmdi"]), data(["cmdi"])) == []


def test_check_mentions_a_changed_analyser_only_when_results_changed() -> None:
    def data(sha: str, tp: int) -> dict[str, object]:
        return {
            "benchmark": {"answer_key_sha256": "k", "split": "all", "test_cases": 1},
            "analyser": {"sha256": sha},
            "categories": [{"category": "cmdi", "tp": tp, "fn": 0, "fp": 0, "tn": 0}],
            "outcomes_sha256": "o",
        }

    assert evaluate_command.differences_from(data("a", 1), data("b", 1)) == []
    assert evaluate_command.differences_from(data("a", 1), data("b", 2))[-1].startswith(
        "the analyser's source is not the recorded one"
    )
    assert len(evaluate_command.differences_from(data("a", 1), data("a", 2))) == 1


@pytest.mark.parametrize("content", ["not json", "[]", '{"schema": 99}', "{}"])
def test_a_record_that_cannot_be_read_is_exit_two(tmp_path: Path, content: str) -> None:
    record = tmp_path / "record.json"
    record.write_text(content, encoding="utf-8")

    code, _out, err = run("evaluate", build(tmp_path), "--check", record)

    assert code == 2
    assert err.startswith("error: The recorded results")


def test_compare_prints_what_changed(tmp_path: Path) -> None:
    root = build(tmp_path)
    earlier = tmp_path / "earlier.csv"
    run("evaluate", root, "--cases", earlier)
    (root / "testcode" / "Case03.py").write_bytes(SHELL.encode())

    code, out, _err = run("evaluate", root, "--compare", earlier)

    assert code == 0
    assert "against the earlier run: 1 fixed, 0 broken (net +1); McNemar p = 1" in out


@pytest.mark.parametrize(
    ("arrange", "message"),
    [
        (lambda root: (root / "expectedresults-9.9.csv").unlink(), "found none"),
        (
            lambda root: (root / "expectedresults-1.csv").write_text("A,sqli,true,89\n"),
            "found 2 of them",
        ),
        (lambda root: (root / "testcode" / "Case01.py").unlink(), "no source file that was read"),
        (
            lambda root: (root / "expectedresults-9.9.csv").write_text("Case01,cmdi,perhaps,78\n"),
            "true or false",
        ),
    ],
)
def test_a_benchmark_that_cannot_be_marked_is_exit_two(tmp_path, arrange, message) -> None:  # type: ignore[no-untyped-def]
    root = build(tmp_path)
    arrange(root)

    code, out, err = run("evaluate", root)

    assert code == 2
    assert message in err
    assert out == ""


def test_a_path_that_is_not_a_folder_is_exit_two(tmp_path: Path) -> None:
    code, _out, err = run("evaluate", tmp_path / "missing")

    assert code == 2
    assert "not a folder" in err


def test_an_answer_key_can_be_named(tmp_path: Path) -> None:
    root = build(tmp_path)
    key = tmp_path / "answers.csv"
    key.write_text("Case01,cmdi,true,78\nCase02,cmdi,false,78\n", encoding="utf-8")

    code, out, _err = run("evaluate", root, "--expected", key)

    assert code == 0
    assert "2 test cases (all): 1 vulnerable, 1 safe" in out


def test_a_results_file_that_cannot_be_written_is_exit_two(tmp_path: Path) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("a file, not a folder", encoding="utf-8")

    code, _out, err = run("evaluate", build(tmp_path), "--json", blocker / "r.json")

    assert code == 2
    assert "could not write the results" in err


def test_a_benchmark_name_cannot_write_to_the_terminal(tmp_path: Path) -> None:
    code, out, _err = run("evaluate", build(tmp_path), "--name", "evil\x1b[2J\n::error::x")

    assert code == 0
    assert "\x1b" not in out
    assert "\n::error::" not in out


def test_scan_still_works_beside_the_new_command(tmp_path: Path) -> None:
    code, out, _err = run("scan", build(tmp_path), "--fail-on", "none")

    assert code == 0
    assert "PASSED" in out


# --- files the interpreter cannot parse ----------------------------------------------


def test_a_test_case_that_does_not_parse_stops_the_run(tmp_path: Path) -> None:
    """The first real measurement silently skipped 470 files this way."""
    root = build(tmp_path)
    (root / "testcode" / "Case04.py").write_bytes(b"def broken(:\n    pass\n")

    with pytest.raises(
        BenchmarkError, match=r"1 test case file\(s\) could not be parsed"
    ) as caught:
        marked(root)

    assert "testcode/Case04.py" in str(caught.value)
    assert f"Python {runner.python_version()}" in str(caught.value)


def test_a_file_that_does_not_parse_and_is_not_a_test_case_is_not_an_obstacle(
    tmp_path: Path,
) -> None:
    root = build(tmp_path)
    (root / "scripts").mkdir()
    (root / "scripts" / "old.py").write_bytes(b"print 'python 2'\n")

    assert marked(root).pooled == Confusion(tp=3, fp=1, tn=3, fn=2)


def test_an_unparsable_test_case_in_the_other_half_still_stops_the_run(tmp_path: Path) -> None:
    """The whole benchmark is analysed whichever half is marked; so is this check."""
    root = build(tmp_path)
    victim = next(name for name in CASES if split_of(name) == HELD_OUT)
    (root / "testcode" / f"{victim}.py").write_bytes(b"def broken(:\n")

    with pytest.raises(BenchmarkError, match="could not be parsed"):
        marked(root, DEVELOPMENT)


def test_the_interpreter_that_parsed_the_benchmark_is_recorded(tmp_path: Path) -> None:
    evaluation = marked(build(tmp_path))

    assert evaluation.python_version == f"{sys.version_info.major}.{sys.version_info.minor}"
    assert render.as_data(evaluation)["analyser"]["python"] == evaluation.python_version
    assert f"| Parsed with | Python {evaluation.python_version} |" in render.as_markdown(evaluation)


def test_forty_characters_that_are_not_a_commit_are_not_reported_as_one(tmp_path: Path) -> None:
    folder = git(tmp_path, "ref: refs/heads/main\n")
    (folder / "refs" / "heads" / "main").write_text("z" * 40, encoding="utf-8")

    assert commit_of(tmp_path) is None
    assert commit_of(git(tmp_path / "detached", "G" * 40 + "\n").parent) is None
