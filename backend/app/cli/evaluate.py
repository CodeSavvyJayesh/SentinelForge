"""``python -m app.cli evaluate`` — mark the analyser against a benchmark.

Exit codes keep the meaning they have for ``scan``:

* ``0`` — the benchmark was marked (and, with ``--check``, the result is the
  recorded one).
* ``1`` — ``--check`` was given and the result is not the recorded one.
* ``2`` — the benchmark could not be marked as asked.

A low score is not a failure of this command. It exits 0 with the low score
written down: a measurement that refuses to report a bad number is not one.
"""

import argparse
import json
from pathlib import Path
from typing import Any, TextIO

from app.cli.text import plain
from app.evaluation import benchmark as benchmarks
from app.evaluation import render
from app.evaluation.compare import Comparison, compare, load_outcomes
from app.evaluation.runner import Evaluation, evaluate

EXIT_OK = 0
EXIT_DIFFERENT = 1
EXIT_ERROR = 2

MAX_RECORDED_BYTES = 5 * 1024 * 1024


def add_parser(commands: Any) -> None:
    command = commands.add_parser(
        "evaluate",
        help="mark the analyser against a benchmark with known answers",
        description=(
            "Analyse a benchmark folder (nothing in it is executed) and mark the result "
            "against its answer key. Exit code 0: marked. 1: --check found a different "
            "result. 2: the benchmark could not be marked."
        ),
    )
    command.add_argument("path", type=Path, help="the benchmark folder")
    command.add_argument(
        "--expected",
        type=Path,
        default=None,
        metavar="CSV",
        help="the answer key (default: the one expectedresults-*.csv in the folder)",
    )
    command.add_argument("--name", default=None, help="what to call the benchmark in results")
    command.add_argument(
        "--split",
        choices=benchmarks.SPLITS,
        default=benchmarks.ALL,
        help="mark every test case, or only one fixed half of them (default: all)",
    )
    command.add_argument(
        "--json", type=Path, default=None, metavar="FILE", help="write the results as data"
    )
    command.add_argument(
        "--markdown", type=Path, default=None, metavar="FILE", help="write the results as a table"
    )
    command.add_argument(
        "--cases",
        type=Path,
        default=None,
        metavar="FILE",
        help="write every test case and how it was judged (CSV)",
    )
    command.add_argument(
        "--compare",
        type=Path,
        default=None,
        metavar="CSV",
        help=(
            "a --cases file from an earlier run; says how many cases changed "
            "and whether that is more than chance"
        ),
    )
    command.add_argument(
        "--check",
        type=Path,
        default=None,
        metavar="JSON",
        help="a --json file from an earlier run; exit 1 unless this run reproduces it",
    )


def run(arguments: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    root: Path = arguments.path
    if not root.is_dir():
        print(f"error: not a folder: {plain(root)}", file=err)
        return EXIT_ERROR
    root = root.resolve()

    try:
        answer_key = arguments.expected or benchmarks.find_answer_key(root)
        loaded = benchmarks.load(answer_key)
        evaluation = evaluate(
            root, loaded, name=arguments.name or root.name or "benchmark", split=arguments.split
        )
        comparison = (
            compare(load_outcomes(arguments.compare), evaluation)
            if arguments.compare is not None
            else None
        )
        recorded = _recorded(arguments.check) if arguments.check is not None else None
    except benchmarks.BenchmarkError as exc:
        print(f"error: {plain(exc)}", file=err)
        return EXIT_ERROR

    data = render.as_data(evaluation, comparison)
    try:
        _write(arguments.json, json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        _write(arguments.markdown, render.as_markdown(evaluation, comparison))
        _write(arguments.cases, render.as_cases(evaluation))
    except OSError as exc:
        print(f"error: could not write the results: {plain(exc)}", file=err)
        return EXIT_ERROR

    _print(out, evaluation, comparison)
    if recorded is None:
        return EXIT_OK
    differences = differences_from(recorded, data)
    if not differences:
        print("REPRODUCED: this run matches the recorded results.", file=out)
        return EXIT_OK
    print("DIFFERENT from the recorded results:", file=out)
    for line in differences:
        print(f"  {plain(line)}", file=out)
    return EXIT_DIFFERENT


def _recorded(path: Path) -> dict[str, Any]:
    try:
        if path.is_symlink() or not path.is_file():
            raise benchmarks.BenchmarkError("The recorded results are not a regular file.")
        if path.stat().st_size > MAX_RECORDED_BYTES:
            raise benchmarks.BenchmarkError("The recorded results file is too large to be one.")
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError, RecursionError) as error:
        raise benchmarks.BenchmarkError("The recorded results could not be read.") from error
    if not isinstance(data, dict) or data.get("schema") != render.SCHEMA:
        raise benchmarks.BenchmarkError(
            "The recorded results are not in a format this version reads."
        )
    return data


def differences_from(recorded: dict[str, Any], current: dict[str, Any]) -> list[str]:
    """What separates a recorded run from this one, most fundamental first.

    Only what was measured is compared. The analyser's own hash is reported
    when it differs but is not by itself a difference in results: a rule can
    be rewritten and judge every test case exactly as before.
    """
    differences: list[str] = []
    then, now = _section(recorded, "benchmark"), current["benchmark"]
    for key, label in (
        ("answer_key_sha256", "the answer key is a different file"),
        ("split", "a different half of the benchmark was marked"),
        ("test_cases", "a different number of test cases was marked"),
    ):
        if then.get(key) != now[key]:
            differences.append(f"{label} (recorded {then.get(key)}, now {now[key]})")

    earlier = {
        item.get("category"): item
        for item in recorded.get("categories", [])
        if isinstance(item, dict)
    }
    for item in current["categories"]:
        before = earlier.pop(item["category"], None)
        if before is None:
            differences.append(f"{item['category']}: not in the recorded results")
            continue
        was = tuple(before.get(key) for key in ("tp", "fn", "fp", "tn"))
        is_ = tuple(item[key] for key in ("tp", "fn", "fp", "tn"))
        if was != is_:
            differences.append(
                f"{item['category']}: recorded TP/FN/FP/TN {'/'.join(map(str, was))}, "
                f"now {'/'.join(map(str, is_))}"
            )
    differences.extend(f"{category}: recorded, and not in this run" for category in earlier)

    if not differences and recorded.get("outcomes_sha256") != current["outcomes_sha256"]:
        differences.append("the totals agree but individual test cases were judged differently")
    if (
        differences
        and _section(recorded, "analyser").get("sha256") != current["analyser"]["sha256"]
    ):
        differences.append("the analyser's source is not the recorded one, which may be why")
    return differences


def _section(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    return value if isinstance(value, dict) else {}


def _write(path: Path | None, content: str) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    # newline="" so the bytes are the same on every platform: a results file
    # written on Windows must not differ from one written on Linux.
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(content)


def _print(out: TextIO, evaluation: Evaluation, comparison: Comparison | None) -> None:
    write = lambda line="": print(line, file=out)  # noqa: E731
    pooled = evaluation.pooled
    version = f" {plain(evaluation.version)}" if evaluation.version else ""
    write(f"SentinelForge {evaluation.tool_version} against {plain(evaluation.name)}{version}")
    write(
        f"  {len(evaluation.outcomes)} test cases ({evaluation.split}): "
        f"{pooled.positives} vulnerable, {pooled.negatives} safe; "
        f"{evaluation.files_scanned} files analysed in {evaluation.duration_ms / 1000:.1f} s"
    )
    write()
    write(
        f"  {'category':<16} {'cases':>5} {'TP':>4} {'FN':>4} {'FP':>4} {'TN':>4} "
        f"{'recall':>8} {'FP rate':>8} {'precision':>9} {'F1':>8} {'score':>6}  reading"
    )
    for item in evaluation.categories:
        write(_line(item.category, item.confusion, render.verdict(item)))
    write(_line("all test cases", pooled, ""))
    write()
    for label, only in (("every category", False), ("categories with a rule", True)):
        count = len(evaluation.with_rule if only else evaluation.categories)
        write(
            f"  average over {label} ({count}): "
            f"recall {render.percent(evaluation.average('recall', only_with_rule=only))}, "
            f"false positive rate "
            f"{render.percent(evaluation.average('false_positive_rate', only_with_rule=only))}, "
            f"score {render.points(evaluation.average('score', only_with_rule=only))}"
        )
    unscored = sum(evaluation.unscored_in_cases.values())
    write(
        f"  not scored: {unscored} finding(s) of another kind in test cases, "
        f"{evaluation.findings_outside_cases} outside test cases"
    )
    if comparison is not None:
        chance = (
            "no test case was judged differently"
            if comparison.p_value is None
            else f"McNemar p = {comparison.p_value:.3g}"
        )
        write(
            f"  against the earlier run: {comparison.fixed} fixed, {comparison.broken} broken "
            f"(net {comparison.net:+d}); {chance}"
        )
    write()


def _line(label: str, confusion: Any, reading: str) -> str:
    return (
        f"  {label:<16} {confusion.total:>5} {confusion.tp:>4} {confusion.fn:>4} "
        f"{confusion.fp:>4} {confusion.tn:>4} {render.percent(confusion.recall):>8} "
        f"{render.percent(confusion.false_positive_rate):>8} "
        f"{render.percent(confusion.precision):>9} {render.percent(confusion.f1):>8} "
        f"{render.points(confusion.score):>6}  {reading}"
    ).rstrip()


__all__ = ["EXIT_DIFFERENT", "EXIT_ERROR", "EXIT_OK", "add_parser", "differences_from", "run"]
