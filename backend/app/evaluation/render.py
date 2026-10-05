"""Results as data, as a table and as a list of every answer.

Three files, for three readers:

* **JSON** — for a later run to be checked against, and for anything that
  wants to draw the numbers. Counts are the truth in it; every ratio is
  derived from them and rounded.
* **Markdown** — for a person. The table, where the numbers came from, and
  what they do not show.
* **CSV** — every test case and how it was judged, so any figure in the table
  can be recounted by someone who does not trust the code that produced it.

Nothing here contains a time or a duration: the same analyser on the same
benchmark writes the same bytes, so a results file that changes in version
control means a result changed.
"""

import csv
import io
from typing import Any

from app.evaluation.benchmark import ALL, split_of
from app.evaluation.compare import Comparison
from app.evaluation.metrics import Confusion, Interval
from app.evaluation.runner import CategoryResult, Evaluation
from app.reports.markdown import text

SCHEMA = 1
DASH = "–"
CASE_COLUMNS = ("name", "category", "cwe", "vulnerable", "reported", "verdict", "rules", "split")


def _round(value: float | None) -> float | None:
    return None if value is None else round(value, 4)


def _pair(interval: Interval | None) -> list[float] | None:
    return None if interval is None else [round(interval.low, 4), round(interval.high, 4)]


def _counts(confusion: Confusion) -> dict[str, Any]:
    return {
        "tp": confusion.tp,
        "fp": confusion.fp,
        "tn": confusion.tn,
        "fn": confusion.fn,
        "recall": _round(confusion.recall),
        "recall_interval": _pair(confusion.recall_interval),
        "false_positive_rate": _round(confusion.false_positive_rate),
        "false_positive_rate_interval": _pair(confusion.false_positive_rate_interval),
        "precision": _round(confusion.precision),
        "precision_interval": _pair(confusion.precision_interval),
        "f1": _round(confusion.f1),
        "accuracy": _round(confusion.accuracy),
        "score": _round(confusion.score),
        "score_interval": _pair(confusion.score_interval),
    }


def _averages(evaluation: Evaluation, *, only_with_rule: bool) -> dict[str, Any]:
    return {
        "recall": _round(evaluation.average("recall", only_with_rule=only_with_rule)),
        "false_positive_rate": _round(
            evaluation.average("false_positive_rate", only_with_rule=only_with_rule)
        ),
        "score": _round(evaluation.average("score", only_with_rule=only_with_rule)),
    }


def as_data(evaluation: Evaluation, comparison: Comparison | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {
        "schema": SCHEMA,
        "benchmark": {
            "name": evaluation.name,
            "version": evaluation.version,
            "commit": evaluation.commit,
            "answer_key_sha256": evaluation.answer_key_sha256,
            "split": evaluation.split,
            "test_cases": len(evaluation.outcomes),
        },
        "analyser": {
            "version": evaluation.tool_version,
            "sha256": evaluation.analyser_sha256,
            "python": evaluation.python_version,
        },
        "files_analysed": evaluation.files_scanned,
        "overall": {
            "all_categories": {
                "categories": len(evaluation.categories),
                "pooled": _counts(evaluation.pooled),
                "category_average": _averages(evaluation, only_with_rule=False),
            },
            "categories_with_a_rule": {
                "categories": len(evaluation.with_rule),
                "pooled": _counts(evaluation.pooled_with_rule),
                "category_average": _averages(evaluation, only_with_rule=True),
            },
        },
        "categories": [
            {
                "category": item.category,
                "cwe": item.cwe,
                "rules": list(item.rules),
                **_counts(item.confusion),
            }
            for item in evaluation.categories
        ],
        "unscored_findings": {
            "in_test_cases_by_rule": evaluation.unscored_in_cases,
            "outside_test_cases": evaluation.findings_outside_cases,
        },
        "outcomes_sha256": evaluation.outcomes_sha256,
    }
    if comparison is not None:
        data["compared_with_earlier_run"] = {
            "test_cases": comparison.cases,
            "fixed": comparison.fixed,
            "broken": comparison.broken,
            "mcnemar_p_value": (
                None if comparison.p_value is None else float(f"{comparison.p_value:.3g}")
            ),
        }
    return data


def as_cases(evaluation: Evaluation) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CASE_COLUMNS)
    for item in sorted(evaluation.outcomes, key=lambda outcome: outcome.case.name):
        writer.writerow(
            [
                item.case.name,
                item.case.category,
                item.case.cwe,
                "yes" if item.case.vulnerable else "no",
                "yes" if item.reported else "no",
                item.verdict,
                " ".join(item.rules),
                split_of(item.case.name),
            ]
        )
    return buffer.getvalue()


# --- for people ------------------------------------------------------------


def percent(value: float | None) -> str:
    return DASH if value is None else f"{value * 100:.1f} %"


def points(value: float | None) -> str:
    """A score: a difference of two percentages, so it carries its sign."""
    if value is None:
        return DASH
    rounded = round(value * 100, 1)
    return f"{rounded + 0.0:+.1f}" if rounded else "0.0"


def interval(value: Interval | None, *, signed: bool = False) -> str:
    if value is None:
        return DASH
    if signed:
        return f"{points(value.low)} to {points(value.high)}"
    return f"{value.low * 100:.1f}–{value.high * 100:.1f}"


def verdict(item: CategoryResult) -> str:
    """One word on whether a category's score can be told apart from guessing."""
    if not item.has_rule:
        return "no rule"
    span = item.confusion.score_interval
    if span is None:
        return DASH
    if span.low > 0:
        return "better than guessing"
    if span.high < 0:
        return "worse than guessing"
    return "not distinguishable from guessing"


def as_markdown(evaluation: Evaluation, comparison: Comparison | None = None) -> str:
    pooled = evaluation.pooled
    lines = [
        f"# Detection results: {text(evaluation.name)}",
        "",
        "| | |",
        "| --- | --- |",
        f"| Benchmark | {text(evaluation.name)}"
        + (f", version {text(evaluation.version)}" if evaluation.version else "")
        + " |",
        f"| Benchmark commit | {_code(evaluation.commit)} |",
        f"| Answer key (SHA-256) | {_code(evaluation.answer_key_sha256)} |",
        f"| Test cases marked | {len(evaluation.outcomes)} ({_split(evaluation.split)}) |",
        f"| Vulnerable / safe | {pooled.positives} / {pooled.negatives} |",
        f"| Analyser | SentinelForge {text(evaluation.tool_version)} |",
        f"| Analyser source (SHA-256) | {_code(evaluation.analyser_sha256)} |",
        f"| Parsed with | Python {text(evaluation.python_version)} |",
        f"| Files analysed | {evaluation.files_scanned} |",
        f"| Outcomes (SHA-256) | {_code(evaluation.outcomes_sha256)} |",
        "",
        "## By category",
        "",
        "Recall is the share of vulnerable test cases that were reported. The false "
        "positive rate is the share of safe ones that were reported anyway. "
        "**Score** is the first minus the second, in percentage points: +100 is "
        "perfect, 0 is what reporting everything, reporting nothing or tossing a "
        "coin all score. The interval is the 95 % interval of the score.",
        "",
        "| Category | CWE | Cases | TP | FN | FP | TN | Recall | False positive rate "
        "| Precision | F1 | Score | 95 % interval | Reading |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: "
        "| --- | --- |",
    ]
    for item in evaluation.categories:
        lines.append(_row(item.category, str(item.cwe), item.confusion, verdict(item)))
    lines += [
        _row("**All test cases**", "", pooled, ""),
        "",
        "## Overall",
        "",
        "| | Categories | Recall | False positive rate | Score |",
        "| --- | ---: | ---: | ---: | ---: |",
        _overall("Average over every category", evaluation, only_with_rule=False),
        _overall(
            "Average over categories the analyser has a rule for", evaluation, only_with_rule=True
        ),
        "",
        "The first row is the benchmark's own headline figure: each category counts "
        "once, including those the analyser has no rule for, which score zero. The "
        "second row leaves those out. It describes how good the existing rules are, "
        "not how much of the benchmark they cover, and is not a substitute for the first.",
        "",
        "## Rules",
        "",
        "| Category | Rules that answer it |",
        "| --- | --- |",
    ]
    for item in evaluation.categories:
        rules = ", ".join(item.rules) if item.rules else "none: every vulnerable case is missed"
        lines.append(f"| {item.category} | {rules} |")

    lines += ["", "## Findings that were not scored", ""]
    if evaluation.unscored_in_cases:
        lines += [
            "A finding in a test case's file that is of a different kind from the "
            "test's question. The answer key says nothing about whether these are "
            "real, so they are counted here and are in no figure above.",
            "",
            "| Rule | Findings |",
            "| --- | ---: |",
        ]
        lines += [f"| {rule} | {count} |" for rule, count in evaluation.unscored_in_cases.items()]
    else:
        lines.append("No finding in a test case's file was of a different kind from its question.")
    lines += [
        "",
        f"Findings in files that are not test cases: {evaluation.findings_outside_cases}.",
    ]

    if comparison is not None:
        lines += [
            "",
            "## Compared with the earlier run",
            "",
            f"Over the same {comparison.cases} test cases, this run judged "
            f"{comparison.fixed} correctly that the earlier run got wrong, and "
            f"{comparison.broken} wrongly that the earlier run got right "
            f"(net {comparison.net:+d}). "
            + (
                "No test case was judged differently."
                if comparison.p_value is None
                else f"Exact McNemar test, two-sided: p = {comparison.p_value:.3g}."
            ),
        ]
    return "\n".join(lines) + "\n"


def _split(split: str) -> str:
    return "the whole benchmark" if split == ALL else f"the {split} half"


def _code(value: str | None) -> str:
    return f"`{value}`" if value else "not recorded"


def _row(label: str, cwe: str, confusion: Confusion, reading: str) -> str:
    return (
        f"| {label} | {cwe} | {confusion.total} | {confusion.tp} | {confusion.fn} "
        f"| {confusion.fp} | {confusion.tn} | {percent(confusion.recall)} "
        f"| {percent(confusion.false_positive_rate)} | {percent(confusion.precision)} "
        f"| {percent(confusion.f1)} | {points(confusion.score)} "
        f"| {interval(confusion.score_interval, signed=True)} | {reading} |"
    )


def _overall(label: str, evaluation: Evaluation, *, only_with_rule: bool) -> str:
    count = len(evaluation.with_rule if only_with_rule else evaluation.categories)
    return (
        f"| {label} | {count} "
        f"| {percent(evaluation.average('recall', only_with_rule=only_with_rule))} "
        f"| {percent(evaluation.average('false_positive_rate', only_with_rule=only_with_rule))} "
        f"| {points(evaluation.average('score', only_with_rule=only_with_rule))} |"
    )


__all__ = [
    "CASE_COLUMNS",
    "SCHEMA",
    "as_cases",
    "as_data",
    "as_markdown",
    "interval",
    "percent",
    "points",
    "verdict",
]
