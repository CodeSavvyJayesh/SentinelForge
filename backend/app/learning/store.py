"""The trained model as a file, and the report that goes with it.

The model file is JSON: the weights, and everything needed to turn a new
proposal into the numbers those weights apply to. It can be read with a text
editor, which is the point — a few dozen weights are small enough to inspect,
and a reader who wants to know why the model said 0.8 can add them up.

The report is written from the cross-validation, not from the final model. The
final model is trained on every example, so it has no examples left to be
tested on; what is known about how well it predicts is what its predecessors,
each trained on four fifths of the data, did on the fifth they had not seen.
"""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from app.learning import crossval
from app.learning.crossval import BASE_RATE, BY_RULE, MODEL, PREDICTORS, Report
from app.learning.dataset import Collected
from app.learning.features import PatchExample, Vectoriser
from app.learning.logistic import Model

SCHEMA = 1
KIND = "sentinelforge-patch-outcome"
# How many of the largest weights the report lists.
LISTED_WEIGHTS = 12
# A gap in AUC smaller than this is not called a difference.
MEANINGFUL_GAP = 0.02
SIGNIFICANT = 0.05

BETTER = "better"
UNCLEAR = "unclear"
NO_BETTER = "no better"


class ModelFileError(Exception):
    """The model file is not one this version can use. The message is safe to show."""


def fingerprint(examples: list[PatchExample]) -> str:
    """A hash of which fixes were used and how each came out."""
    lines = sorted(f"{item.patch_id}:{int(item.passed)}" for item in examples)
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def verdict(report: Report) -> str:
    """Whether the model does better than knowing only the rule.

    ``BETTER`` needs three things at once: a higher average, no overlap between
    the two spreads across repeats, and a paired test on the individual
    predictions that would be surprising by chance. Anything less is reported
    as less.
    """
    model = report.summary(MODEL, "auc")
    baseline = report.summary(BY_RULE, "auc")
    if model is None or baseline is None:
        return UNCLEAR
    if model.mean <= baseline.mean + MEANINGFUL_GAP:
        return NO_BETTER
    clear = (
        model.low > baseline.high
        and report.p_value is not None
        and report.p_value < SIGNIFICANT
        and report.model_only > report.baseline_only
    )
    return BETTER if clear else UNCLEAR


def as_data(
    vectoriser: Vectoriser,
    model: Model,
    report: Report,
    examples: list[PatchExample],
    *,
    trained_at: datetime,
    tool_version: str,
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "kind": KIND,
        "trained_at": trained_at.isoformat(timespec="seconds"),
        "tool_version": tool_version,
        "data": {
            "examples": report.examples,
            "passed": report.passed,
            "rejected": report.examples - report.passed,
            "findings": report.findings,
            "fingerprint": fingerprint(examples),
        },
        "vectoriser": {
            "names": list(vectoriser.names),
            "scales": [list(item) for item in vectoriser.scales],
            "vocabulary": [[name, list(values)] for name, values in vectoriser.vocabulary],
        },
        "model": {
            "weights": list(model.weights),
            "bias": model.bias,
            "l2": report.l2,
            "iterations": model.iterations,
        },
        "cross_validation": {
            "folds": report.folds,
            "repeats": report.repeats,
            "seed": report.seed,
            "verdict": verdict(report),
            "mcnemar_p_value": report.p_value,
            "predictors": {
                name: {
                    figure: _summary(report, name, figure)
                    for figure in ("accuracy", "precision", "recall", "f1", "auc", "brier")
                }
                for name in PREDICTORS
            },
        },
    }


def _summary(report: Report, predictor: str, figure: str) -> dict[str, float] | None:
    summary = report.summary(predictor, figure)
    if summary is None:
        return None
    return {
        "mean": round(summary.mean, 4),
        "low": round(summary.low, 4),
        "high": round(summary.high, 4),
    }


def save(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def load(path: Path) -> tuple[Vectoriser, Model]:
    """Read a model file back. Refuses anything that is not exactly the shape it wrote."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ModelFileError("The model file could not be read.") from error
    try:
        if data["schema"] != SCHEMA or data["kind"] != KIND:
            raise ModelFileError("The model file is not one this version can use.")
        described = data["vectoriser"]
        vectoriser = Vectoriser(
            names=tuple(str(name) for name in described["names"]),
            scales=tuple(
                (str(name), float(mean), float(spread))
                for name, mean, spread in described["scales"]
            ),
            vocabulary=tuple(
                (str(name), tuple(str(value) for value in values))
                for name, values in described["vocabulary"]
            ),
        )
        model = Model(
            weights=tuple(float(weight) for weight in data["model"]["weights"]),
            bias=float(data["model"]["bias"]),
            iterations=int(data["model"]["iterations"]),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ModelFileError("The model file is damaged or incomplete.") from error
    if len(model.weights) != len(vectoriser.names):
        raise ModelFileError("The model file's weights do not match its features.")
    return vectoriser, model


# --- the report ---------------------------------------------------------------


def _percent(summary: crossval.Summary | None) -> str:
    if summary is None:
        return "–"
    return f"{summary.mean * 100:.1f} % ({summary.low * 100:.1f}–{summary.high * 100:.1f})"


def _plain(summary: crossval.Summary | None) -> str:
    if summary is None:
        return "–"
    return f"{summary.mean:.3f} ({summary.low:.3f}–{summary.high:.3f})"


CONCLUSIONS = {
    BETTER: (
        "**The model predicts better than knowing the rule alone.** Its average is higher, "
        "the two ranges across repeats do not overlap, and on the individual predictions "
        "the difference would be unlikely by chance."
    ),
    UNCLEAR: (
        "**The model is ahead of the rule-only baseline on average, but not clearly.** The "
        "difference is within what a different shuffle of the same data produces, or the "
        "paired test on individual predictions does not support it. More judged fixes are "
        "needed before this can be called a result."
    ),
    NO_BETTER: (
        "**The model does not predict better than knowing the rule alone.** What it was told "
        "about each proposal — its size, how much tidying the model's output needed, how "
        "long it took — adds nothing measurable to knowing which rule the fix was for. That "
        "is a finding about these features and this amount of data, and it is reported as "
        "one rather than hidden."
    ),
}


def as_markdown(
    collected: Collected,
    report: Report,
    vectoriser: Vectoriser,
    model: Model,
    *,
    trained_at: datetime,
    tool_version: str,
) -> str:
    rejected = report.examples - report.passed
    commoner = max(report.passed, rejected) / report.examples
    lines = [
        "# Patch-outcome classifier: results",
        "",
        "Predicts, from what is known about a proposed fix before it is checked, whether "
        "re-scanning the patched code will support it. Trained on this installation's own "
        "data.",
        "",
        "| | |",
        "| --- | --- |",
        f"| Trained | {trained_at.strftime('%Y-%m-%d %H:%M')} UTC |",
        f"| SentinelForge | {tool_version} |",
        f"| Judged fixes used | {report.examples} |",
        f"| Passed / rejected | {report.passed} / {rejected} |",
        f"| Findings they were for | {report.findings} |",
        f"| Data fingerprint | `{fingerprint(collected.examples)}` |",
        "",
        "## The data",
        "",
        f"{collected.requested} fixes have been requested. Only those with a verdict are examples:",
        "",
        "| What became of the fix | Count | Used |",
        "| --- | ---: | --- |",
        f"| Checked: passed | {collected.passed} | yes |",
        f"| Checked: rejected | {collected.rejected} | yes |",
        f"| Checked, but could not be judged | {collected.not_judged} | no: no verdict |",
        f"| Proposed, not checked yet | {collected.unchecked + collected.checking} | no |",
        f"| Refused before it became a proposal | {collected.refused} | no |",
        f"| Still being generated | {collected.generating} | no |",
        "",
        "| Rule | Passed | Rejected | Pass rate |",
        "| --- | ---: | ---: | ---: |",
    ]
    for rule, passed, failed in collected.by_rule():
        lines.append(f"| {rule} | {passed} | {failed} | {passed / (passed + failed) * 100:.0f} % |")

    lines += [
        "",
        "## How well it predicts",
        "",
        f"{report.folds}-fold cross-validation, repeated {report.repeats} times with "
        f"different shuffles (seed {report.seed}). All fixes for one finding are kept in the "
        "same fold. Each cell is the mean over the repeats, with the lowest and highest "
        "repeat in brackets.",
        "",
        "| Predictor | Accuracy | Precision | Recall | F1 | AUC | Brier |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    labels = {
        MODEL: "Logistic regression",
        BY_RULE: "Baseline: pass rate of the rule",
        BASE_RATE: "Baseline: always the commoner outcome",
    }
    for name in PREDICTORS:
        lines.append(
            f"| {labels[name]} "
            f"| {_percent(report.summary(name, 'accuracy'))} "
            f"| {_percent(report.summary(name, 'precision'))} "
            f"| {_percent(report.summary(name, 'recall'))} "
            f"| {_percent(report.summary(name, 'f1'))} "
            f"| {_plain(report.summary(name, 'auc'))} "
            f"| {_plain(report.summary(name, 'brier'))} |"
        )
    chance = (
        "no prediction differed between the two"
        if report.p_value is None
        else f"exact McNemar test, two-sided: p = {report.p_value:.3g}"
    )
    lines += [
        "",
        "Precision and recall are for the outcome *passed*. AUC is the chance that a fix "
        "that passed is scored above one that was rejected: 0.5 is a coin. Brier is the mean "
        "squared error of the probabilities: lower is better, and always answering "
        f"{commoner * 100:.0f} % would score {commoner * (1 - commoner):.3f}.",
        "",
        f"On the first repeat, the model was right on {report.model_only} fixes the rule-only "
        f"baseline got wrong, and wrong on {report.baseline_only} it got right ({chance}).",
        "",
        CONCLUSIONS[verdict(report)],
        "",
        "## What the model learnt",
        "",
        "The final model is trained on every example. These are its largest weights; a "
        "positive weight moves the prediction towards *passed*. Numbers are scaled, so "
        "weights are comparable with each other.",
        "",
        "| Feature | Weight | Pushes towards |",
        "| --- | ---: | --- |",
    ]
    ranked = sorted(
        zip(vectoriser.names, model.weights, strict=True), key=lambda pair: -abs(pair[1])
    )
    for name, weight in ranked[:LISTED_WEIGHTS]:
        if abs(weight) < 1e-9:
            break
        lines.append(f"| {name} | {weight:+.3f} | {'passed' if weight > 0 else 'rejected'} |")
    lines += [
        "",
        "## What this does not show",
        "",
        '- **"Passed" means the re-scan no longer reports the finding and reports nothing '
        "new.** It does not mean the fix is correct, or that the program still works. The "
        "model predicts the scanner's verdict, not a person's.",
        "- **The examples come from one installation**: the repositories scanned here, the "
        "language model configured here, the rules of this version. A model trained on them "
        "says nothing about other code or another model.",
        "- **A weight is not a cause.** A feature that goes with passing may simply go with "
        "the rules whose fixes are easy.",
        "- **The figures move with the data.** The range in brackets is the spread across "
        "shuffles of the same examples; with more examples of other kinds they would move "
        "further.",
    ]
    return "\n".join(lines) + "\n"


__all__ = [
    "BETTER",
    "KIND",
    "NO_BETTER",
    "SCHEMA",
    "UNCLEAR",
    "ModelFileError",
    "as_data",
    "as_markdown",
    "fingerprint",
    "load",
    "save",
    "verdict",
]
