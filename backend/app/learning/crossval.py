"""How well the model predicts fixes it was not trained on.

A model scored on the examples it learnt from is scored on its memory. So the
examples are split into folds; the model is trained on all but one fold and
asked about the one it has not seen; and every example ends up predicted
exactly once by a model that never saw it.

Four decisions that keep the number honest:

* **Fixes for one finding stay together.** A second attempt at the same finding
  is nearly the same code as the first. With one in training and the other in
  the test fold, the model would be recognising, not predicting.
* **Everything fitted is fitted inside the fold** — the scaling of each number
  and the list of rules that get their own column, not only the weights.
* **The split is repeated** with different shuffles, and the spread across
  repeats is reported beside the mean. One split of a few hundred rows can be
  lucky.
* **Two baselines are scored the same way.** "Always say the commoner outcome"
  and "say what usually happens for this rule" need no model at all. If the
  model does not beat the second one, the features it was given carry no
  information beyond the rule, and the report says so.
"""

import random
from collections import Counter, defaultdict
from dataclasses import dataclass

from app.evaluation.metrics import Confusion, mcnemar, mean
from app.learning.features import PatchExample, Vectoriser
from app.learning.logistic import DEFAULT_L2, train

# Below these the folds are too small for any figure to mean much.
MIN_EXAMPLES = 60
MIN_PER_CLASS = 15
DEFAULT_FOLDS = 5
DEFAULT_REPEATS = 10
DEFAULT_SEED = 16
THRESHOLD = 0.5

MODEL = "model"
BY_RULE = "pass rate of the rule"
BASE_RATE = "commoner outcome"
PREDICTORS = (MODEL, BY_RULE, BASE_RATE)


class NotEnoughDataError(Exception):
    """There are too few judged fixes to train on. The message says how many."""


@dataclass(frozen=True)
class Scores:
    confusion: Confusion
    # Probability that a passed fix is ranked above a rejected one. 0.5 is
    # what a coin gets; None when one of the two outcomes is absent. In a
    # cross-validation this is the average over the folds.
    auc: float | None
    # Mean squared error of the probabilities. Lower is better; always saying
    # the base rate scores p(1-p).
    brier: float


@dataclass(frozen=True)
class Summary:
    """One figure across the repeats: its mean and how far it moved."""

    mean: float
    low: float
    high: float


@dataclass(frozen=True)
class Report:
    examples: int
    passed: int
    findings: int
    folds: int
    repeats: int
    seed: int
    l2: float
    # predictor -> one Scores per repeat.
    scores: dict[str, tuple[Scores, ...]]
    # Model against the by-rule baseline on the first repeat: examples only the
    # model got right, only the baseline got right, and the McNemar p-value.
    model_only: int
    baseline_only: int
    p_value: float | None

    def summary(self, predictor: str, figure: str) -> Summary | None:
        values = [_figure(scores, figure) for scores in self.scores[predictor]]
        present = [value for value in values if value is not None]
        if not present:
            return None
        return Summary(sum(present) / len(present), min(present), max(present))


def _figure(scores: Scores, figure: str) -> float | None:
    if figure in {"auc", "brier"}:
        return getattr(scores, figure)  # type: ignore[no-any-return]
    return getattr(scores.confusion, figure)  # type: ignore[no-any-return]


def require_enough(examples: list[PatchExample]) -> None:
    passed = sum(1 for item in examples if item.passed)
    rejected = len(examples) - passed
    problems = []
    if len(examples) < MIN_EXAMPLES:
        problems.append(f"{MIN_EXAMPLES - len(examples)} more judged fixes")
    for label, count in (("passed", passed), ("rejected", rejected)):
        if count < MIN_PER_CLASS:
            problems.append(f"{MIN_PER_CLASS - count} more that {label}")
    if problems:
        raise NotEnoughDataError(
            f"There are {len(examples)} judged fixes ({passed} passed, {rejected} rejected). "
            f"Training needs at least {MIN_EXAMPLES}, with at least {MIN_PER_CLASS} of each "
            f"outcome: {', and '.join(problems)}."
        )


def grouped_folds(examples: list[PatchExample], folds: int, seed: int) -> list[list[int]]:
    """Positions of the examples in each fold, findings kept whole.

    Findings are dealt out like cards, the ones whose fixes mostly passed first
    and the rest after, so each fold gets about the same mix of outcomes.
    """
    if folds < 2:
        raise ValueError("there must be at least two folds")
    members: dict[int, list[int]] = defaultdict(list)
    for position, example in enumerate(examples):
        members[example.finding_id].append(position)
    if len(members) < folds:
        raise NotEnoughDataError(
            f"The judged fixes are for {len(members)} findings, and {folds} folds need at "
            "least that many: a finding's fixes cannot be split between folds."
        )

    def mostly_passed(finding: int) -> bool:
        passed = sum(1 for position in members[finding] if examples[position].passed)
        return passed * 2 >= len(members[finding])

    order = sorted(members)
    random.Random(seed).shuffle(order)  # noqa: S311 - a shuffle, not a secret
    order.sort(key=lambda finding: not mostly_passed(finding))  # stable: keeps the shuffle
    dealt: list[list[int]] = [[] for _ in range(folds)]
    for turn, finding in enumerate(order):
        dealt[turn % folds].extend(members[finding])
    return [sorted(fold) for fold in dealt]


def roc_auc(probabilities: list[float], labels: list[bool]) -> float | None:
    """Area under the ROC curve, by ranks; tied scores share their rank."""
    positives = sum(1 for label in labels if label)
    negatives = len(labels) - positives
    if not positives or not negatives:
        return None
    order = sorted(range(len(labels)), key=lambda position: probabilities[position])
    ranks = [0.0] * len(labels)
    start = 0
    while start < len(order):
        end = start
        while end + 1 < len(order) and probabilities[order[end + 1]] == probabilities[order[start]]:
            end += 1
        shared = (start + end) / 2 + 1  # ranks are counted from one
        for position in order[start : end + 1]:
            ranks[position] = shared
        start = end + 1
    rank_sum = sum(rank for rank, label in zip(ranks, labels, strict=True) if label)
    return (rank_sum - positives * (positives + 1) / 2) / (positives * negatives)


def score(probabilities: list[float], labels: list[bool]) -> Scores:
    tally: Counter[str] = Counter()
    for probability, label in zip(probabilities, labels, strict=True):
        predicted = probability >= THRESHOLD
        tally[("t" if predicted == label else "f") + ("p" if predicted else "n")] += 1
    brier = sum(
        (probability - (1.0 if label else 0.0)) ** 2
        for probability, label in zip(probabilities, labels, strict=True)
    ) / len(labels)
    return Scores(
        Confusion(tp=tally["tp"], fp=tally["fp"], tn=tally["tn"], fn=tally["fn"]),
        roc_auc(probabilities, labels),
        brier,
    )


def predict_fold(
    training: list[PatchExample], testing: list[PatchExample], l2: float
) -> dict[str, list[float]]:
    """Probabilities that each test fix passes, from the model and both baselines."""
    vectoriser = Vectoriser.fit(training)
    model = train(
        [vectoriser.transform(item) for item in training],
        [item.passed for item in training],
        l2=l2,
    )
    base_rate = sum(1 for item in training if item.passed) / len(training)
    seen: Counter[str] = Counter(item.rule_id for item in training)
    passed: Counter[str] = Counter(item.rule_id for item in training if item.passed)

    def by_rule(item: PatchExample) -> float:
        if not seen[item.rule_id]:
            return base_rate
        # One imaginary pass and one imaginary rejection, so a rule seen once
        # is not predicted with certainty.
        return (passed[item.rule_id] + 1) / (seen[item.rule_id] + 2)

    return {
        MODEL: [model.probability(vectoriser.transform(item)) for item in testing],
        BY_RULE: [by_rule(item) for item in testing],
        BASE_RATE: [base_rate for _ in testing],
    }


def cross_validate(
    examples: list[PatchExample],
    *,
    folds: int = DEFAULT_FOLDS,
    repeats: int = DEFAULT_REPEATS,
    seed: int = DEFAULT_SEED,
    l2: float = DEFAULT_L2,
) -> Report:
    require_enough(examples)
    if repeats < 1:
        raise ValueError("there must be at least one repeat")
    labels = [item.passed for item in examples]
    scores: dict[str, list[Scores]] = {name: [] for name in PREDICTORS}
    first: dict[str, list[float]] = {}

    for repeat in range(repeats):
        predicted: dict[str, list[float]] = {name: [0.0] * len(examples) for name in PREDICTORS}
        areas: dict[str, list[float | None]] = {name: [] for name in PREDICTORS}
        for held_out in grouped_folds(examples, folds, seed + repeat):
            inside = set(held_out)
            training = [item for position, item in enumerate(examples) if position not in inside]
            testing = [examples[position] for position in held_out]
            for name, probabilities in predict_fold(training, testing, l2).items():
                for position, probability in zip(held_out, probabilities, strict=True):
                    predicted[name][position] = probability
                areas[name].append(roc_auc(probabilities, [item.passed for item in testing]))
        for name in PREDICTORS:
            pooled = score(predicted[name], labels)
            # The area is taken fold by fold and averaged. Each fold's model has
            # its own idea of the base rate, so ranking a fix from one fold
            # against a fix from another compares two models, not two fixes —
            # pooled, a baseline that says one number per fold scores 0.49.
            scores[name].append(Scores(pooled.confusion, mean(areas[name]), pooled.brier))
        if repeat == 0:
            first = predicted

    model_right = [(p >= THRESHOLD) == label for p, label in zip(first[MODEL], labels, strict=True)]
    rule_right = [
        (p >= THRESHOLD) == label for p, label in zip(first[BY_RULE], labels, strict=True)
    ]
    model_only = sum(1 for a, b in zip(model_right, rule_right, strict=True) if a and not b)
    baseline_only = sum(1 for a, b in zip(model_right, rule_right, strict=True) if b and not a)
    return Report(
        examples=len(examples),
        passed=sum(1 for label in labels if label),
        findings=len({item.finding_id for item in examples}),
        folds=folds,
        repeats=repeats,
        seed=seed,
        l2=l2,
        scores={name: tuple(values) for name, values in scores.items()},
        model_only=model_only,
        baseline_only=baseline_only,
        p_value=mcnemar(baseline_only, model_only),
    )


__all__ = [
    "BASE_RATE",
    "BY_RULE",
    "DEFAULT_FOLDS",
    "DEFAULT_REPEATS",
    "DEFAULT_SEED",
    "MIN_EXAMPLES",
    "MIN_PER_CLASS",
    "MODEL",
    "PREDICTORS",
    "NotEnoughDataError",
    "Report",
    "Scores",
    "Summary",
    "cross_validate",
    "grouped_folds",
    "predict_fold",
    "require_enough",
    "roc_auc",
    "score",
]
