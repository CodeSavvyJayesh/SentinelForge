"""The patch-outcome classifier: its arithmetic, its honesty and its files.

Every example in this file is made up, and is only ever used to check that the
machinery does what it says — that a fold never sees its own test rows, that an
area under a curve is computed correctly, that a model with nothing to learn
from is reported as having learnt nothing. No figure produced here is a result.
Results come from ``scripts/train_patch_classifier.py`` run against a database
of fixes that were really proposed and really checked.
"""

import json
import math
import random
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.evaluation.metrics import Confusion
from app.learning import crossval, store
from app.learning.crossval import (
    BASE_RATE,
    BY_RULE,
    MODEL,
    NotEnoughDataError,
    Report,
    Scores,
    cross_validate,
    grouped_folds,
    require_enough,
    roc_auc,
    score,
)
from app.learning.dataset import Collected
from app.learning.features import OTHER, PatchExample, Vectoriser
from app.learning.logistic import Model, sigmoid, train

TRAINED_AT = datetime(2026, 10, 4, 9, 30, tzinfo=UTC)


def example(number: int, passed: bool, **overrides: object) -> PatchExample:
    fields: dict[str, object] = {
        "patch_id": number,
        "finding_id": number,
        "passed": passed,
        "rule_id": "PY003",
        "severity": "HIGH",
        "confidence": "HIGH",
        "suffix": ".py",
        "lines_added": 2,
        "lines_removed": 1,
        "region_lines": 9,
        "diff_characters": 300,
        "rationale_characters": 120,
        "fences_stripped": False,
        "gutters_stripped": 0,
        "reindented": False,
        "attempts": 1,
        "had_explanation": True,
        "passages": 3,
        "prompt_tokens": 900,
        "completion_tokens": 150,
        "duration_ms": 20000,
        "temperature": 0.0,
    }
    fields.update(overrides)
    return PatchExample(**fields)  # type: ignore[arg-type]


def made_up(count: int, *, informative: bool, seed: int = 1) -> list[PatchExample]:
    """Examples whose outcome does, or does not, depend on a feature."""
    rng = random.Random(seed)  # noqa: S311 - made-up examples, not a secret
    examples = []
    for number in range(count):
        added = rng.randint(1, 40)
        chance = (0.9 if added < 12 else 0.15) if informative else 0.5
        examples.append(
            example(
                number,
                rng.random() < chance,
                lines_added=added,
                rule_id=rng.choice(["PY003", "PY010", "JV003"]),
                diff_characters=rng.randint(100, 3000),
            )
        )
    return examples


# --- features -------------------------------------------------------------------


def test_a_row_has_one_number_for_every_name() -> None:
    examples = [example(number, number % 2 == 0) for number in range(10)]
    vectoriser = Vectoriser.fit(examples)

    row = vectoriser.transform(examples[0])

    assert len(row) == len(vectoriser.names)
    assert len(set(vectoriser.names)) == len(vectoriser.names)
    assert all(math.isfinite(value) for value in row)


def test_the_label_is_not_a_feature() -> None:
    passed = Vectoriser.fit([example(1, True)]).transform(example(1, True))
    rejected = Vectoriser.fit([example(1, True)]).transform(example(1, False))

    assert passed == rejected


def test_numbers_are_scaled_by_the_training_examples() -> None:
    training = [example(number, True, attempts=attempts) for number, attempts in enumerate([1, 5])]
    vectoriser = Vectoriser.fit(training)
    column = vectoriser.names.index("generation attempts")

    # Mean 3, spread 2.
    assert vectoriser.transform(example(9, True, attempts=1))[column] == pytest.approx(-1.0)
    assert vectoriser.transform(example(9, True, attempts=5))[column] == pytest.approx(1.0)
    assert vectoriser.transform(example(9, True, attempts=9))[column] == pytest.approx(3.0)


def test_counts_are_compared_on_a_logarithmic_scale() -> None:
    training = [example(1, True, lines_added=0), example(2, True, lines_added=99)]
    vectoriser = Vectoriser.fit(training)
    column = vectoriser.names.index("lines added")

    small = vectoriser.transform(example(3, True, lines_added=9))[column]

    # log(1+9) is halfway between log(1+0) and log(1+99): the middle, scaled, is zero.
    assert small == pytest.approx(0.0, abs=1e-9)


def test_a_number_that_never_varies_becomes_zero_not_a_division_by_zero() -> None:
    vectoriser = Vectoriser.fit([example(number, True, attempts=2) for number in range(4)])
    column = vectoriser.names.index("generation attempts")

    assert vectoriser.transform(example(9, True, attempts=2))[column] == 0.0


def test_a_number_that_was_not_recorded_is_flagged_rather_than_invented() -> None:
    vectoriser = Vectoriser.fit([example(1, True), example(2, False, prompt_tokens=None)])
    value = vectoriser.names.index("prompt tokens")
    flag = vectoriser.names.index("prompt tokens: not recorded")

    missing = vectoriser.transform(example(3, True, prompt_tokens=None))
    present = vectoriser.transform(example(3, True, prompt_tokens=900))

    assert (missing[value], missing[flag]) == (0.0, 1.0)
    assert present[flag] == 0.0


def test_a_rule_seen_too_rarely_shares_a_column_with_the_others() -> None:
    training = [example(n, True, rule_id="PY003") for n in range(3)]
    training += [example(10, True, rule_id="JV003"), example(11, True, rule_id="JV003")]
    vectoriser = Vectoriser.fit(training)

    assert "rule = PY003" in vectoriser.names
    assert "rule = JV003" not in vectoriser.names
    rare = vectoriser.transform(example(20, True, rule_id="JV003"))
    assert rare[vectoriser.names.index(f"rule = {OTHER}")] == 1.0
    assert rare[vectoriser.names.index("rule = PY003")] == 0.0


def test_a_rule_never_seen_in_training_is_other() -> None:
    vectoriser = Vectoriser.fit([example(n, True) for n in range(3)])

    unseen = vectoriser.transform(example(9, True, rule_id="SQL001"))

    assert unseen[vectoriser.names.index(f"rule = {OTHER}")] == 1.0


def test_flags_are_one_or_zero() -> None:
    vectoriser = Vectoriser.fit([example(1, True)])
    column = vectoriser.names.index("re-indented")

    assert vectoriser.transform(example(2, True, reindented=True))[column] == 1.0
    assert vectoriser.transform(example(2, True, reindented=False))[column] == 0.0


# --- logistic regression ---------------------------------------------------------


def test_the_sigmoid_does_not_overflow_at_either_end() -> None:
    assert sigmoid(0) == 0.5
    assert sigmoid(1000) == 1.0
    assert sigmoid(-1000) == 0.0
    assert sigmoid(2) == pytest.approx(1 / (1 + math.exp(-2)))
    assert sigmoid(-2) == pytest.approx(1 - sigmoid(2))


def test_it_learns_a_rule_that_is_there() -> None:
    rows = [[-2.0], [-1.5], [-1.0], [1.0], [1.5], [2.0]]
    labels = [False, False, False, True, True, True]

    model = train(rows, labels, l2=0.01)

    assert model.weights[0] > 0
    assert model.probability([2.0]) > 0.9
    assert model.probability([-2.0]) < 0.1


def test_with_nothing_to_learn_from_it_predicts_the_base_rate() -> None:
    rows = [[0.0]] * 10
    labels = [True] * 7 + [False] * 3

    model = train(rows, labels)

    assert model.weights == (0.0,)
    assert model.probability([0.0]) == pytest.approx(0.7, abs=0.01)


def test_the_same_examples_give_the_same_model() -> None:
    rows = [[float(n % 5), float(n % 3)] for n in range(30)]
    labels = [n % 5 > 2 for n in range(30)]

    assert train(rows, labels) == train(rows, labels)


def test_the_fit_is_the_lowest_point_of_the_penalised_loss() -> None:
    """At the minimum the slope is zero: sum of (p - y) x, plus the penalty times the weight."""
    rows = [[float(n % 7) - 3, float(n % 3) - 1] for n in range(40)]
    labels = [(n % 7) + (n % 3) > 4 for n in range(40)]
    l2 = 3.0

    model = train(rows, labels, l2=l2)

    errors = [
        model.probability(row) - (1.0 if label else 0.0)
        for row, label in zip(rows, labels, strict=True)
    ]
    for column in range(2):
        slope = sum(e * row[column] for e, row in zip(errors, rows, strict=True))
        slope += l2 * model.weights[column]
        assert slope == pytest.approx(0.0, abs=1e-6)
    assert sum(errors) == pytest.approx(0.0, abs=1e-6)  # the bias is not penalised


def test_a_step_that_overshoots_is_cut_back_until_it_helps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every step ten times too long: the fit still arrives where it should."""
    from app.learning import logistic

    honest = logistic._solve
    monkeypatch.setattr(logistic, "_solve", lambda m, v: [10 * s for s in honest(m, v)])
    rows = [[0.0]] * 4 + [[1.0]] * 4
    labels = [True, False, False, False, True, True, True, False]

    model = train(rows, labels, l2=1e-9)

    assert model.bias == pytest.approx(math.log(1 / 3), abs=1e-3)
    assert model.weights[0] == pytest.approx(math.log(9), abs=1e-3)


def test_a_stronger_penalty_gives_smaller_weights() -> None:
    rows = [[-1.0], [1.0], [-1.2], [1.2]]
    labels = [False, True, False, True]

    loose = train(rows, labels, l2=0.01)
    tight = train(rows, labels, l2=50.0)

    assert abs(tight.weights[0]) < abs(loose.weights[0])


def test_training_stops_when_it_has_settled() -> None:
    model = train([[0.0]] * 4, [True, False, True, False])

    assert model.iterations <= 2


def test_a_strong_penalty_on_a_few_rows_does_not_diverge() -> None:
    """Gradient descent with a fixed step returned nan here."""
    model = train([[-1.0], [1.0], [-1.2], [1.2]], [False, True, False, True], l2=50.0)

    assert math.isfinite(model.bias)
    assert all(math.isfinite(weight) for weight in model.weights)
    assert 0 < model.weights[0] < 0.2


def test_perfectly_separable_examples_do_not_send_the_weights_to_infinity() -> None:
    rows = [[float(number)] for number in range(-10, 11) if number]
    labels = [row[0] > 0 for row in rows]

    model = train(rows, labels, l2=1.0)

    assert math.isfinite(model.weights[0]) and model.weights[0] < 50
    assert model.probability([5.0]) > 0.99


def test_the_fit_matches_a_value_worked_out_by_hand() -> None:
    """One feature, no penalty to speak of: the odds ratio of a two-by-two table.

    x=0: 1 passed of 4.  x=1: 3 passed of 4.
    bias = log(1/3), weight = log(3) - log(1/3) = log(9).
    """
    rows = [[0.0]] * 4 + [[1.0]] * 4
    labels = [True, False, False, False, True, True, True, False]

    model = train(rows, labels, l2=1e-9)

    assert model.bias == pytest.approx(math.log(1 / 3), abs=1e-4)
    assert model.weights[0] == pytest.approx(math.log(9), abs=1e-4)


def test_malformed_training_data_is_refused() -> None:
    with pytest.raises(ValueError, match="one label for every row"):
        train([[1.0]], [True, False])
    with pytest.raises(ValueError, match="at least one row"):
        train([], [])
    with pytest.raises(ValueError, match="same number of features"):
        train([[1.0], [1.0, 2.0]], [True, False])
    with pytest.raises(ValueError, match="negative"):
        train([[1.0]], [True], l2=-1.0)
    with pytest.raises(ValueError, match="different number of features"):
        Model((1.0, 2.0), 0.0).probability([1.0])


# --- scoring ------------------------------------------------------------------------


def test_area_under_the_curve_known_values() -> None:
    labels = [False, False, True, True]

    assert roc_auc([0.1, 0.2, 0.8, 0.9], labels) == 1.0
    assert roc_auc([0.9, 0.8, 0.2, 0.1], labels) == 0.0
    assert roc_auc([0.5, 0.5, 0.5, 0.5], labels) == 0.5
    # One of the four passed/rejected pairs is the wrong way round.
    assert roc_auc([0.1, 0.6, 0.5, 0.9], labels) == 0.75
    # A tie between a passed and a rejected fix counts as half.
    assert roc_auc([0.1, 0.5, 0.5, 0.9], labels) == 0.875


def test_area_under_the_curve_needs_both_outcomes() -> None:
    assert roc_auc([0.1, 0.9], [True, True]) is None
    assert roc_auc([0.1, 0.9], [False, False]) is None


def test_scores_count_a_prediction_of_exactly_one_half_as_passed() -> None:
    scores = score([0.5, 0.49, 0.9, 0.1], [True, True, False, False])

    assert scores.confusion == Confusion(tp=1, fn=1, fp=1, tn=1)
    assert scores.brier == pytest.approx((0.25 + 0.2601 + 0.81 + 0.01) / 4)


# --- folds ----------------------------------------------------------------------------


def test_every_example_is_in_exactly_one_fold() -> None:
    examples = made_up(100, informative=False)

    folds = grouped_folds(examples, 5, seed=3)

    assert sorted(position for fold in folds for position in fold) == list(range(100))
    assert max(len(fold) for fold in folds) - min(len(fold) for fold in folds) <= 1


def test_fixes_for_one_finding_are_never_split_between_folds() -> None:
    examples = [example(number, number % 3 == 0, finding_id=number // 4) for number in range(80)]

    folds = grouped_folds(examples, 5, seed=3)

    for fold in folds:
        inside = {examples[position].finding_id for position in fold}
        outside = {examples[p].finding_id for other in folds if other is not fold for p in other}
        assert not inside & outside


def test_the_folds_get_about_the_same_mix_of_outcomes() -> None:
    examples = [example(number, number < 30) for number in range(100)]

    folds = grouped_folds(examples, 5, seed=3)

    assert [sum(1 for p in fold if examples[p].passed) for fold in folds] == [6] * 5


def test_the_split_depends_on_the_seed_and_on_nothing_else() -> None:
    examples = made_up(60, informative=False)

    assert grouped_folds(examples, 5, seed=1) == grouped_folds(examples, 5, seed=1)
    assert grouped_folds(examples, 5, seed=1) != grouped_folds(examples, 5, seed=2)


def test_fewer_findings_than_folds_cannot_be_split() -> None:
    examples = [example(number, True, finding_id=number % 3) for number in range(30)]

    with pytest.raises(NotEnoughDataError, match="3 findings"):
        grouped_folds(examples, 5, seed=1)
    with pytest.raises(ValueError, match="at least two folds"):
        grouped_folds(examples, 1, seed=1)


# --- enough data ------------------------------------------------------------------------


def test_too_few_examples_are_refused_with_the_number_missing() -> None:
    examples = [example(number, number % 2 == 0) for number in range(40)]

    with pytest.raises(NotEnoughDataError) as caught:
        require_enough(examples)

    message = str(caught.value)
    assert "40 judged fixes (20 passed, 20 rejected)" in message
    assert "20 more judged fixes" in message


def test_too_few_of_one_outcome_are_refused_however_many_there_are_of_the_other() -> None:
    examples = [example(number, number >= 5) for number in range(100)]

    with pytest.raises(NotEnoughDataError, match="10 more that rejected"):
        require_enough(examples)


def test_exactly_enough_is_enough() -> None:
    passed = crossval.MIN_EXAMPLES - crossval.MIN_PER_CLASS
    require_enough([example(number, number < passed) for number in range(crossval.MIN_EXAMPLES)])


def test_cross_validation_refuses_rather_than_report_on_too_little() -> None:
    with pytest.raises(NotEnoughDataError):
        cross_validate(made_up(30, informative=True))


# --- cross-validation -------------------------------------------------------------------


def test_the_rule_baseline_is_not_certain_about_a_rule_it_saw_once() -> None:
    training = [example(1, True, rule_id="JV003")]
    training += [example(10 + n, n < 2, rule_id="PY003") for n in range(8)]
    testing = [
        example(50, True, rule_id="JV003"),
        example(51, True, rule_id="PY003"),
        example(52, True, rule_id="SQL001"),
    ]

    predicted = crossval.predict_fold(training, testing, l2=1.0)

    # One pass of one, plus one imaginary pass and one imaginary rejection.
    assert predicted[BY_RULE][0] == pytest.approx(2 / 3)
    assert predicted[BY_RULE][1] == pytest.approx((2 + 1) / (8 + 2))
    # A rule never seen in training gets the base rate of the training fold.
    assert predicted[BY_RULE][2] == pytest.approx(3 / 9)
    assert predicted[BASE_RATE] == [pytest.approx(3 / 9)] * 3


def test_every_fold_is_fitted_without_its_own_test_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    """The scaling and the vocabulary, not only the weights."""
    examples = made_up(100, informative=True)
    fitted_on: list[set[int]] = []
    original = Vectoriser.fit.__func__  # type: ignore[attr-defined]

    def recording(cls: type[Vectoriser], training: list[PatchExample]) -> Vectoriser:
        fitted_on.append({item.patch_id for item in training})
        return original(cls, training)  # type: ignore[no-any-return]

    monkeypatch.setattr(Vectoriser, "fit", classmethod(recording))
    held_out = grouped_folds(examples, 5, seed=crossval.DEFAULT_SEED)

    cross_validate(examples, folds=5, repeats=1)

    assert len(fitted_on) == 5
    for training, fold in zip(fitted_on, held_out, strict=True):
        assert not training & {examples[position].patch_id for position in fold}
        assert len(training) + len(fold) == 100


def test_a_pattern_that_is_there_is_found_and_beats_both_baselines() -> None:
    report = cross_validate(made_up(300, informative=True), repeats=3)

    model = report.summary(MODEL, "auc")
    by_rule = report.summary(BY_RULE, "auc")
    base = report.summary(BASE_RATE, "auc")
    assert model is not None and by_rule is not None and base is not None
    assert model.mean > 0.8
    assert by_rule.mean < 0.6
    # One answer for every fix in a fold ranks nothing above anything.
    assert (base.low, base.mean, base.high) == (0.5, 0.5, 0.5)
    assert store.verdict(report) == store.BETTER


def test_when_there_is_nothing_to_find_the_report_does_not_claim_a_result() -> None:
    report = cross_validate(made_up(300, informative=False), repeats=3)

    model = report.summary(MODEL, "auc")
    assert model is not None
    assert 0.35 < model.mean < 0.65
    assert store.verdict(report) != store.BETTER


def test_the_same_examples_and_seed_give_the_same_report() -> None:
    examples = made_up(80, informative=True)

    assert cross_validate(examples, repeats=2) == cross_validate(examples, repeats=2)


def test_a_report_says_how_far_each_figure_moved_between_repeats() -> None:
    report = cross_validate(made_up(120, informative=True), repeats=4)
    accuracy = report.summary(MODEL, "accuracy")
    assert accuracy is not None

    assert len(report.scores[MODEL]) == 4
    # Each repeat shuffles differently, so the figure moves.
    assert accuracy.low < accuracy.mean < accuracy.high
    assert report.examples == 120
    assert report.findings == 120
    assert report.model_only + report.baseline_only >= 0


def test_the_base_rate_baseline_is_as_accurate_as_the_commoner_outcome_is_common() -> None:
    examples = [example(number, number % 4 != 0, lines_added=number % 7) for number in range(80)]

    report = cross_validate(examples, repeats=1)

    accuracy = report.summary(BASE_RATE, "accuracy")
    assert accuracy is not None
    assert accuracy.mean == pytest.approx(0.75)


# --- the verdict ---------------------------------------------------------------------------


def hand_made(model_auc: list[float], rule_auc: list[float], **overrides: object) -> Report:
    def scores(values: list[float]) -> tuple[Scores, ...]:
        return tuple(Scores(Confusion(tp=1, tn=1), value, 0.2) for value in values)

    fields: dict[str, object] = {
        "examples": 100,
        "passed": 60,
        "findings": 90,
        "folds": 5,
        "repeats": len(model_auc),
        "seed": 16,
        "l2": 1.0,
        "scores": {
            MODEL: scores(model_auc),
            BY_RULE: scores(rule_auc),
            BASE_RATE: scores([0.5] * len(model_auc)),
        },
        "model_only": 20,
        "baseline_only": 5,
        "p_value": 0.004,
    }
    fields.update(overrides)
    return Report(**fields)  # type: ignore[arg-type]


def test_better_needs_a_higher_average_no_overlap_and_a_paired_test() -> None:
    assert store.verdict(hand_made([0.80, 0.78], [0.60, 0.62])) == store.BETTER


def test_overlapping_ranges_are_not_a_result() -> None:
    assert store.verdict(hand_made([0.80, 0.61], [0.60, 0.62])) == store.UNCLEAR


def test_a_paired_test_that_could_be_chance_is_not_a_result() -> None:
    assert store.verdict(hand_made([0.80, 0.78], [0.60, 0.62], p_value=0.2)) == store.UNCLEAR
    assert store.verdict(hand_made([0.80, 0.78], [0.60, 0.62], p_value=None)) == store.UNCLEAR


def test_a_model_that_wins_on_ranking_and_loses_on_predictions_is_not_a_result() -> None:
    report = hand_made([0.80, 0.78], [0.60, 0.62], model_only=5, baseline_only=20)
    assert store.verdict(report) == store.UNCLEAR


def test_a_gap_too_small_to_mean_anything_is_no_better() -> None:
    assert store.verdict(hand_made([0.61, 0.62], [0.60, 0.61])) == store.NO_BETTER
    assert store.verdict(hand_made([0.50, 0.52], [0.60, 0.62])) == store.NO_BETTER


# --- files -------------------------------------------------------------------------------------


def trained(examples: list[PatchExample]) -> tuple[Vectoriser, Model, Report]:
    vectoriser = Vectoriser.fit(examples)
    model = train([vectoriser.transform(item) for item in examples], [i.passed for i in examples])
    return vectoriser, model, cross_validate(examples, repeats=2)


def collected(examples: list[PatchExample]) -> Collected:
    return Collected(examples, len(examples) + 9, 1, 2, 3, 1, 2)


def test_a_saved_model_predicts_exactly_what_it_predicted_before(tmp_path: Path) -> None:
    examples = made_up(80, informative=True)
    vectoriser, model, report = trained(examples)
    path = tmp_path / "models" / "patch_outcome.json"

    store.save(
        path,
        store.as_data(
            vectoriser, model, report, examples, trained_at=TRAINED_AT, tool_version="0.1.0"
        ),
    )
    loaded_vectoriser, loaded_model = store.load(path)

    for item in examples[:10]:
        assert loaded_model.probability(loaded_vectoriser.transform(item)) == model.probability(
            vectoriser.transform(item)
        )
    assert b"\r" not in path.read_bytes()


def test_the_model_file_says_what_it_was_trained_on(tmp_path: Path) -> None:
    examples = made_up(80, informative=True)
    vectoriser, model, report = trained(examples)

    data = store.as_data(
        vectoriser, model, report, examples, trained_at=TRAINED_AT, tool_version="0.1.0"
    )

    assert data["schema"] == 1
    assert data["trained_at"] == "2026-10-04T09:30:00+00:00"
    assert data["data"]["examples"] == 80
    assert data["data"]["passed"] + data["data"]["rejected"] == 80
    assert data["data"]["fingerprint"] == store.fingerprint(examples)
    assert len(data["model"]["weights"]) == len(data["vectoriser"]["names"])
    assert set(data["cross_validation"]["predictors"]) == {MODEL, BY_RULE, BASE_RATE}
    assert data["cross_validation"]["verdict"] == store.verdict(report)
    json.dumps(data)  # everything in it can be written


def test_the_data_fingerprint_changes_when_one_outcome_does() -> None:
    examples = made_up(20, informative=True)
    flipped = [*examples[:-1], example(examples[-1].patch_id, not examples[-1].passed)]

    assert store.fingerprint(examples) == store.fingerprint(list(reversed(examples)))
    assert store.fingerprint(examples) != store.fingerprint(flipped)
    assert store.fingerprint(examples) != store.fingerprint(examples[:-1])


@pytest.mark.parametrize(
    "change",
    [
        lambda data: data.update(schema=99),
        lambda data: data.update(kind="something-else"),
        lambda data: data["model"].pop("bias"),
        lambda data: data["model"].update(weights=[1.0]),
        lambda data: data["model"].update(weights="not a list of numbers"),
        lambda data: data.pop("vectoriser"),
    ],
)
def test_a_model_file_that_is_not_what_was_written_is_refused(tmp_path: Path, change) -> None:  # type: ignore[no-untyped-def]
    examples = made_up(80, informative=True)
    vectoriser, model, report = trained(examples)
    data = store.as_data(
        vectoriser, model, report, examples, trained_at=TRAINED_AT, tool_version="0.1.0"
    )
    change(data)
    path = tmp_path / "model.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(store.ModelFileError):
        store.load(path)


def test_a_model_file_that_is_missing_or_not_json_is_refused(tmp_path: Path) -> None:
    with pytest.raises(store.ModelFileError, match="could not be read"):
        store.load(tmp_path / "missing.json")
    (tmp_path / "bad.json").write_text("not json", encoding="utf-8")
    with pytest.raises(store.ModelFileError, match="could not be read"):
        store.load(tmp_path / "bad.json")


# --- the report ---------------------------------------------------------------------------------


def report_for(examples: list[PatchExample]) -> str:
    vectoriser, model, report = trained(examples)
    return store.as_markdown(
        collected(examples), report, vectoriser, model, trained_at=TRAINED_AT, tool_version="0.1.0"
    )


def test_the_report_states_the_data_and_what_was_left_out() -> None:
    examples = made_up(80, informative=True)
    page = report_for(examples)
    passed = sum(1 for item in examples if item.passed)

    assert "| Judged fixes used | 80 |" in page
    assert f"| Passed / rejected | {passed} / {80 - passed} |" in page
    assert "89 fixes have been requested." in page
    assert "| Checked, but could not be judged | 2 | no: no verdict |" in page
    assert "| Proposed, not checked yet | 4 | no |" in page
    assert "| Refused before it became a proposal | 2 | no |" in page
    assert "| Trained | 2026-10-04 09:30 UTC |" in page


def test_the_report_has_the_model_and_both_baselines_in_one_table() -> None:
    page = report_for(made_up(80, informative=True))

    assert "| Logistic regression |" in page
    assert "| Baseline: pass rate of the rule |" in page
    assert "| Baseline: always the commoner outcome |" in page
    assert "5-fold cross-validation, repeated 2 times" in page


def test_the_report_says_what_passed_does_not_mean() -> None:
    page = report_for(made_up(80, informative=True))

    assert "It does not mean the fix is correct" in page
    assert "A weight is not a cause." in page


@pytest.mark.parametrize(
    ("verdict", "sentence"),
    [
        (store.BETTER, "The model predicts better than knowing the rule alone."),
        (store.UNCLEAR, "ahead of the rule-only baseline on average, but not clearly"),
        (store.NO_BETTER, "The model does not predict better than knowing the rule alone."),
    ],
)
def test_the_report_says_which_of_the_three_things_happened(
    monkeypatch: pytest.MonkeyPatch, verdict: str, sentence: str
) -> None:
    monkeypatch.setattr(store, "verdict", lambda _report: verdict)

    page = report_for(made_up(80, informative=True))

    assert sentence in page
    others = [text for key, text in store.CONCLUSIONS.items() if key != verdict]
    assert not any(text in page for text in others)


def test_the_report_lists_the_largest_weights_with_their_direction() -> None:
    page = report_for(made_up(200, informative=True))
    table = page.split("## What the model learnt")[1].split("## What this does not show")[0]
    rows = [line for line in table.splitlines() if line.startswith("| ") and "Weight" not in line]

    assert 1 <= len([row for row in rows if "---" not in row]) <= store.LISTED_WEIGHTS
    assert "| lines added | -" in table  # more lines, less likely to pass, in this made-up data
    assert "rejected |" in table
