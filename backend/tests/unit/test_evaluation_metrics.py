"""The arithmetic behind the results table, checked against published values.

If one of these is wrong, every number in the evaluation chapter is wrong in
the same direction and nothing else in the suite would notice.
"""

import pytest

from app.evaluation.metrics import Confusion, Interval, mcnemar, mean, wilson


def test_the_four_counts_give_the_textbook_ratios() -> None:
    confusion = Confusion(tp=30, fn=10, fp=20, tn=40)

    assert confusion.positives == 40
    assert confusion.negatives == 60
    assert confusion.total == 100
    assert confusion.reported == 50
    assert confusion.recall == pytest.approx(0.75)
    assert confusion.false_positive_rate == pytest.approx(1 / 3)
    assert confusion.precision == pytest.approx(0.6)
    assert confusion.accuracy == pytest.approx(0.7)
    assert confusion.f1 == pytest.approx(2 * 0.6 * 0.75 / (0.6 + 0.75))
    assert confusion.score == pytest.approx(0.75 - 1 / 3)


def test_reporting_everything_scores_zero_not_full_marks() -> None:
    everything = Confusion(tp=40, fn=0, fp=60, tn=0)

    assert everything.recall == 1.0
    assert everything.score == 0.0


def test_reporting_nothing_scores_zero_and_has_no_precision() -> None:
    nothing = Confusion(tp=0, fn=40, fp=0, tn=60)

    assert nothing.recall == 0.0
    assert nothing.score == 0.0
    # Nothing was reported, so there is nothing to be precise about. Not 0 %
    # and not 100 %: undefined.
    assert nothing.precision is None
    assert nothing.precision_interval is None
    # F1 is defined here, and it is zero: every vulnerability was missed.
    assert nothing.f1 == 0.0


def test_being_wrong_more_often_than_right_scores_below_zero() -> None:
    assert Confusion(tp=1, fn=9, fp=9, tn=1).score == pytest.approx(-0.8)


def test_a_ratio_with_nothing_underneath_it_is_undefined() -> None:
    no_vulnerable_cases = Confusion(tp=0, fn=0, fp=2, tn=8)
    no_safe_cases = Confusion(tp=5, fn=5, fp=0, tn=0)
    empty = Confusion()

    assert no_vulnerable_cases.recall is None
    assert no_vulnerable_cases.score is None
    assert no_vulnerable_cases.score_interval is None
    assert no_safe_cases.false_positive_rate is None
    assert no_safe_cases.score is None
    assert empty.accuracy is None
    assert empty.f1 is None


def test_counts_add_up_category_by_category() -> None:
    total = Confusion(tp=1, fp=2, tn=3, fn=4) + Confusion(tp=10, fp=20, tn=30, fn=40)

    assert total == Confusion(tp=11, fp=22, tn=33, fn=44)


def test_a_negative_count_is_refused() -> None:
    with pytest.raises(ValueError, match="negative"):
        Confusion(tp=-1)


def test_wilson_interval_matches_known_values() -> None:
    half = wilson(5, 10)
    assert half is not None
    assert half.low == pytest.approx(0.2366, abs=1e-4)
    assert half.high == pytest.approx(0.7634, abs=1e-4)


def test_wilson_interval_has_width_at_zero_and_at_one() -> None:
    """Where the textbook interval collapses to nothing and claims certainty."""
    none = wilson(0, 10)
    every = wilson(10, 10)

    assert none == Interval(0.0, pytest.approx(0.2775, abs=1e-4))
    assert every == Interval(pytest.approx(0.7225, abs=1e-4), 1.0)


def test_more_cases_give_a_narrower_interval_for_the_same_proportion() -> None:
    few, many = wilson(5, 5), wilson(500, 500)
    assert few is not None and many is not None

    assert few.low < 0.6
    assert many.low > 0.99


def test_wilson_interval_needs_trials_and_sane_counts() -> None:
    assert wilson(0, 0) is None
    with pytest.raises(ValueError, match="between"):
        wilson(11, 10)
    with pytest.raises(ValueError, match="between"):
        wilson(-1, 10)


def test_the_score_interval_matches_newcombes_published_example() -> None:
    """56/70 against 48/80: Newcombe (1998), method 10, gives 0.0524 to 0.3339."""
    confusion = Confusion(tp=56, fn=14, fp=48, tn=32)
    interval = confusion.score_interval
    assert interval is not None

    assert confusion.score == pytest.approx(0.2)
    assert interval.low == pytest.approx(0.0524, abs=1e-4)
    assert interval.high == pytest.approx(0.3339, abs=1e-4)
    assert interval.excludes(0.0)


def test_a_score_from_a_handful_of_cases_cannot_exclude_guessing() -> None:
    interval = Confusion(tp=2, fn=1, fp=1, tn=2).score_interval
    assert interval is not None

    assert not interval.excludes(0.0)


def test_the_score_interval_stays_inside_what_a_score_can_be() -> None:
    perfect = Confusion(tp=3, fn=0, fp=0, tn=3).score_interval
    inverted = Confusion(tp=0, fn=3, fp=3, tn=0).score_interval
    assert perfect is not None and inverted is not None

    assert perfect.high == 1.0
    assert inverted.low == -1.0


def test_mean_ignores_what_is_undefined_and_is_undefined_when_everything_is() -> None:
    assert mean([0.5, None, 1.0]) == pytest.approx(0.75)
    assert mean([None, None]) is None
    assert mean([]) is None
    assert mean([0.0, 0.0]) == 0.0


def test_mcnemar_exact_values() -> None:
    # 1 against 9: 2 * (C(10,0) + C(10,1)) / 2**10
    assert mcnemar(1, 9) == pytest.approx(22 / 1024)
    assert mcnemar(9, 1) == pytest.approx(22 / 1024)
    assert mcnemar(0, 6) == pytest.approx(2 / 64)


def test_mcnemar_says_an_even_split_is_no_evidence() -> None:
    assert mcnemar(5, 5) == 1.0


def test_mcnemar_has_nothing_to_say_when_no_case_changed() -> None:
    assert mcnemar(0, 0) is None
    with pytest.raises(ValueError, match="negative"):
        mcnemar(-1, 3)


@pytest.mark.parametrize("trials", [1, 7, 100, 20000])
def test_an_interval_never_excludes_what_was_observed_at_either_end(trials: int) -> None:
    """Rounding in the square root must not report 0.99999 as the top of 20000/20000."""
    none, every = wilson(0, trials), wilson(trials, trials)
    assert none is not None and every is not None

    assert none.low == 0.0
    assert every.high == 1.0
