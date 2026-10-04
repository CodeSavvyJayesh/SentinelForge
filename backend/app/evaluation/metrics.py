"""The arithmetic of being right and wrong, and nothing else.

Pure functions over four counts. No file is read here and no rule is known
here, so every number in a results table can be checked by hand against this
file alone.

Three decisions that are easy to get wrong and change what a table says.

**An undefined ratio is ``None``, never zero.** A scanner that reports nothing
has no precision — there is nothing to be precise about. Printing 0 % would
call it maximally wrong, printing 100 % would call it perfect, and both would
be invented. The table shows a dash.

**A proportion is reported with its interval.** Five test cases out of five is
100 %, and so is five hundred out of five hundred, and they are not the same
evidence. The Wilson interval is used because the usual textbook one collapses
to zero width at exactly the 0 % and 100 % this benchmark produces.

**The headline is the benchmark's own score: true positive rate minus false
positive rate.** A scanner that flags every file catches every vulnerability —
recall 100 % — and is useless, and this score gives it exactly zero. So does
flagging nothing, and so does guessing. It is the only single number here that
cannot be raised by reporting more.
"""

import math
from dataclasses import dataclass

# Two-sided 95 %.
Z_95 = 1.959963984540054


@dataclass(frozen=True)
class Interval:
    low: float
    high: float

    def excludes(self, value: float) -> bool:
        return value < self.low or value > self.high


@dataclass(frozen=True)
class Confusion:
    """How a set of test cases with known answers was judged."""

    tp: int = 0  # vulnerable, reported
    fp: int = 0  # safe, reported
    tn: int = 0  # safe, not reported
    fn: int = 0  # vulnerable, not reported

    def __post_init__(self) -> None:
        if min(self.tp, self.fp, self.tn, self.fn) < 0:
            raise ValueError("a count cannot be negative")

    def __add__(self, other: "Confusion") -> "Confusion":
        return Confusion(
            self.tp + other.tp, self.fp + other.fp, self.tn + other.tn, self.fn + other.fn
        )

    @property
    def positives(self) -> int:
        """Test cases that really are vulnerable."""
        return self.tp + self.fn

    @property
    def negatives(self) -> int:
        """Test cases that only look vulnerable."""
        return self.fp + self.tn

    @property
    def total(self) -> int:
        return self.positives + self.negatives

    @property
    def reported(self) -> int:
        return self.tp + self.fp

    @property
    def recall(self) -> float | None:
        """True positive rate: of the vulnerable cases, the share reported."""
        return _ratio(self.tp, self.positives)

    @property
    def false_positive_rate(self) -> float | None:
        """Of the safe cases, the share reported anyway."""
        return _ratio(self.fp, self.negatives)

    @property
    def precision(self) -> float | None:
        """Of what was reported, the share that was really vulnerable."""
        return _ratio(self.tp, self.reported)

    @property
    def accuracy(self) -> float | None:
        return _ratio(self.tp + self.tn, self.total)

    @property
    def f1(self) -> float | None:
        """Harmonic mean of precision and recall.

        Written as ``2TP / (2TP + FP + FN)``, which is the same number and is
        defined in the case that matters: a scanner that reports nothing while
        vulnerabilities exist scores 0, not "undefined".
        """
        return _ratio(2 * self.tp, 2 * self.tp + self.fp + self.fn)

    @property
    def score(self) -> float | None:
        """True positive rate minus false positive rate (Youden's J).

        +1 is perfect, 0 is no better than guessing, below 0 is worse than
        guessing. ``None`` when either rate has nothing to be a rate of.
        """
        recall, false_positive_rate = self.recall, self.false_positive_rate
        if recall is None or false_positive_rate is None:
            return None
        return recall - false_positive_rate

    @property
    def recall_interval(self) -> Interval | None:
        return wilson(self.tp, self.positives)

    @property
    def false_positive_rate_interval(self) -> Interval | None:
        return wilson(self.fp, self.negatives)

    @property
    def precision_interval(self) -> Interval | None:
        return wilson(self.tp, self.reported)

    @property
    def score_interval(self) -> Interval | None:
        """Interval for the difference of the two rates (Newcombe's method).

        The two rates are measured on different test cases — one on the
        vulnerable ones, one on the safe ones — so they are independent, which
        is what this construction assumes. If the interval contains zero, the
        result cannot be told apart from guessing with this many cases.
        """
        recall, rate = self.recall, self.false_positive_rate
        upper, lower = self.recall_interval, self.false_positive_rate_interval
        if recall is None or rate is None or upper is None or lower is None:
            return None
        difference = recall - rate
        below = math.hypot(recall - upper.low, lower.high - rate)
        above = math.hypot(upper.high - recall, rate - lower.low)
        # Always within -1..+1: each bound of the difference is at least as far
        # in as the corresponding bounds of the two rates.
        return Interval(difference - below, difference + above)


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def wilson(successes: int, trials: int, z: float = Z_95) -> Interval | None:
    """Wilson score interval for a proportion. ``None`` when there were no trials."""
    if trials <= 0:
        return None
    if not 0 <= successes <= trials:
        raise ValueError("successes must be between 0 and the number of trials")
    proportion = successes / trials
    denominator = 1 + z * z / trials
    centre = (proportion + z * z / (2 * trials)) / denominator
    margin = (
        z
        * math.sqrt(proportion * (1 - proportion) / trials + z * z / (4 * trials * trials))
        / denominator
    )
    # At the two ends the exact bound is the proportion itself; rounding in the
    # square root must not report an interval that excludes what was observed.
    low = 0.0 if successes == 0 else max(0.0, centre - margin)
    high = 1.0 if successes == trials else min(1.0, centre + margin)
    return Interval(low, high)


def mean(values: list[float | None]) -> float | None:
    """Average of the values that exist. ``None`` when none do."""
    present = [value for value in values if value is not None]
    return sum(present) / len(present) if present else None


def mcnemar(only_first: int, only_second: int) -> float | None:
    """Exact two-sided McNemar test: did two runs over the same cases differ?

    ``only_first`` is the number of cases the first run judged correctly and
    the second did not; ``only_second`` the reverse. Cases both got right or
    both got wrong say nothing about which is better and do not appear.

    Returns the probability of a split at least this uneven if the two runs
    were equally good. ``None`` when no case was judged differently.
    """
    if only_first < 0 or only_second < 0:
        raise ValueError("a count cannot be negative")
    discordant = only_first + only_second
    if discordant == 0:
        return None
    smaller = min(only_first, only_second)
    tail = sum(math.comb(discordant, k) for k in range(smaller + 1)) / 2**discordant
    return min(1.0, 2 * tail)


__all__ = ["Confusion", "Interval", "Z_95", "mcnemar", "mean", "wilson"]
