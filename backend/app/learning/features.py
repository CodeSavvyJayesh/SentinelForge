"""What is known about a proposed fix before anyone checks it.

Only that. The label is "did the re-scan support it", so anything recorded by
the re-scan — findings before and after, the checks that ran — would be the
answer smuggled in as a question. Every field here is written when the
proposal is created.

Turning an example into numbers is done by a :class:`Vectoriser` that is
**fitted on the training examples only**: which rules are common enough to get
a column of their own, and the mean and spread used to scale each number, are
decided without looking at the examples the model will be tested on.
"""

import math
from collections import Counter
from dataclasses import dataclass

# A category seen fewer times than this in training shares the "other" column:
# a column that is 1 for two examples teaches the model those two examples.
MIN_CATEGORY_COUNT = 3
OTHER = "other"


@dataclass(frozen=True)
class PatchExample:
    patch_id: int
    # Fixes for one finding are near-copies of each other, so they are kept on
    # the same side of every train/test split.
    finding_id: int
    passed: bool
    rule_id: str
    severity: str
    confidence: str
    suffix: str  # ".py", ".java"
    lines_added: int
    lines_removed: int
    region_lines: int
    diff_characters: int
    rationale_characters: int
    fences_stripped: bool
    gutters_stripped: int
    reindented: bool
    attempts: int
    had_explanation: bool
    passages: int
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    duration_ms: int | None = None
    temperature: float | None = None


# name -> how to read it from an example. Counts are log-scaled: the difference
# between 1 and 10 changed lines matters more than between 101 and 110.
NUMBERS: dict[str, tuple[str, bool]] = {
    "lines added": ("lines_added", True),
    "lines removed": ("lines_removed", True),
    "lines the model could change": ("region_lines", True),
    "size of the diff": ("diff_characters", True),
    "length of the rationale": ("rationale_characters", True),
    "line-number gutters stripped": ("gutters_stripped", True),
    "generation attempts": ("attempts", False),
    "knowledge passages used": ("passages", False),
    "prompt tokens": ("prompt_tokens", True),
    "completion tokens": ("completion_tokens", True),
    "generation time": ("duration_ms", True),
    "temperature": ("temperature", False),
}
FLAGS: dict[str, str] = {
    "code fences stripped": "fences_stripped",
    "re-indented": "reindented",
    "had an explanation": "had_explanation",
}
CATEGORIES: dict[str, str] = {
    "rule": "rule_id",
    "severity": "severity",
    "confidence": "confidence",
    "file type": "suffix",
}


def _number(example: PatchExample, attribute: str, logarithmic: bool) -> float | None:
    value = getattr(example, attribute)
    if value is None:
        return None
    number = float(value)
    return math.log1p(max(number, 0.0)) if logarithmic else number


@dataclass(frozen=True)
class Vectoriser:
    names: tuple[str, ...]
    # For each numeric feature: (mean, spread) of the training examples.
    scales: tuple[tuple[str, float, float], ...]
    # For each categorical feature: the values that have a column of their own.
    vocabulary: tuple[tuple[str, tuple[str, ...]], ...]

    @classmethod
    def fit(cls, examples: list[PatchExample]) -> "Vectoriser":
        scales = []
        for name, (attribute, logarithmic) in NUMBERS.items():
            present = [
                value
                for value in (_number(item, attribute, logarithmic) for item in examples)
                if value is not None
            ]
            mean = sum(present) / len(present) if present else 0.0
            variance = (
                sum((value - mean) ** 2 for value in present) / len(present) if present else 0.0
            )
            # A feature that never varies gets spread 1, so it becomes all zeros
            # rather than a division by zero.
            scales.append((name, mean, math.sqrt(variance) or 1.0))

        vocabulary = []
        for name, attribute in CATEGORIES.items():
            counts = Counter(str(getattr(item, attribute)) for item in examples)
            kept = sorted(value for value, count in counts.items() if count >= MIN_CATEGORY_COUNT)
            vocabulary.append((name, tuple(kept)))

        names: list[str] = []
        for name, _mean, _spread in scales:
            names += [name, f"{name}: not recorded"]
        names += list(FLAGS)
        for name, values in vocabulary:
            names += [f"{name} = {value}" for value in (*values, OTHER)]
        return cls(tuple(names), tuple(scales), tuple(vocabulary))

    def transform(self, example: PatchExample) -> list[float]:
        row: list[float] = []
        for name, mean, spread in self.scales:
            attribute, logarithmic = NUMBERS[name]
            value = _number(example, attribute, logarithmic)
            # A missing number is "average" plus a flag saying it was missing,
            # so the model can learn from the absence without a made-up value.
            row += [0.0, 1.0] if value is None else [(value - mean) / spread, 0.0]
        row += [1.0 if getattr(example, attribute) else 0.0 for attribute in FLAGS.values()]
        for name, values in self.vocabulary:
            actual = str(getattr(example, CATEGORIES[name]))
            row += [1.0 if actual == value else 0.0 for value in values]
            row.append(0.0 if actual in values else 1.0)
        return row


__all__ = ["CATEGORIES", "FLAGS", "MIN_CATEGORY_COUNT", "NUMBERS", "PatchExample", "Vectoriser"]
