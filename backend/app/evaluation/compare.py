"""Was one run better than another, or just different?

Two runs over the same test cases are compared case by case. A case both runs
judged correctly, or both judged wrongly, says nothing about which is better;
only the cases they disagree on do. McNemar's test asks how likely a split at
least that uneven would be if the two runs were equally good.

This is what stops "the score went up" being reported for a change that fixed
nine cases and broke eight.
"""

import csv
import io
from dataclasses import dataclass
from pathlib import Path

from app.evaluation.benchmark import NAME, BenchmarkError
from app.evaluation.metrics import mcnemar
from app.evaluation.runner import Evaluation

MAX_OUTCOME_BYTES = 10 * 1024 * 1024
REPORTED = {"yes": True, "no": False}


@dataclass(frozen=True)
class Comparison:
    cases: int
    # Judged correctly by the earlier run and wrongly by this one.
    broken: int
    # Judged wrongly by the earlier run and correctly by this one.
    fixed: int
    p_value: float | None

    @property
    def net(self) -> int:
        return self.fixed - self.broken


def load_outcomes(path: Path) -> dict[str, bool]:
    """Test name -> whether it was reported, from a file written by ``--cases``."""
    try:
        if path.is_symlink() or not path.is_file():
            raise BenchmarkError("The earlier outcomes are not a regular file.")
        if path.stat().st_size > MAX_OUTCOME_BYTES:
            raise BenchmarkError("The earlier outcomes file is too large to be one.")
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as error:
        raise BenchmarkError("The earlier outcomes could not be read.") from error

    reader = csv.DictReader(io.StringIO(text, newline=""))
    if not reader.fieldnames or not {"name", "reported"} <= set(reader.fieldnames):
        raise BenchmarkError("The earlier outcomes file has no name and reported columns.")
    outcomes: dict[str, bool] = {}
    for number, row in enumerate(reader, start=2):
        name = (row.get("name") or "").strip()
        reported = (row.get("reported") or "").strip().lower()
        if not NAME.fullmatch(name) or reported not in REPORTED or name in outcomes:
            raise BenchmarkError(f"Line {number} of the earlier outcomes file is not usable.")
        outcomes[name] = REPORTED[reported]
    return outcomes


def compare(earlier: dict[str, bool], evaluation: Evaluation) -> Comparison:
    """Compare an earlier run with this one, over exactly this run's cases.

    Refuses when the earlier run did not judge a case this one did: a missing
    case is not a wrong answer, and counting it as one would manufacture an
    improvement.
    """
    missing = [item.case.name for item in evaluation.outcomes if item.case.name not in earlier]
    if missing:
        raise BenchmarkError(
            f"The earlier run has no outcome for {len(missing)} of these test cases "
            f"(the first is {missing[0]}), so the two runs cannot be compared."
        )
    broken = fixed = 0
    for item in evaluation.outcomes:
        was_correct = earlier[item.case.name] == item.case.vulnerable
        if was_correct and not item.correct:
            broken += 1
        elif item.correct and not was_correct:
            fixed += 1
    return Comparison(
        cases=len(evaluation.outcomes),
        broken=broken,
        fixed=fixed,
        p_value=mcnemar(broken, fixed),
    )


__all__ = ["Comparison", "compare", "load_outcomes"]
