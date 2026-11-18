"""The two commands, without the parts that open a database.

``scripts/train_patch_classifier.py`` and ``scripts/collect_patch_outcomes.py``
are thin: they open a session and call these. Kept here so the behaviour that
matters — refusing to train on too little, saying what is missing, exiting
with the right code — is covered by tests that do not need a script to be run.

Exit codes, the same three as the scanner's: ``0`` done, ``1`` the data says
no (too few examples), ``2`` the command could not be carried out.
"""

import time
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

from sqlalchemy.orm import Session

from app.learning import collection, crossval, store
from app.learning.dataset import Collected, collect
from app.learning.features import Vectoriser
from app.learning.logistic import DEFAULT_L2, train

EXIT_OK = 0
EXIT_NOT_ENOUGH = 1
EXIT_ERROR = 2


def describe(collected: Collected, out: TextIO) -> None:
    """What is in the database, in the terms the training needs."""
    write = lambda line="": print(line, file=out)  # noqa: E731
    write(f"Fixes requested:             {collected.requested}")
    write(f"  with a verdict (usable):   {len(collected.examples)}")
    write(f"    passed:                  {collected.passed}")
    write(f"    rejected:                {collected.rejected}")
    write(f"  checked, not judged:       {collected.not_judged}")
    write(f"  proposed, not checked:     {collected.unchecked + collected.checking}")
    write(f"  refused before a proposal: {collected.refused}")
    write(f"  still being generated:     {collected.generating}")
    if collected.examples:
        write()
        write("  rule      passed  rejected")
        for rule, passed, rejected in collected.by_rule():
            write(f"  {rule:<9} {passed:>6}  {rejected:>8}")


def train_command(  # noqa: PLR0913 - one argument per option of the command
    db: Session,
    *,
    model_path: Path,
    report_path: Path,
    tool_version: str,
    out: TextIO,
    status_only: bool = False,
    folds: int = crossval.DEFAULT_FOLDS,
    repeats: int = crossval.DEFAULT_REPEATS,
    seed: int = crossval.DEFAULT_SEED,
    l2: float = DEFAULT_L2,
    now: datetime | None = None,
) -> int:
    collected = collect(db)
    describe(collected, out)
    print(file=out)
    if status_only:
        try:
            crossval.require_enough(collected.examples)
        except crossval.NotEnoughDataError as error:
            print(f"Not enough to train on yet. {error}", file=out)
            return EXIT_NOT_ENOUGH
        print("Enough to train on.", file=out)
        return EXIT_OK

    try:
        report = crossval.cross_validate(
            collected.examples, folds=folds, repeats=repeats, seed=seed, l2=l2
        )
    except crossval.NotEnoughDataError as error:
        print(f"Not trained. {error}", file=out)
        print("No model and no report were written.", file=out)
        return EXIT_NOT_ENOUGH
    except ValueError as error:
        print(f"error: {error}", file=out)
        return EXIT_ERROR

    # The model that is kept is trained on everything. What is known about how
    # well it predicts is the cross-validation above, not anything it does here.
    vectoriser = Vectoriser.fit(collected.examples)
    model = train(
        [vectoriser.transform(item) for item in collected.examples],
        [item.passed for item in collected.examples],
        l2=l2,
    )
    trained_at = now or datetime.now(UTC)
    try:
        store.save(
            model_path,
            store.as_data(
                vectoriser,
                model,
                report,
                collected.examples,
                trained_at=trained_at,
                tool_version=tool_version,
            ),
        )
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with report_path.open("w", encoding="utf-8", newline="") as handle:
            handle.write(
                store.as_markdown(
                    collected,
                    report,
                    vectoriser,
                    model,
                    trained_at=trained_at,
                    tool_version=tool_version,
                )
            )
    except OSError as error:
        print(f"error: could not write the model or the report: {error}", file=out)
        return EXIT_ERROR

    accuracy = report.summary(crossval.MODEL, "accuracy")
    auc = report.summary(crossval.MODEL, "auc")
    baseline = report.summary(crossval.BY_RULE, "auc")
    print(f"Trained on {report.examples} judged fixes for {report.findings} findings.", file=out)
    if accuracy is not None:
        print(f"  cross-validated accuracy: {accuracy.mean * 100:.1f} %", file=out)
    if auc is not None and baseline is not None:
        print(
            f"  cross-validated AUC: {auc.mean:.3f} (rule-only baseline: {baseline.mean:.3f})",
            file=out,
        )
    print(f"  against the rule-only baseline: {store.verdict(report)}", file=out)
    print(f"Model:  {model_path}", file=out)
    print(f"Report: {report_path}", file=out)
    return EXIT_OK


def collect_command(db: Session, *, action: str, limit: int, again: bool, out: TextIO) -> int:
    if limit < 1:
        print("error: --limit must be at least 1", file=out)
        return EXIT_ERROR
    if action == "fixes":
        queued = collection.queue_fixes(db, limit=limit, again=again)
        db.commit()
        print(f"Asked for {queued.added} fix(es); {queued.left} more qualify.", file=out)
    elif action == "checks":
        queued = collection.queue_checks(db, limit=limit)
        db.commit()
        print(f"Asked for {queued.added} check(s); {queued.left} more qualify.", file=out)
    elif action != "status":
        print(f"error: unknown action: {action}", file=out)
        return EXIT_ERROR
    if action != "status" and queued.added:
        print(
            "The running application does the work: start the backend (with the language "
            "model available for fixes) and run 'status' to watch the counts move.",
            file=out,
        )
    print(file=out)
    describe(collect(db), out)
    return EXIT_OK


# --- collecting until there is enough --------------------------------------

# How long the counts may stay exactly the same, with work outstanding, before
# the loop concludes that nothing is doing the work.
STALL_MINUTES = 15

WAIT = "wait"
QUEUE_CHECKS = "checks"
QUEUE_FIXES = "fixes"
DONE = "done"


@dataclass(frozen=True)
class Step:
    action: str
    reason: str


def next_step(collected: Collected) -> Step:
    """What the collection loop does next, from the counts alone.

    Checks before fixes: a proposal waiting for a check is an example nearly
    made, and checking costs no model time. New fixes are asked for only when
    nothing is being generated, so the model is never handed a queue it would
    take hours to work through while the counts tell the user nothing.
    """
    try:
        crossval.require_enough(collected.examples)
        return Step(DONE, "There is enough to train on.")
    except crossval.NotEnoughDataError as error:
        missing = str(error)
    if collected.unchecked:
        return Step(QUEUE_CHECKS, f"{collected.unchecked} proposal(s) to check.")
    if collected.generating or collected.checking:
        return Step(WAIT, missing)
    return Step(QUEUE_FIXES, missing)


def auto_command(  # noqa: PLR0913 - one argument per knob, all with defaults
    sessions: Callable[[], AbstractContextManager[Session]],
    *,
    out: TextIO,
    batch: int = 10,
    poll_seconds: float = 20,
    max_minutes: float = 12 * 60,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> int:
    """Ask for fixes and checks until there is enough to train on.

    The backend's workers do the work, so it has to be running — with Ollama,
    for fixes. This only queues requests, a few at a time, and watches. It stops
    when there is enough, when nothing qualifies any more (more findings are
    needed: scan more code), when the counts have not moved for a long time with
    work outstanding (the backend is not running), or after ``max_minutes``.
    """
    if batch < 1 or poll_seconds <= 0 or max_minutes <= 0:
        print("error: --batch, --poll and --minutes must be positive", file=out)
        return EXIT_ERROR
    started = clock()
    last_counts: tuple[int, ...] | None = None
    unchanged_since = started
    retried = False
    while True:
        with sessions() as db:
            collected = collect(db)
            step = next_step(collected)
            counts = (
                len(collected.examples),
                collected.generating,
                collected.unchecked,
                collected.checking,
                collected.refused,
            )
            print(
                f"[{(clock() - started) / 60:5.1f} min] judged {len(collected.examples)} "
                f"({collected.passed} passed, {collected.rejected} rejected), "
                f"generating {collected.generating}, "
                f"to check {collected.unchecked + collected.checking}",
                file=out,
                flush=True,
            )
            if step.action == DONE:
                print(step.reason, file=out)
                print("Next: python scripts/train_patch_classifier.py", file=out)
                return EXIT_OK
            if step.action == QUEUE_CHECKS:
                collection.queue_checks(db, limit=batch)
                db.commit()
            elif step.action == QUEUE_FIXES:
                queued = collection.queue_fixes(db, limit=batch, again=retried)
                if not queued.added and not retried:
                    # Every finding has a judged fix. A second attempt where the
                    # first was rejected is a further example.
                    retried = True
                    queued = collection.queue_fixes(db, limit=batch, again=True)
                db.commit()
                if not queued.added:
                    print(
                        "No more findings qualify for a fix. Scan more code (the more "
                        f"different rules, the better), then run this again. {step.reason}",
                        file=out,
                    )
                    return EXIT_NOT_ENOUGH

        now = clock()
        if counts != last_counts:
            last_counts, unchanged_since = counts, now
        elif now - unchanged_since >= STALL_MINUTES * 60:
            print(
                f"Nothing has changed for {STALL_MINUTES} minutes. Is the backend running "
                "(python -m uvicorn app.main:app), and Ollama with the model pulled?",
                file=out,
            )
            return EXIT_ERROR
        if now - started >= max_minutes * 60:
            print(f"Stopped after {max_minutes:g} minutes. Run it again to carry on.", file=out)
            return EXIT_NOT_ENOUGH
        sleep(poll_seconds)


__all__ = [
    "DONE",
    "QUEUE_CHECKS",
    "QUEUE_FIXES",
    "WAIT",
    "Step",
    "auto_command",
    "next_step",
    "EXIT_ERROR",
    "EXIT_NOT_ENOUGH",
    "EXIT_OK",
    "collect_command",
    "describe",
    "train_command",
]
