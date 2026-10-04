"""Train the patch-outcome classifier on this installation's own fixes.

    python scripts/train_patch_classifier.py --status     # is there enough data?
    python scripts/train_patch_classifier.py              # train, write model and report

Reads every fix that was proposed and then checked, trains a logistic
regression to predict the verdict from what was known before the check, and
writes two files: the model (``models/patch_outcome.json``) and a report of how
well it predicts fixes it was not trained on, next to two baselines
(``docs/evaluation/results/classifier/report.md``).

With too few judged fixes it trains nothing, writes nothing, says how many more
are needed and exits 1. ``scripts/collect_patch_outcomes.py`` asks the
application for more.

It is a script rather than a test because it needs what a test must not depend
on: a database with real outcomes in it.
"""

import argparse
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.core.config import get_settings  # noqa: E402
from app.core.database import SessionLocal  # noqa: E402
from app.learning import crossval  # noqa: E402
from app.learning.commands import EXIT_ERROR, train_command  # noqa: E402
from app.learning.logistic import DEFAULT_L2  # noqa: E402

DEFAULT_MODEL = BACKEND_DIR / "models" / "patch_outcome.json"
DEFAULT_REPORT = BACKEND_DIR.parent / "docs" / "evaluation" / "results" / "classifier" / "report.md"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--status", action="store_true", help="only say how much data there is")
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL, metavar="FILE")
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT, metavar="FILE")
    parser.add_argument("--folds", type=int, default=crossval.DEFAULT_FOLDS)
    parser.add_argument("--repeats", type=int, default=crossval.DEFAULT_REPEATS)
    parser.add_argument("--seed", type=int, default=crossval.DEFAULT_SEED)
    parser.add_argument("--l2", type=float, default=DEFAULT_L2, help="strength of the penalty")
    arguments = parser.parse_args(argv)

    try:
        with SessionLocal() as db:
            return train_command(
                db,
                model_path=arguments.model,
                report_path=arguments.report,
                tool_version=get_settings().APP_VERSION,
                out=sys.stdout,
                status_only=arguments.status,
                folds=arguments.folds,
                repeats=arguments.repeats,
                seed=arguments.seed,
                l2=arguments.l2,
            )
    except Exception as error:  # noqa: BLE001 - a script's last line of defence
        print(f"error: {type(error).__name__}: {error}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
