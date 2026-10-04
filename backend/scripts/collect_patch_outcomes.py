"""Ask the application for more fixes and checks, to have something to train on.

    python scripts/collect_patch_outcomes.py status
    python scripts/collect_patch_outcomes.py fixes --limit 25
    python scripts/collect_patch_outcomes.py checks --limit 100
    python scripts/collect_patch_outcomes.py fixes --limit 25 --again

``fixes`` queues "suggest a fix" for open findings that have no fix with a
verdict (credentials are skipped: the fix for a leaked secret is to rotate it).
``checks`` queues "validate" for every proposal nobody has checked. ``--again``
also asks again where the last attempt was rejected or refused.

Nothing is generated or judged here. The rows are picked up by the workers of
the running backend, so start it first — with Ollama running, for fixes — and
use ``status`` to watch the counts move. A fix takes the language model the
time it takes; ask for a modest ``--limit`` and repeat.
"""

import argparse
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.core.database import SessionLocal  # noqa: E402
from app.learning.commands import EXIT_ERROR, collect_command  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("action", choices=("status", "fixes", "checks"))
    parser.add_argument("--limit", type=int, default=25, help="how many to ask for (default 25)")
    parser.add_argument(
        "--again",
        action="store_true",
        help="also ask again where the last fix was rejected or refused",
    )
    arguments = parser.parse_args(argv)

    try:
        with SessionLocal() as db:
            return collect_command(
                db,
                action=arguments.action,
                limit=arguments.limit,
                again=arguments.again,
                out=sys.stdout,
            )
    except Exception as error:  # noqa: BLE001 - a script's last line of defence
        print(f"error: {type(error).__name__}: {error}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
