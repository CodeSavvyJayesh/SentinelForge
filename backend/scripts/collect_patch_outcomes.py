"""Ask the application for more fixes and checks, to have something to train on.

    python scripts/collect_patch_outcomes.py status
    python scripts/collect_patch_outcomes.py fixes --limit 25
    python scripts/collect_patch_outcomes.py checks --limit 100
    python scripts/collect_patch_outcomes.py fixes --limit 25 --again
    python scripts/collect_patch_outcomes.py auto

``auto`` does the rest by itself: it asks for fixes and checks a few at a time,
waits for the running backend to do them, and stops when there are enough
judged fixes to train on (or when nothing more qualifies, or nothing is moving).

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
from app.learning.commands import EXIT_ERROR, auto_command, collect_command  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("action", choices=("status", "fixes", "checks", "auto"))
    parser.add_argument("--limit", type=int, default=25, help="how many to ask for (default 25)")
    parser.add_argument(
        "--again",
        action="store_true",
        help="also ask again where the last fix was rejected or refused",
    )
    parser.add_argument("--batch", type=int, default=10, help="auto: requests at a time")
    parser.add_argument("--poll", type=float, default=20, help="auto: seconds between looks")
    parser.add_argument("--minutes", type=float, default=720, help="auto: give up after this long")
    arguments = parser.parse_args(argv)

    try:
        if arguments.action == "auto":
            return auto_command(
                SessionLocal,
                out=sys.stdout,
                batch=arguments.batch,
                poll_seconds=arguments.poll,
                max_minutes=arguments.minutes,
            )
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
