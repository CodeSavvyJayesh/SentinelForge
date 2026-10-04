"""``python -m app.cli`` — see :mod:`app.cli.main`."""

import sys

EXIT_ERROR = 2


def run() -> int:
    # Everything, the imports included, is inside the try. A crash must exit 2
    # ("the scan could not be run"), never 1: an uncaught exception exits 1 by
    # default, and 1 is how this tool says the *code* failed the gate.
    try:
        from app.cli.main import main

        return main()
    except Exception as exc:  # noqa: BLE001 - the last line of defence for the exit code
        print(f"error: the scan could not be run: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(run())
