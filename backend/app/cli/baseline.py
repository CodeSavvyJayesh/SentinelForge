"""Reading the fingerprints out of an earlier run's SARIF.

A baseline is a file somebody hands to the build, so it is read as untrusted
input: bounded in size, parsed as data, and every level of its structure is
checked before it is indexed. A baseline that cannot be read is an **error**,
never an empty baseline — treating it as empty would make every existing
finding "new" and fail the build for the wrong reason, and treating it as
"everything is known" would wave every finding through.
"""

import json
from pathlib import Path

from app.reports.sarif import FINGERPRINT_KEY

MAX_BASELINE_BYTES = 50 * 1024 * 1024


class BaselineError(ValueError):
    """The baseline file exists but cannot be used."""


def load(path: Path) -> frozenset[str]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise BaselineError(f"The baseline file cannot be read: {path}") from exc
    if size > MAX_BASELINE_BYTES:
        raise BaselineError("The baseline file is larger than 50 MB.")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise BaselineError("The baseline file is not valid JSON.") from exc

    runs = document.get("runs") if isinstance(document, dict) else None
    if not isinstance(runs, list):
        raise BaselineError("The baseline file is not a SARIF log: it has no runs.")

    fingerprints: set[str] = set()
    for run in runs:
        results = run.get("results") if isinstance(run, dict) else None
        if not isinstance(results, list):
            continue
        for result in results:
            partial = result.get("partialFingerprints") if isinstance(result, dict) else None
            value = partial.get(FINGERPRINT_KEY) if isinstance(partial, dict) else None
            if isinstance(value, str) and value:
                fingerprints.add(value)
    return frozenset(fingerprints)


__all__ = ["MAX_BASELINE_BYTES", "BaselineError", "load"]
