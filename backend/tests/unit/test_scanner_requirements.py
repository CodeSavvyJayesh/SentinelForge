"""The scanner's own requirements file, against what the scanner really imports.

The VS Code extension installs ``requirements-scanner.txt`` — not the whole
backend's requirements — into an environment of its own. If the scanner came to
need a package that is not listed there, the extension would install, and then
fail on the first scan on every machine but the one it was developed on.
"""

import re
import subprocess
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2]
PIN = re.compile(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?==(\S+)", re.MULTILINE)

# What the server needs and the scanner must not: if one of these is imported
# by a scan or a fix, requirements-scanner.txt is incomplete.
SERVER_ONLY = ("uvicorn", "alembic", "psycopg", "jwt")


def pins(name: str) -> dict[str, str]:
    return {key.lower(): value for key, value in PIN.findall((BACKEND / name).read_text("utf-8"))}


def test_every_scanner_pin_is_the_backends_own() -> None:
    scanner = pins("requirements-scanner.txt")
    backend = pins("requirements.txt")

    assert scanner
    for name, version in scanner.items():
        assert backend.get(name) == version, name


def test_a_scan_and_a_fix_import_nothing_the_scanner_does_not_install(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import hashlib\n\n\ndef digest(value):\n    return hashlib.md5(value).hexdigest()\n",
        encoding="utf-8",
    )
    probe = f"""
import sys
from app.cli.main import main
main(["scan", {str(tmp_path)!r}, "--quiet", "--fail-on", "none"])
main(["fix", {str(tmp_path)!r}, "--at", "app.py:5"])
print(",".join(sorted({{name.split(".")[0] for name in sys.modules}})))
"""
    completed = subprocess.run(  # noqa: S603 - our own interpreter, our own code
        [sys.executable, "-c", probe],
        cwd=BACKEND,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    imported = set(completed.stdout.strip().splitlines()[-1].split(","))
    assert not imported & set(SERVER_ONLY), imported & set(SERVER_ONLY)
