"""A real (smart-protocol) Git HTTP server for tests.

``git clone --depth 1`` needs the smart protocol, which the plain static file
server does not speak ("dumb http transport does not support shallow
capabilities"). Rather than weaken the clone flags to suit the test, the test
runs git's own CGI, ``git-http-backend``, behind a small HTTP handler.

The result is a genuine clone over TCP: the command, the flags, the sanitised
environment and the shallow fetch are all exercised for real.
"""

import http.server
import os
import shutil
import subprocess  # noqa: S404 - test helper running git's own CGI
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

HTTP_BACKEND_CANDIDATES = (
    "/usr/lib/git-core/git-http-backend",
    "/usr/libexec/git-core/git-http-backend",
    "/usr/local/libexec/git-core/git-http-backend",
)


def _platform_variables() -> dict[str, str]:
    """Windows reaches sockets, DNS and its certificate store through libraries
    that read these; without them even a local clone fails."""
    if sys.platform != "win32":
        return {}
    names = ("SystemRoot", "SYSTEMROOT", "COMSPEC", "TEMP", "TMP", "USERPROFILE")
    return {name: os.environ[name] for name in names if os.environ.get(name)}


GIT_TEST_ENV = {
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "SentinelForge Test",
    "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "SentinelForge Test",
    "GIT_COMMITTER_EMAIL": "test@example.invalid",
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00+00:00",
    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00+00:00",
    "LC_ALL": "C",
    **_platform_variables(),
}


def find_http_backend() -> str | None:
    """Locate ``git-http-backend``.

    ``git --exec-path`` is the portable answer (it finds the Windows copy under
    ``Program Files\\Git\\mingw64\\libexec\\git-core`` too); the fixed
    paths are a fallback for an unusual installation.
    """
    git = shutil.which("git")
    if git:
        try:
            exec_path = subprocess.run(  # noqa: S603
                [git, "--exec-path"], capture_output=True, text=True, timeout=10, check=False
            ).stdout.strip()
        except (OSError, subprocess.SubprocessError):  # pragma: no cover
            exec_path = ""
        if exec_path:
            for name in ("git-http-backend", "git-http-backend.exe"):
                candidate = Path(exec_path) / name
                if candidate.exists():
                    return str(candidate)
    for candidate_path in HTTP_BACKEND_CANDIDATES:
        if Path(candidate_path).exists():
            return candidate_path
    return None


GIT = shutil.which("git") or "git"


def run_git(*arguments: str, cwd: Path) -> str:
    """Run git in a test repository with a clean environment."""
    completed = subprocess.run(  # noqa: S603
        [GIT, *arguments],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        env={**GIT_TEST_ENV, "HOME": str(cwd)},
    )
    return completed.stdout.strip()


def build_repository(path: Path, files: dict[str, str], branch: str = "main") -> str:
    """Create a repository with ``files`` committed on ``branch``; returns the SHA."""
    path.mkdir(parents=True, exist_ok=True)
    run_git("init", "--quiet", "--initial-branch", branch, ".", cwd=path)
    for name, content in files.items():
        target = path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    run_git("add", "--all", cwd=path)
    run_git("commit", "--quiet", "--message", "Initial commit", cwd=path)
    return run_git("rev-parse", "HEAD", cwd=path)


class _GitBackendHandler(http.server.BaseHTTPRequestHandler):
    """Forwards each request to ``git-http-backend`` as a CGI script."""

    project_root: str = ""
    backend: str = ""

    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return  # keep the test output readable

    def do_GET(self) -> None:  # noqa: N802
        self._serve(b"")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        self._serve(self.rfile.read(length))

    def _serve(self, body: bytes) -> None:
        path, _, query = self.path.partition("?")
        environment = {
            **GIT_TEST_ENV,
            "GIT_PROJECT_ROOT": self.project_root,
            "GIT_HTTP_EXPORT_ALL": "1",
            "REQUEST_METHOD": self.command,
            "PATH_INFO": path,
            "QUERY_STRING": query,
            "REMOTE_ADDR": self.client_address[0],
            "CONTENT_TYPE": self.headers.get("Content-Type", ""),
            "CONTENT_LENGTH": str(len(body)),
            "HTTP_GIT_PROTOCOL": self.headers.get("Git-Protocol", ""),
            "HOME": self.project_root,
        }
        completed = subprocess.run(  # noqa: S603
            [self.backend], input=body, capture_output=True, env=environment, check=False
        )
        raw_headers, _, payload = completed.stdout.partition(b"\r\n\r\n")
        status = 200
        headers: list[tuple[str, str]] = []
        for line in raw_headers.decode("latin-1").splitlines():
            name, _, value = line.partition(":")
            value = value.strip()
            if name.lower() == "status":
                status = int(value.split()[0])
            else:
                headers.append((name, value))

        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@contextmanager
def serve_repository(repository: Path) -> Iterator[str]:
    """Serve ``repository``'s parent directory; yields the clone URL."""
    backend = find_http_backend()
    if backend is None:  # pragma: no cover - depends on the git installation
        raise RuntimeError("git-http-backend not found")

    handler = type(
        "BoundGitHandler",
        (_GitBackendHandler,),
        {"project_root": str(repository.parent), "backend": backend},
    )
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/{repository.name}"
    finally:
        server.shutdown()
        server.server_close()
