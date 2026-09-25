"""Cloning a Git URL, defensively.

Cloning is the riskiest thing SentinelForge does with user input in this phase,
so the rules are strict:

* **Scheme allow-list.** Only ``https://`` (and ``http://`` if a deployment
  enables it). ``file://``, ``git://``, ``ssh://`` and especially ``ext::`` are
  refused — ``ext::`` lets a URL name a command for git to run.
* **No SSRF.** The host is resolved and every address it maps to must be
  public. This blocks ``localhost``, ``127.0.0.1``, ``10.x``, ``192.168.x`` and
  the cloud metadata address ``169.254.169.254``.
* **No argument injection.** A URL or branch starting with ``-`` would be read
  by git as an option (``--upload-pack=...`` runs a command). Both are
  validated, and ``--`` separates options from operands.
* **No credentials.** URLs carrying ``user:password@`` are refused rather than
  stored.
* **Nothing from the repository runs.** Hooks are disabled, submodules are not
  fetched, the system and global git configs are ignored, and the terminal
  prompt is turned off so a private repository fails instead of hanging.
* **Bounded.** ``--depth 1`` (one commit), one branch, no tags, and a timeout.
"""

import ipaddress
import os
import re
import shutil
import socket
import subprocess  # noqa: S404 - git is invoked with a fixed argument list, never a shell
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from app.core.config import Settings
from app.core.logging import get_logger
from app.ingestion.limits import (
    CloneFailedError,
    GitUnavailableError,
    RepositoryUrlInvalidError,
)

logger = get_logger("sentinelforge.ingestion.git")

ALLOWED_SCHEMES: frozenset[str] = frozenset({"https", "http"})
BRANCH_PATTERN = re.compile(r"^[A-Za-z0-9._/-]{1,100}$")
MAX_URL_LENGTH = 500


@dataclass(frozen=True)
class CloneResult:
    commit_hash: str
    branch: str


def git_executable() -> str | None:
    """The absolute path to git, or ``None`` if it is not installed.

    Resolved rather than spelled as ``"git"`` so the command never depends on
    whatever PATH the process happens to have inherited.
    """
    return shutil.which("git")


def git_is_available() -> bool:
    return git_executable() is not None


def validate_repository_url(raw_url: str, settings: Settings) -> str:
    """Return a safe, normalised clone URL or raise ``RepositoryUrlInvalidError``."""
    url = raw_url.strip()
    if not url or len(url) > MAX_URL_LENGTH:
        raise RepositoryUrlInvalidError("The repository URL is missing or too long")
    if url.startswith("-"):
        raise RepositoryUrlInvalidError("The repository URL may not start with '-'")

    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise RepositoryUrlInvalidError(
            "Only https:// URLs can be cloned. "
            "For a private or SSH repository, upload a zip archive instead."
        )
    if scheme == "http" and not settings.ALLOW_INSECURE_GIT_URLS:
        raise RepositoryUrlInvalidError("Only https:// URLs are allowed")
    if parsed.username or parsed.password:
        raise RepositoryUrlInvalidError(
            "Remove the username and password from the URL; credentials are not stored"
        )
    if not parsed.hostname:
        raise RepositoryUrlInvalidError("The repository URL has no host")

    _assert_public_host(parsed.hostname, settings)
    return url


def _assert_public_host(hostname: str, settings: Settings) -> None:
    """Refuse hosts that resolve to an address inside the server's own network."""
    if settings.ALLOW_PRIVATE_GIT_HOSTS:
        return  # opt-in, for an internal deployment with its own Git server
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise RepositoryUrlInvalidError("The repository host could not be resolved") from exc

    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local  # includes 169.254.169.254 (cloud metadata)
            or address.is_reserved
            or address.is_multicast
            or address.is_unspecified
        ):
            raise RepositoryUrlInvalidError(
                "That host is on a private or local network and cannot be cloned"
            )


def validate_branch(branch: str | None) -> str | None:
    if branch is None:
        return None
    candidate = branch.strip()
    if not candidate:
        return None
    if candidate.startswith("-") or not BRANCH_PATTERN.match(candidate):
        raise RepositoryUrlInvalidError("That branch name contains characters git does not allow")
    return candidate


def _git_environment() -> dict[str, str]:
    """A minimal environment: no user config, no prompts, no credential helpers."""
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "GIT_TERMINAL_PROMPT": "0",  # fail instead of asking for a password
        "GIT_ASKPASS": "",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "HOME": "/nonexistent",
        "GIT_ALLOW_PROTOCOL": "https:http",
        "LC_ALL": "C",
    }


def clone_repository(
    *, url: str, branch: str | None, destination: Path, settings: Settings
) -> CloneResult:
    """Shallow-clone ``url`` into ``destination`` (which must already exist)."""
    executable = git_executable()
    if executable is None:
        raise GitUnavailableError

    command = [
        executable,
        # Config flags come before the subcommand so they apply to the clone.
        "-c",
        "protocol.ext.allow=never",  # ext:: can execute a command
        "-c",
        "protocol.file.allow=never",
        "-c",
        "core.hooksPath=/dev/null",  # never run a hook from the repository
        "-c",
        "core.symlinks=false",  # write symlinks as plain files
        "-c",
        "credential.helper=",
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--no-tags",
        "--no-recurse-submodules",
        "--quiet",
    ]
    if branch:
        command += ["--branch", branch]
    command += ["--", url, str(destination)]

    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, shell=False, sanitised env
            command,
            capture_output=True,
            text=True,
            timeout=settings.CLONE_TIMEOUT_SECONDS,
            env=_git_environment(),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CloneFailedError(
            f"The repository took longer than {settings.CLONE_TIMEOUT_SECONDS} seconds to clone"
        ) from exc

    if completed.returncode != 0:
        raise CloneFailedError(_clone_failure_reason(completed.stderr, branch))

    return CloneResult(
        commit_hash=_git_output(["rev-parse", "HEAD"], destination, settings) or "",
        branch=branch
        or _git_output(["rev-parse", "--abbrev-ref", "HEAD"], destination, settings)
        or "",
    )


def _clone_failure_reason(stderr: str, branch: str | None) -> str:
    """Translate git's output into something safe and useful.

    Raw stderr can contain internal paths, so only recognised cases are passed
    through as specific messages.
    """
    lowered = stderr.lower()
    if "could not find remote branch" in lowered or "remote branch" in lowered:
        return f"Branch '{branch}' does not exist in that repository"
    if "authentication failed" in lowered or "could not read username" in lowered:
        return "That repository is private or requires credentials; upload a zip instead"
    if "not found" in lowered or "repository not found" in lowered:
        return "That repository does not exist or is not public"
    if "could not resolve host" in lowered:
        return "The repository host could not be reached"
    return "The repository could not be cloned"


def _git_output(arguments: list[str], repository: Path, settings: Settings) -> str | None:
    executable = git_executable()
    if executable is None:  # pragma: no cover - git vanished mid-request
        return None
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, shell=False
            [executable, "-C", str(repository), *arguments],
            capture_output=True,
            text=True,
            timeout=settings.GIT_COMMAND_TIMEOUT_SECONDS,
            env=_git_environment(),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None
    return completed.stdout.strip() if completed.returncode == 0 else None
