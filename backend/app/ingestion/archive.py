"""Safe zip extraction.

`zipfile.extractall` is not safe for untrusted input. This module extracts
entry by entry and refuses anything dangerous **before** writing it:

1. **Zip slip** — an entry named ``../../etc/passwd`` or ``/etc/passwd``
   escapes the destination. Every resolved path is checked against the target.
2. **Symlinks** — a zip can store a symlink; following it later writes outside
   the workspace. Symlink entries are refused outright.
3. **Zip bombs** — the uncompressed total and the compression ratio are checked
   against the declared sizes *and* enforced again while writing, because the
   header can lie.
4. **Volume** — file count and per-file size limits.
5. **Special files** — device nodes, fifos and anything that is not a regular
   file or directory are refused.

Nothing inside the archive is executed, and no file permission bits are
restored: everything lands as plain data.
"""

import os
import stat
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from app.core.config import Settings
from app.core.logging import get_logger
from app.ingestion.limits import (
    ArchiveExpandsTooMuchError,
    ArchiveInvalidError,
    ArchiveTooManyFilesError,
    ArchiveUnsafeError,
)

logger = get_logger("sentinelforge.ingestion.archive")

# Directories that are never source code worth analysing. Skipping them keeps
# the file budget for real code and avoids ingesting a vendored universe.
IGNORED_DIRECTORIES: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "venv",
        ".venv",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".idea",
        ".vscode",
        "dist",
        "build",
        "target",
        ".gradle",
        ".next",
        "coverage",
        "__MACOSX",
    }
)

READ_CHUNK = 64 * 1024


@dataclass
class ExtractionResult:
    file_count: int = 0
    total_bytes: int = 0
    skipped_paths: list[str] = field(default_factory=list)
    # The single top-level folder, when the archive wraps everything in one
    # (as GitHub's "Download ZIP" does). Analysis starts from there.
    root_prefix: str | None = None


def _is_ignored(parts: tuple[str, ...]) -> bool:
    return any(part in IGNORED_DIRECTORIES for part in parts)


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    # The upper 16 bits of external_attr hold the Unix mode for zips made on
    # Unix; S_ISLNK tells us the entry is a symlink rather than a file.
    mode = info.external_attr >> 16
    return bool(mode) and stat.S_ISLNK(mode)


def _is_regular_or_dir(info: zipfile.ZipInfo) -> bool:
    file_type = (info.external_attr >> 16) & 0o170000
    if not file_type:
        # No file-type information at all (Windows tools, and Python's own
        # ``writestr``). Nothing claims it is special, so treat it as a file —
        # its contents are still validated and its permissions are reset.
        return True
    return file_type in {stat.S_IFREG, stat.S_IFDIR}


def safe_member_path(destination: Path, name: str) -> Path:
    """Resolve an archive entry inside ``destination`` or refuse it."""
    if name.startswith("/") or name.startswith("\\"):
        raise ArchiveUnsafeError("The archive contains an absolute path")
    # Windows-style separators and drive letters can also escape.
    normalised = name.replace("\\", "/")
    if ":" in normalised.split("/")[0] and len(normalised.split("/")[0]) == 2:
        raise ArchiveUnsafeError("The archive contains a Windows drive path")
    if ".." in Path(normalised).parts:
        raise ArchiveUnsafeError("The archive contains a path that escapes the target folder")

    target = (destination / normalised).resolve()
    if destination != target and destination not in target.parents:
        raise ArchiveUnsafeError("The archive contains a path that escapes the target folder")
    return target


def detect_root_prefix(names: list[str]) -> str | None:
    """Return the single wrapping folder, if the archive has exactly one."""
    tops = {name.replace("\\", "/").split("/")[0] for name in names if name.strip()}
    tops.discard("")
    if len(tops) != 1:
        return None
    only = tops.pop()
    # A single *file* at the root is not a wrapper.
    return only if any(name.replace("\\", "/").startswith(f"{only}/") for name in names) else None


def extract_archive(archive_path: Path, destination: Path, settings: Settings) -> ExtractionResult:
    """Extract ``archive_path`` into ``destination``, refusing unsafe content."""
    result = ExtractionResult()
    try:
        with zipfile.ZipFile(archive_path) as archive:
            infos = archive.infolist()
            result.root_prefix = detect_root_prefix([info.filename for info in infos])

            declared_uncompressed = sum(info.file_size for info in infos)
            compressed = max(archive_path.stat().st_size, 1)
            if declared_uncompressed > settings.MAX_UNCOMPRESSED_BYTES:
                raise ArchiveExpandsTooMuchError
            if declared_uncompressed / compressed > settings.MAX_COMPRESSION_RATIO:
                raise ArchiveExpandsTooMuchError

            for info in infos:
                _extract_one(archive, info, destination, settings, result)
    except zipfile.BadZipFile as exc:
        raise ArchiveInvalidError from exc

    logger.info(
        "archive_extracted",
        extra={
            "file_count": result.file_count,
            "total_bytes": result.total_bytes,
            "skipped": len(result.skipped_paths),
        },
    )
    return result


def _extract_one(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    destination: Path,
    settings: Settings,
    result: ExtractionResult,
) -> None:
    name = info.filename
    if not name or name.endswith("/"):
        return  # directory entry: created on demand below

    if _is_symlink(info):
        raise ArchiveUnsafeError("The archive contains a symbolic link")
    if not _is_regular_or_dir(info):
        raise ArchiveUnsafeError("The archive contains a special file")

    target = safe_member_path(destination, name)
    relative_parts = Path(name.replace("\\", "/")).parts

    if _is_ignored(relative_parts):
        result.skipped_paths.append(name)
        return
    if info.file_size > settings.MAX_FILE_BYTES:
        result.skipped_paths.append(name)
        return
    if result.file_count >= settings.MAX_FILES:
        raise ArchiveTooManyFilesError(settings.MAX_FILES)

    target.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with archive.open(info) as source, open(target, "wb") as sink:
        while chunk := source.read(READ_CHUNK):
            written += len(chunk)
            # The header can lie about file_size; stop if the real stream
            # exceeds either the per-file limit or the total budget.
            if written > settings.MAX_FILE_BYTES:
                sink.close()
                target.unlink(missing_ok=True)
                result.skipped_paths.append(name)
                return
            if result.total_bytes + written > settings.MAX_UNCOMPRESSED_BYTES:
                sink.close()
                target.unlink(missing_ok=True)
                raise ArchiveExpandsTooMuchError
            sink.write(chunk)

    # Plain data: no execute bits, whatever the archive claimed.
    os.chmod(target, 0o644)
    result.file_count += 1
    result.total_bytes += written
