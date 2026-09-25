"""Ingestion limits and the errors raised when input violates them.

Every limit exists because of a specific attack or accident:

* ``MAX_ARCHIVE_BYTES`` — a huge upload filling the disk.
* ``MAX_UNCOMPRESSED_BYTES`` / ``MAX_COMPRESSION_RATIO`` — a zip bomb: a few
  kilobytes that expand to gigabytes.
* ``MAX_FILES`` — an archive with a million tiny files (inode exhaustion, and
  an analysis phase that never finishes).
* ``MAX_FILE_BYTES`` — one enormous file that no parser should ever be handed.
* ``CLONE_TIMEOUT_SECONDS`` — a git clone that hangs forever.

The values are settings, not constants, so a deployment can lower them.
"""

from http import HTTPStatus

from app.core.errors import AppError


class IngestionError(AppError):
    """Base for anything wrong with the submitted code. Always the user's
    fault, never a 500: the message is safe to show them."""

    def __init__(self, code: str, message: str, status_code: int = HTTPStatus.BAD_REQUEST) -> None:
        super().__init__(code, message, status_code=status_code)


class ArchiveTooLargeError(IngestionError):
    def __init__(self, limit_mb: float) -> None:
        super().__init__(
            "ARCHIVE_TOO_LARGE",
            f"The archive is larger than the {limit_mb:.0f} MB limit",
            status_code=HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
        )


class ArchiveInvalidError(IngestionError):
    def __init__(self, reason: str = "The file is not a valid zip archive") -> None:
        super().__init__("ARCHIVE_INVALID", reason)


class ArchiveUnsafeError(IngestionError):
    """A path or entry that tries to escape the extraction directory."""

    def __init__(self, reason: str) -> None:
        super().__init__("ARCHIVE_UNSAFE", reason)


class ArchiveTooManyFilesError(IngestionError):
    def __init__(self, limit: int) -> None:
        super().__init__("ARCHIVE_TOO_MANY_FILES", f"The archive contains more than {limit} files")


class ArchiveExpandsTooMuchError(IngestionError):
    def __init__(self) -> None:
        super().__init__(
            "ARCHIVE_EXPANDS_TOO_MUCH",
            "The archive expands to far more data than its compressed size (possible zip bomb)",
        )


class RepositoryUrlInvalidError(IngestionError):
    def __init__(self, reason: str) -> None:
        super().__init__("REPOSITORY_URL_INVALID", reason)


class CloneFailedError(IngestionError):
    def __init__(self, reason: str) -> None:
        super().__init__("CLONE_FAILED", reason, status_code=HTTPStatus.BAD_REQUEST)


class GitUnavailableError(IngestionError):
    def __init__(self) -> None:
        super().__init__(
            "GIT_UNAVAILABLE",
            "Git is not installed on the server, so Git URLs cannot be cloned. "
            "Upload a zip archive instead.",
            status_code=HTTPStatus.SERVICE_UNAVAILABLE,
        )


class EmptyRepositoryError(IngestionError):
    def __init__(self) -> None:
        super().__init__("REPOSITORY_EMPTY", "No source files were found in the uploaded code")
