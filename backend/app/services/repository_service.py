"""Repository ingestion: take untrusted code and make it inspectable.

Two ways in — an uploaded zip or a public Git URL — and one way out: an
isolated workspace directory with a summary row in the database.

Three rules shape this service:

1. **Ownership first.** Every entry point resolves the project through
   ``ProjectService.get``, which 404s for a project that is missing *or*
   someone else's. Nothing is written before that check passes.
2. **A failure leaves a record, not a mess.** When ingestion fails, the
   workspace is deleted, the row is marked ``FAILED`` with a message safe to
   show the owner, and the transaction is committed so the failure and its
   audit entry survive the error response.
3. **Nothing is run.** No script, hook, build or installer from the archive or
   repository is executed — this service only reads bytes and counts them.
"""

import shutil
import tempfile
from datetime import UTC, datetime
from http import HTTPStatus
from pathlib import Path
from typing import BinaryIO

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.logging import get_logger
from app.ingestion import git_clone
from app.ingestion.archive import extract_archive
from app.ingestion.language import summarise_tree
from app.ingestion.limits import (
    ArchiveTooLargeError,
    EmptyRepositoryError,
    IngestionError,
)
from app.ingestion.workspace import WorkspaceManager
from app.models import AuditAction, Project, Repository, RepositorySource, RepositoryStatus, User
from app.repositories.audit_log_repository import AuditLogRepository
from app.repositories.repository_repository import RepositoryRepository
from app.schemas.repository import RepositoryConnectRequest
from app.services.auth_service import RequestContext
from app.services.project_service import ProjectService

logger = get_logger("sentinelforge.repositories")

UPLOAD_CHUNK = 1024 * 1024
FILENAME_MAX = 200


class RepositoryNotFoundError(IngestionError):
    """404 for "no such repository" *and* "not yours" — same reasoning as
    projects: a 403 would confirm the id exists."""

    def __init__(self) -> None:
        super().__init__(
            "REPOSITORY_NOT_FOUND", "Repository not found", status_code=HTTPStatus.NOT_FOUND
        )


class RepositoryLimitReachedError(IngestionError):
    def __init__(self, limit: int) -> None:
        super().__init__(
            "REPOSITORY_LIMIT_REACHED",
            f"This project already has the maximum of {limit} repositories",
            status_code=HTTPStatus.CONFLICT,
        )


def sanitise_filename(name: str | None) -> str:
    """Keep an uploaded filename readable without keeping it dangerous.

    The stored name is only ever displayed, never used as a path — but a value
    that is displayed still ends up in logs, reports and HTML, so path
    separators, control characters and unbounded length all go."""
    candidate = (name or "").strip().replace("\\", "/").split("/")[-1]
    cleaned = "".join(character for character in candidate if character.isprintable())
    cleaned = cleaned.replace("‮", "")  # right-to-left override hides extensions
    return cleaned[:FILENAME_MAX] or "upload.zip"


class RepositoryService:
    def __init__(self, db: Session, settings: Settings) -> None:
        self.db = db
        self.settings = settings
        self.repositories = RepositoryRepository(db)
        self.projects = ProjectService(db)
        self.audit = AuditLogRepository(db)
        self.workspaces = WorkspaceManager(settings)

    # -- reads -------------------------------------------------------------

    def get(self, repository_id: int, user: User) -> Repository:
        repository = self.repositories.get_for_owner(repository_id, user.id)
        if repository is None:
            raise RepositoryNotFoundError
        return repository

    def list_for_project(self, project_id: int, user: User) -> list[Repository]:
        project = self.projects.get(project_id, user)  # ownership check
        return self.repositories.list_for_project(project.id)

    # -- writes ------------------------------------------------------------

    def ingest_upload(
        self,
        *,
        project_id: int,
        filename: str | None,
        stream: BinaryIO,
        user: User,
        context: RequestContext,
    ) -> Repository:
        project = self.projects.get(project_id, user)
        self._assert_room_for_another(project)

        repository = self._start(
            project, source=RepositorySource.UPLOAD, origin=sanitise_filename(filename), branch=None
        )
        workspace, relative = self.workspaces.create(
            project_id=project.id, repository_id=repository.id
        )
        repository.workspace_path = relative
        self.db.flush()

        archive_path: Path | None = None
        try:
            archive_path = self._spool_upload(stream)
            extract_archive(archive_path, workspace, self.settings)
            _flatten_single_root(workspace)
            self._finish(repository, workspace, user, context)
        except IngestionError as exc:
            self._fail(repository, exc, user, context)
            raise
        finally:
            if archive_path is not None:
                archive_path.unlink(missing_ok=True)
        return repository

    def ingest_git(
        self,
        *,
        project_id: int,
        payload: RepositoryConnectRequest,
        user: User,
        context: RequestContext,
    ) -> Repository:
        project = self.projects.get(project_id, user)
        self._assert_room_for_another(project)

        # Validated before anything is created: a bad URL should not leave a
        # FAILED row and an empty directory behind.
        url = git_clone.validate_repository_url(payload.repository_url, self.settings)
        branch = git_clone.validate_branch(payload.branch) or project.default_branch or None

        repository = self._start(project, source=RepositorySource.GIT, origin=url, branch=branch)
        workspace, relative = self.workspaces.create(
            project_id=project.id, repository_id=repository.id
        )
        repository.workspace_path = relative
        self.db.flush()

        try:
            result = git_clone.clone_repository(
                url=url, branch=branch, destination=workspace, settings=self.settings
            )
            repository.commit_hash = result.commit_hash or None
            repository.branch = result.branch or branch
            self._finish(repository, workspace, user, context)
        except IngestionError as exc:
            self._fail(repository, exc, user, context)
            raise
        return repository

    def delete(self, repository_id: int, user: User, context: RequestContext) -> None:
        repository = self.get(repository_id, user)
        workspace_path = repository.workspace_path
        project_id = repository.project_id
        self.repositories.delete(repository)
        # The row goes first: if removing the files fails, the user is not left
        # with a repository they cannot delete. An orphaned directory is a
        # cleanup problem; an undeletable row is a bug they have to live with.
        self.workspaces.remove(workspace_path)
        self._record(
            AuditAction.REPOSITORY_DELETED,
            user,
            context,
            entity_id=str(repository_id),
            details={"project_id": project_id},
        )
        logger.info(
            "repository_deleted", extra={"repository_id": repository_id, "user_id": user.id}
        )

    # -- internals ---------------------------------------------------------

    def _assert_room_for_another(self, project: Project) -> None:
        limit = self.settings.MAX_REPOSITORIES_PER_PROJECT
        if self.repositories.count_for_project(project.id) >= limit:
            raise RepositoryLimitReachedError(limit)

    def _start(
        self, project: Project, *, source: RepositorySource, origin: str, branch: str | None
    ) -> Repository:
        return self.repositories.add(
            Repository(
                project_id=project.id,
                source=source,
                status=RepositoryStatus.INGESTING,
                origin=origin,
                branch=branch,
            )
        )

    def _spool_upload(self, stream: BinaryIO) -> Path:
        """Copy the upload to a temporary file, refusing it the moment it grows
        past the limit.

        The size is enforced here rather than trusting ``Content-Length``: a
        client controls that header, and a chunked upload has none at all.
        """
        handle = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)  # noqa: SIM115
        path = Path(handle.name)
        written = 0
        try:
            with handle:
                while chunk := stream.read(UPLOAD_CHUNK):
                    written += len(chunk)
                    if written > self.settings.MAX_ARCHIVE_BYTES:
                        raise ArchiveTooLargeError(self.settings.MAX_ARCHIVE_BYTES / (1024 * 1024))
                    handle.write(chunk)
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return path

    def _finish(
        self, repository: Repository, workspace: Path, user: User, context: RequestContext
    ) -> None:
        summary = summarise_tree(workspace)
        if summary.file_count == 0:
            raise EmptyRepositoryError

        repository.status = RepositoryStatus.READY
        repository.file_count = summary.file_count
        repository.total_bytes = summary.total_bytes
        repository.primary_language = summary.primary_language
        repository.language_breakdown = summary.breakdown
        repository.error_message = None
        repository.ingested_at = datetime.now(UTC)
        self.db.flush()

        self._record(
            AuditAction.REPOSITORY_CONNECTED,
            user,
            context,
            entity_id=str(repository.id),
            details={
                "project_id": repository.project_id,
                "source": str(repository.source),
                "file_count": summary.file_count,
                "primary_language": summary.primary_language,
            },
        )
        logger.info(
            "repository_ingested",
            extra={
                "repository_id": repository.id,
                "project_id": repository.project_id,
                "source": str(repository.source),
                "file_count": summary.file_count,
                "total_bytes": summary.total_bytes,
                "primary_language": summary.primary_language,
            },
        )

    def _fail(
        self,
        repository: Repository,
        error: IngestionError,
        user: User,
        context: RequestContext,
    ) -> None:
        """Record the failure durably, then let the error propagate."""
        self.workspaces.remove(repository.workspace_path)
        repository.status = RepositoryStatus.FAILED
        repository.workspace_path = None
        repository.error_message = error.message
        repository.file_count = 0
        repository.total_bytes = 0
        self._record(
            AuditAction.REPOSITORY_INGEST_FAILED,
            user,
            context,
            entity_id=str(repository.id),
            details={"project_id": repository.project_id, "reason": error.code},
        )
        # The endpoint never reaches its own commit() when this raises, so the
        # failed row and its audit entry are committed here or lost entirely.
        self.db.commit()
        logger.warning(
            "repository_ingest_failed",
            extra={
                "repository_id": repository.id,
                "project_id": repository.project_id,
                "reason": error.code,  # the code, never the attacker's input
            },
        )

    def _record(
        self,
        action: AuditAction,
        user: User,
        context: RequestContext,
        *,
        entity_id: str | None,
        details: dict[str, object] | None = None,
    ) -> None:
        self.audit.add(
            action=str(action),
            user_id=user.id,
            entity_type="repository",
            entity_id=entity_id,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            details=details,
        )


def _flatten_single_root(workspace: Path) -> None:
    """Unwrap ``project-main/`` when an archive nests everything one level deep.

    GitHub's "Download ZIP" produces ``repo-main/...``; without this, every
    analysed path in later phases carries a meaningless prefix.
    """
    entries = list(workspace.iterdir())
    if len(entries) != 1 or not entries[0].is_dir() or entries[0].is_symlink():
        return
    wrapper = entries[0]
    for child in list(wrapper.iterdir()):
        target = workspace / child.name
        if target.exists():  # a collision means this was not a simple wrapper
            return
        shutil.move(str(child), str(target))
    wrapper.rmdir()


__all__ = [
    "RepositoryLimitReachedError",
    "RepositoryNotFoundError",
    "RepositoryService",
    "sanitise_filename",
]
