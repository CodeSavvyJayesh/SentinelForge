"""Project business logic, with ownership as the first rule.

The access model is simple and absolute for this phase: a project belongs to
one user, and only that user can see or change it. Administrators get no
special path here — an admin view over all projects belongs with the dashboard
in a later phase, where it can be designed deliberately rather than inherited
by accident.
"""

from dataclasses import dataclass
from http import HTTPStatus

from sqlalchemy.orm import Session

from app.core.errors import AppError, ErrorCode
from app.core.logging import get_logger
from app.models import AuditAction, Project, User
from app.repositories.audit_log_repository import AuditLogRepository
from app.repositories.project_repository import ProjectRepository
from app.schemas.project import ProjectCreate, ProjectUpdate
from app.services.auth_service import RequestContext

logger = get_logger("sentinelforge.projects")

MAX_PROJECTS_PER_USER = 100


class ProjectNotFoundError(AppError):
    """404 for both "no such project" and "not yours".

    Returning 403 for someone else's project would confirm that the id exists,
    which lets an attacker map the database by walking ids. 404 reveals nothing.
    """

    def __init__(self) -> None:
        super().__init__("PROJECT_NOT_FOUND", "Project not found", status_code=HTTPStatus.NOT_FOUND)


class ProjectNameTakenError(AppError):
    def __init__(self) -> None:
        super().__init__(
            "PROJECT_NAME_TAKEN",
            "You already have a project with this name",
            status_code=HTTPStatus.CONFLICT,
        )


class ProjectLimitReachedError(AppError):
    def __init__(self, limit: int) -> None:
        super().__init__(
            "PROJECT_LIMIT_REACHED",
            f"You have reached the limit of {limit} projects",
            status_code=HTTPStatus.CONFLICT,
        )


@dataclass(frozen=True)
class ProjectPage:
    items: list[Project]
    total: int
    limit: int
    offset: int


class ProjectService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.projects = ProjectRepository(db)
        self.audit = AuditLogRepository(db)

    # -- reads -------------------------------------------------------------

    def get(self, project_id: int, user: User) -> Project:
        project = self.projects.get_for_owner(project_id, user.id)
        if project is None:
            raise ProjectNotFoundError
        return project

    def list(
        self, user: User, *, search: str | None = None, limit: int = 20, offset: int = 0
    ) -> ProjectPage:
        return ProjectPage(
            items=self.projects.list_for_owner(user.id, search=search, limit=limit, offset=offset),
            total=self.projects.count_for_owner(user.id, search=search),
            limit=limit,
            offset=offset,
        )

    # -- writes ------------------------------------------------------------

    def create(self, data: ProjectCreate, user: User, context: RequestContext) -> Project:
        if self.projects.get_by_name(data.name, user.id) is not None:
            raise ProjectNameTakenError
        if self.projects.count_for_owner(user.id) >= MAX_PROJECTS_PER_USER:
            raise ProjectLimitReachedError(MAX_PROJECTS_PER_USER)

        project = self.projects.add(
            Project(
                owner_id=user.id,  # from the token, never from the request body
                name=data.name,
                description=data.description,
                repository_url=data.repository_url,
                default_branch=data.default_branch,
            )
        )
        self._record(AuditAction.PROJECT_CREATED, project, user, context)
        logger.info("project_created", extra={"project_id": project.id, "user_id": user.id})
        return project

    def update(
        self, project_id: int, data: ProjectUpdate, user: User, context: RequestContext
    ) -> Project:
        project = self.get(project_id, user)  # ownership enforced here
        changes = data.model_dump(exclude_unset=True)

        new_name = changes.get("name")
        if new_name and new_name.lower() != project.name.lower():
            existing = self.projects.get_by_name(new_name, user.id)
            if existing is not None and existing.id != project.id:
                raise ProjectNameTakenError

        for field, value in changes.items():
            setattr(project, field, value)
        self.db.flush()

        self._record(
            AuditAction.PROJECT_UPDATED,
            project,
            user,
            context,
            details={"fields": sorted(changes)},  # field names only, never values
        )
        logger.info(
            "project_updated",
            extra={"project_id": project.id, "user_id": user.id, "fields": sorted(changes)},
        )
        return project

    def delete(self, project_id: int, user: User, context: RequestContext) -> None:
        project = self.get(project_id, user)
        name = project.name
        self.projects.delete(project)
        self._record(
            AuditAction.PROJECT_DELETED,
            None,
            user,
            context,
            entity_id=str(project_id),
            details={"name": name},
        )
        logger.info("project_deleted", extra={"project_id": project_id, "user_id": user.id})

    # -- internals ---------------------------------------------------------

    def _record(
        self,
        action: AuditAction,
        project: Project | None,
        user: User,
        context: RequestContext,
        *,
        entity_id: str | None = None,
        details: dict[str, object] | None = None,
    ) -> None:
        self.audit.add(
            action=str(action),
            user_id=user.id,
            entity_type="project",
            entity_id=entity_id or (str(project.id) if project else None),
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=context.request_id,
            details=details,
        )


def raise_if_not_owner(project: Project, user: User) -> None:
    """Guard for later phases that already hold a project instance."""
    if project.owner_id != user.id:
        raise ProjectNotFoundError


__all__ = [
    "MAX_PROJECTS_PER_USER",
    "ErrorCode",
    "ProjectLimitReachedError",
    "ProjectNameTakenError",
    "ProjectNotFoundError",
    "ProjectPage",
    "ProjectService",
    "raise_if_not_owner",
]
