"""Database queries for ingested repositories.

The same rule as projects: no query ignores ownership. A repository belongs to
a project, and a project belongs to a user, so every lookup joins through
``projects.owner_id``. There is no ``get(repository_id)``.
"""

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.models import Project, Repository


class RepositoryRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def get_for_owner(self, repository_id: int, owner_id: int) -> Repository | None:
        statement = (
            select(Repository)
            .join(Project, Repository.project_id == Project.id)
            .where(Repository.id == repository_id, Project.owner_id == owner_id)
        )
        return self.db.scalars(statement).first()

    def get(self, repository_id: int) -> Repository | None:
        """Unscoped lookup — for the background worker only.

        The worker has no user: it acts on a scan row the API already
        authorised when it was queued. Every path that serves a request still
        goes through ``get_for_owner``.
        """
        return self.db.get(Repository, repository_id)

    def list_for_project(self, project_id: int) -> list[Repository]:
        statement = (
            select(Repository)
            .where(Repository.project_id == project_id)
            .order_by(Repository.created_at.desc(), Repository.id.desc())
        )
        return list(self.db.scalars(statement))

    def count_for_project(self, project_id: int) -> int:
        return (
            self.db.scalar(
                select(func.count()).select_from(self._for_project(project_id).subquery())
            )
            or 0
        )

    def add(self, repository: Repository) -> Repository:
        self.db.add(repository)
        self.db.flush()
        return repository

    def delete(self, repository: Repository) -> None:
        self.db.delete(repository)
        self.db.flush()

    def _for_project(self, project_id: int) -> Select[tuple[Repository]]:
        return select(Repository).where(Repository.project_id == project_id)
