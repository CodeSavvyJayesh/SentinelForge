"""Database queries for projects.

Every read is scoped to an owner. There is deliberately no ``get(project_id)``
that ignores ownership: if such a method existed, one forgotten check in a
service or endpoint would leak another user's data. The safe query is the only
query available.
"""

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.models import Project


class ProjectRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def get_for_owner(self, project_id: int, owner_id: int) -> Project | None:
        statement = select(Project).where(
            Project.id == project_id,
            Project.owner_id == owner_id,
        )
        return self.db.scalars(statement).first()

    def get_by_name(self, name: str, owner_id: int) -> Project | None:
        statement = select(Project).where(
            Project.owner_id == owner_id,
            func.lower(Project.name) == name.lower(),
        )
        return self.db.scalars(statement).first()

    def list_for_owner(
        self, owner_id: int, *, search: str | None = None, limit: int = 20, offset: int = 0
    ) -> list[Project]:
        statement = (
            self._owned(owner_id, search)
            .order_by(Project.created_at.desc(), Project.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(self.db.scalars(statement))

    def count_for_owner(self, owner_id: int, *, search: str | None = None) -> int:
        statement = select(func.count()).select_from(self._owned(owner_id, search).subquery())
        return self.db.scalar(statement) or 0

    def add(self, project: Project) -> Project:
        self.db.add(project)
        self.db.flush()
        return project

    def delete(self, project: Project) -> None:
        self.db.delete(project)
        self.db.flush()

    def _owned(self, owner_id: int, search: str | None) -> Select[tuple[Project]]:
        statement = select(Project).where(Project.owner_id == owner_id)
        if search:
            # Escape LIKE wildcards: someone searching for "100%" must not get
            # a match-everything pattern.
            escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            statement = statement.where(Project.name.ilike(f"%{escaped}%", escape="\\"))
        return statement
