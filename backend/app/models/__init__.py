"""ORM models.

Every model must be imported here so that ``Base.metadata`` knows about it;
Alembic autogenerate imports this package to discover tables.
"""

from app.models.user import User

__all__ = ["User"]
