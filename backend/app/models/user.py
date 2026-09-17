"""User account model."""

from sqlalchemy import Boolean, String, true
from sqlalchemy.orm import Mapped, mapped_column

from app.core.base import Base
from app.models.mixins import TimestampMixin


class User(TimestampMixin, Base):
    """A SentinelForge user. Roles and auth-related fields arrive in Phase 2."""

    __tablename__ = "users"

    # The primary key is already indexed by PostgreSQL; no extra index needed.
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    username: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        server_default=true(),
        nullable=False,
    )

    def __repr__(self) -> str:  # never include hashed_password
        return f"User(id={self.id!r}, username={self.username!r})"
