"""User account model."""

from enum import StrEnum

from sqlalchemy import Boolean, Enum, String, true
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.base import Base
from app.models.mixins import TimestampMixin


class UserRole(StrEnum):
    """Authorisation role. Kept deliberately small; extend when a phase needs it."""

    USER = "USER"
    ADMIN = "ADMIN"


class User(TimestampMixin, Base):
    """A SentinelForge user."""

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
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="user_role", native_enum=True, validate_strings=True),
        default=UserRole.USER,
        server_default=UserRole.USER.value,
        nullable=False,
    )

    refresh_sessions: Mapped[list["RefreshSession"]] = relationship(  # noqa: F821
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    projects: Mapped[list["Project"]] = relationship(  # noqa: F821
        back_populates="owner",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    @property
    def is_admin(self) -> bool:
        return self.role is UserRole.ADMIN

    def __repr__(self) -> str:  # never include hashed_password
        return f"User(id={self.id!r}, username={self.username!r}, role={self.role!r})"
