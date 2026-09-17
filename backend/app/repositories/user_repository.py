"""Database queries for users."""

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import User


class UserRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def get_by_id(self, user_id: int) -> User | None:
        return self.db.get(User, user_id)

    def get_by_email(self, email: str) -> User | None:
        statement = select(User).where(func.lower(User.email) == email.lower())
        return self.db.scalars(statement).first()

    def get_by_username(self, username: str) -> User | None:
        statement = select(User).where(func.lower(User.username) == username.lower())
        return self.db.scalars(statement).first()

    def get_by_identifier(self, identifier: str) -> User | None:
        """Look up by email or username: users may log in with either."""
        value = identifier.lower()
        statement = select(User).where(
            (func.lower(User.email) == value) | (func.lower(User.username) == value)
        )
        return self.db.scalars(statement).first()

    def add(self, user: User) -> User:
        self.db.add(user)
        self.db.flush()
        return user

    def list_users(self, *, limit: int = 50, offset: int = 0) -> list[User]:
        statement = select(User).order_by(User.id).limit(limit).offset(offset)
        return list(self.db.scalars(statement))

    def count(self) -> int:
        return self.db.scalar(select(func.count()).select_from(User)) or 0
