"""User model persistence."""

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import User

pytestmark = pytest.mark.integration


def make_user(**overrides: str) -> User:
    values = {
        "email": "dev@example.com",
        "username": "dev",
        "hashed_password": "not-a-real-hash",
        **overrides,
    }
    return User(**values)


def test_database_fills_timezone_aware_timestamps_and_defaults(db_session: Session) -> None:
    user = make_user()
    db_session.add(user)
    db_session.flush()
    db_session.refresh(user)

    assert user.id is not None
    assert user.is_active is True
    assert user.created_at.tzinfo is not None
    assert user.updated_at.tzinfo is not None


def test_email_must_be_unique(db_session: Session) -> None:
    db_session.add(make_user())
    db_session.flush()
    db_session.add(make_user(username="someone-else"))
    with pytest.raises(IntegrityError):
        db_session.flush()


def test_repr_does_not_expose_password_hash() -> None:
    assert "not-a-real-hash" not in repr(make_user())
