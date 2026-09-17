"""Reusable FastAPI dependencies."""

from collections.abc import Generator
from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.core.database import SessionLocal


def get_db() -> Generator[Session, None, None]:
    """Provide one database session per request and always close it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Use as a type annotation in endpoints: ``def endpoint(db: DbSession): ...``
DbSession = Annotated[Session, Depends(get_db)]
