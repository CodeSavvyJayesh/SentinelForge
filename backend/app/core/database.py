"""Database engine and session factory.

``config.py`` says *where* the database is; this module says *how* the
application connects to it (connection pool + session factory).
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings

engine = create_engine(
    settings.DATABASE_URL,
    # Validate pooled connections before use so a restarted PostgreSQL
    # does not surface as random errors on the first request.
    pool_pre_ping=True,
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
    pool_timeout=settings.DB_POOL_TIMEOUT_SECONDS,
    connect_args={"connect_timeout": settings.DB_CONNECT_TIMEOUT_SECONDS},
    echo=settings.DB_ECHO,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
)
