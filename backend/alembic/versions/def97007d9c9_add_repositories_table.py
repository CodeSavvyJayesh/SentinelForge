"""Add repositories table

Revision ID: def97007d9c9
Revises: 5e575e845395
Create Date: 2026-09-25 06:57:30.944045

Hand-reviewed after autogeneration. Two changes to what Alembic produced:

1. The two PostgreSQL enum types are created explicitly with ``checkfirst``
   and **dropped in the downgrade**. ``drop_table`` leaves a type behind, so
   the generated downgrade made ``upgrade -> downgrade -> upgrade`` fail with
   "type repository_source already exists". The migration test does exactly
   that round trip.
2. ``create_type=False`` on the columns, so ``create_table`` does not try to
   create the types a second time.

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "def97007d9c9"
down_revision: str | Sequence[str] | None = "5e575e845395"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

source_enum = postgresql.ENUM("UPLOAD", "GIT", name="repository_source", create_type=False)
status_enum = postgresql.ENUM(
    "PENDING", "INGESTING", "READY", "FAILED", name="repository_status", create_type=False
)


def upgrade() -> None:
    """Upgrade schema."""
    bind = op.get_bind()
    source_enum.create(bind, checkfirst=True)
    status_enum.create(bind, checkfirst=True)

    op.create_table(
        "repositories",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("source", source_enum, nullable=False),
        sa.Column("status", status_enum, server_default="PENDING", nullable=False),
        sa.Column("origin", sa.String(length=500), nullable=False),
        sa.Column("branch", sa.String(length=100), nullable=True),
        sa.Column("commit_hash", sa.String(length=64), nullable=True),
        sa.Column("workspace_path", sa.String(length=300), nullable=True),
        sa.Column("file_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("total_bytes", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("primary_language", sa.String(length=50), nullable=True),
        sa.Column("language_breakdown", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_repositories_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_repositories")),
    )
    op.create_index(
        op.f("ix_repositories_project_id"), "repositories", ["project_id"], unique=False
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f("ix_repositories_project_id"), table_name="repositories")
    op.drop_table("repositories")

    bind = op.get_bind()
    status_enum.drop(bind, checkfirst=True)
    source_enum.drop(bind, checkfirst=True)
