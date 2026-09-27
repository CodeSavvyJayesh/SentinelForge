"""Add patches

Revision ID: b81d4f2c9a07
Revises: a6c5ed2d3245
Create Date: 2026-09-27 09:12:03.118402

Hand-reviewed after autogeneration, with the same single change as the five
migrations before it: **the enum type is created explicitly and dropped in the
downgrade.** ``drop_table`` leaves the PostgreSQL type behind, so a generated
downgrade produces a database where the next ``upgrade`` fails with "type
patch_status already exists". The migration test runs upgrade → downgrade →
upgrade, which is the only reason this keeps being caught before a deployment
finds it.

No backfill, and no column on `findings` marking one as patched. A proposal
does not change the finding it addresses — that is Phase 11's decision to
record, after re-scanning — so there is nothing here to carry forward.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "b81d4f2c9a07"
down_revision: str | Sequence[str] | None = "a6c5ed2d3245"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# PROPOSED, and no APPLIED. The vocabulary is the promise: nothing in this
# phase can record that a change was made to anybody's code.
patch_status_enum = postgresql.ENUM(
    "QUEUED", "RUNNING", "PROPOSED", "FAILED", name="patch_status", create_type=False
)


def upgrade() -> None:
    """Upgrade schema."""
    patch_status_enum.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "patches",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("finding_id", sa.Integer(), nullable=False),
        sa.Column("requested_by_id", sa.Integer(), nullable=True),
        sa.Column("explanation_id", sa.Integer(), nullable=True),
        sa.Column("status", patch_status_enum, server_default="QUEUED", nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("model", sa.String(length=120), nullable=True),
        sa.Column("prompt_version", sa.Integer(), nullable=True),
        sa.Column("passage_chunk_ids", postgresql.ARRAY(sa.Integer()), nullable=True),
        sa.Column("prompt_tokens", sa.Integer(), nullable=True),
        sa.Column("completion_tokens", sa.Integer(), nullable=True),
        sa.Column("diff", sa.Text(), nullable=True),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("file_path", sa.String(length=1024), nullable=True),
        sa.Column("first_line", sa.Integer(), nullable=True),
        sa.Column("last_line", sa.Integer(), nullable=True),
        sa.Column("lines_added", sa.Integer(), server_default="0", nullable=False),
        sa.Column("lines_removed", sa.Integer(), server_default="0", nullable=False),
        sa.Column("fences_stripped", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("gutters_stripped", sa.Integer(), server_default="0", nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
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
            ["finding_id"],
            ["findings.id"],
            name=op.f("fk_patches_finding_id_findings"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_id"],
            ["users.id"],
            name=op.f("fk_patches_requested_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["explanation_id"],
            ["explanations.id"],
            name=op.f("fk_patches_explanation_id_explanations"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_patches")),
    )
    op.create_index(
        "ix_patches_finding_created", "patches", ["finding_id", "created_at"], unique=False
    )
    op.create_index(op.f("ix_patches_finding_id"), "patches", ["finding_id"], unique=False)
    op.create_index("ix_patches_status_created", "patches", ["status", "created_at"], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_patches_status_created", table_name="patches")
    op.drop_index(op.f("ix_patches_finding_id"), table_name="patches")
    op.drop_index("ix_patches_finding_created", table_name="patches")
    op.drop_table("patches")
    # Dropping the table does not drop the type. Without this, the next
    # upgrade fails with "type patch_status already exists".
    patch_status_enum.drop(op.get_bind(), checkfirst=True)
