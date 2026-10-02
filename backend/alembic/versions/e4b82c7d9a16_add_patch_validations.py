"""Add patch validations

Revision ID: e4b82c7d9a16
Revises: d3a71b9c6e25
Create Date: 2026-10-02 10:21:37.640125

Hand-reviewed after autogeneration, with the usual single change: the enum type
is created explicitly and dropped in the downgrade, because ``drop_table``
leaves a PostgreSQL type behind and the next ``upgrade`` then fails with "type
patch_validation_status already exists".

A new table rather than new values on ``patch_status``. A verdict needs its
evidence stored with it — every check and how it came out — and a patch can be
checked more than once. It also sidesteps ``ALTER TYPE … ADD VALUE``, which
cannot be undone by a downgrade without rebuilding the type.

No backfill. Proposals that already exist were never checked, and inventing a
verdict for them is the one thing this table exists to prevent. They show as
"not checked" until somebody asks.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "e4b82c7d9a16"
down_revision: str | Sequence[str] | None = "d3a71b9c6e25"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# PASSED and REJECTED are verdicts. FAILED is not one: it means the check could
# not be made, and it is a separate value so it is never counted as a verdict.
validation_status_enum = postgresql.ENUM(
    "QUEUED",
    "RUNNING",
    "PASSED",
    "REJECTED",
    "FAILED",
    name="patch_validation_status",
    create_type=False,
)


def upgrade() -> None:
    """Upgrade schema."""
    validation_status_enum.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "patch_validations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("patch_id", sa.Integer(), nullable=False),
        sa.Column("requested_by_id", sa.Integer(), nullable=True),
        sa.Column("status", validation_status_enum, server_default="QUEUED", nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("checks", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("findings_before", sa.Integer(), nullable=True),
        sa.Column("findings_after", sa.Integer(), nullable=True),
        sa.Column("also_resolved", sa.Integer(), server_default="0", nullable=False),
        sa.Column("new_findings", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
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
            ["patch_id"],
            ["patches.id"],
            name=op.f("fk_patch_validations_patch_id_patches"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_id"],
            ["users.id"],
            name=op.f("fk_patch_validations_requested_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_patch_validations")),
    )
    op.create_index(
        "ix_patch_validations_patch_created",
        "patch_validations",
        ["patch_id", "created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_patch_validations_patch_id"), "patch_validations", ["patch_id"], unique=False
    )
    op.create_index(
        "ix_patch_validations_status_created",
        "patch_validations",
        ["status", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_patch_validations_status_created", table_name="patch_validations")
    op.drop_index(op.f("ix_patch_validations_patch_id"), table_name="patch_validations")
    op.drop_index("ix_patch_validations_patch_created", table_name="patch_validations")
    op.drop_table("patch_validations")
    # Dropping the table does not drop the type.
    validation_status_enum.drop(op.get_bind(), checkfirst=True)
