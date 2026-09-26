"""Add explanations

Revision ID: 4ce5951fa3ca
Revises: 9f6e26e043f7
Create Date: 2026-09-26 18:00:55.385651

Hand-reviewed after autogeneration. One change, and it is the fifth phase in a
row that needs it: **the enum type is created explicitly and dropped in the
downgrade.** ``drop_table`` removes the table and leaves the PostgreSQL enum
behind, so the generated downgrade produces a database where the next
``upgrade`` fails with "type explanation_status already exists". The migration
test runs upgrade -> downgrade -> upgrade, which is the only reason this keeps
being caught before a deployment finds it.

No backfill. An explanation is generated on request by a model that may not be
installed, so there is nothing to carry forward and nothing to invent. Existing
findings simply have none until somebody asks.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "4ce5951fa3ca"
down_revision: str | Sequence[str] | None = "9f6e26e043f7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

explanation_status_enum = postgresql.ENUM(
    "QUEUED", "RUNNING", "COMPLETED", "FAILED", name="explanation_status", create_type=False
)


def upgrade() -> None:
    """Upgrade schema."""
    explanation_status_enum.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "explanations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("finding_id", sa.Integer(), nullable=False),
        sa.Column("requested_by_id", sa.Integer(), nullable=True),
        sa.Column("status", explanation_status_enum, server_default="QUEUED", nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("model", sa.String(length=120), nullable=True),
        sa.Column("prompt_version", sa.Integer(), nullable=True),
        sa.Column("passage_chunk_ids", postgresql.ARRAY(sa.Integer()), nullable=True),
        sa.Column("prompt_tokens", sa.Integer(), nullable=True),
        sa.Column("completion_tokens", sa.Integer(), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("impact", sa.Text(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("citations", postgresql.ARRAY(sa.Integer()), nullable=True),
        sa.Column("dropped_citations", sa.Integer(), server_default="0", nullable=False),
        sa.Column("links_removed", sa.Integer(), server_default="0", nullable=False),
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
            name=op.f("fk_explanations_finding_id_findings"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_id"],
            ["users.id"],
            name=op.f("fk_explanations_requested_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_explanations")),
    )
    op.create_index(
        "ix_explanations_finding_created",
        "explanations",
        ["finding_id", "created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_explanations_finding_id"), "explanations", ["finding_id"], unique=False
    )
    op.create_index(
        "ix_explanations_status_created", "explanations", ["status", "created_at"], unique=False
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_explanations_status_created", table_name="explanations")
    op.drop_index(op.f("ix_explanations_finding_id"), table_name="explanations")
    op.drop_index("ix_explanations_finding_created", table_name="explanations")
    op.drop_table("explanations")
    # Dropping the table does not drop the type. Without this, the next
    # upgrade fails with "type explanation_status already exists".
    explanation_status_enum.drop(op.get_bind(), checkfirst=True)
