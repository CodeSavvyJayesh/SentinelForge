"""Add findings table and repository analyzed_at

Revision ID: a7be837ea618
Revises: def97007d9c9
Create Date: 2026-09-25 08:17:53.817829

Hand-reviewed after autogeneration, and edited for the same reason as the
Phase 4 migration: ``drop_table`` does not drop a PostgreSQL enum type, so the
generated downgrade would leave ``finding_severity`` behind and the next
``upgrade`` would fail with "type already exists". Both enums are now created
with ``checkfirst`` and dropped in the downgrade, and the columns use
``create_type=False`` so ``create_table`` does not try to create them twice.

The migration test runs upgrade -> downgrade -> upgrade, which is what catches
this.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "a7be837ea618"
down_revision: str | Sequence[str] | None = "def97007d9c9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

severity_enum = postgresql.ENUM(
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", name="finding_severity", create_type=False
)
confidence_enum = postgresql.ENUM(
    "HIGH", "MEDIUM", "LOW", name="finding_confidence", create_type=False
)


def upgrade() -> None:
    """Upgrade schema."""
    bind = op.get_bind()
    severity_enum.create(bind, checkfirst=True)
    confidence_enum.create(bind, checkfirst=True)

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("repository_id", sa.Integer(), nullable=False),
        sa.Column("rule_id", sa.String(length=32), nullable=False),
        sa.Column("analyzer", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("severity", severity_enum, nullable=False),
        sa.Column("confidence", confidence_enum, nullable=False),
        sa.Column("cwe_id", sa.String(length=16), nullable=True),
        sa.Column("owasp_category", sa.String(length=80), nullable=True),
        sa.Column("file_path", sa.String(length=500), nullable=False),
        sa.Column("line_start", sa.Integer(), nullable=False),
        sa.Column("line_end", sa.Integer(), nullable=False),
        sa.Column("snippet", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
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
            ["repository_id"],
            ["repositories.id"],
            name=op.f("fk_findings_repository_id_repositories"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_findings")),
        sa.UniqueConstraint(
            "repository_id", "fingerprint", name="uq_findings_repository_fingerprint"
        ),
    )
    op.create_index(op.f("ix_findings_repository_id"), "findings", ["repository_id"], unique=False)
    op.create_index(
        "ix_findings_repository_severity", "findings", ["repository_id", "severity"], unique=False
    )
    op.add_column(
        "repositories", sa.Column("analyzed_at", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("repositories", "analyzed_at")
    op.drop_index("ix_findings_repository_severity", table_name="findings")
    op.drop_index(op.f("ix_findings_repository_id"), table_name="findings")
    op.drop_table("findings")

    bind = op.get_bind()
    confidence_enum.drop(bind, checkfirst=True)
    severity_enum.drop(bind, checkfirst=True)
