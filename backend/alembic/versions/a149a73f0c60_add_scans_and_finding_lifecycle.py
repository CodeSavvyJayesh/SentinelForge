"""Add scans and finding lifecycle

Revision ID: a149a73f0c60
Revises: a7be837ea618
Create Date: 2026-09-25 18:50:51.152217

Hand-reviewed after autogeneration. Three changes:

1. **Enum types are created explicitly and dropped in the downgrade.** Same
   lesson as Phases 4 and 5: ``drop_table``/``drop_column`` leave the type
   behind, and ``ADD COLUMN`` with an enum fails if the type does not exist
   yet. The migration test does upgrade → downgrade → upgrade, which is what
   catches it.

2. **Existing findings are backfilled, not orphaned.** Anyone who ran Phase 5
   already has findings with no scan attached. Deleting them would be the easy
   answer and the wrong one, so this migration mints one ``COMPLETED`` scan per
   already-analysed repository (dated from ``repositories.analyzed_at``) and
   points those findings at it, as ``OPEN``. Their history starts there rather
   than nowhere.

3. The backfilled scan records ``new_findings = total_findings``: that run is
   the first that saw them, so they were all new to it. ``files_scanned`` stays
   0 because we genuinely do not know it — inventing a number would be worse.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "a149a73f0c60"
down_revision: str | Sequence[str] | None = "a7be837ea618"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

scan_status_enum = postgresql.ENUM(
    "QUEUED", "RUNNING", "COMPLETED", "FAILED", name="scan_status", create_type=False
)
finding_status_enum = postgresql.ENUM(
    "NEW", "OPEN", "FIXED", name="finding_status", create_type=False
)


def upgrade() -> None:
    """Upgrade schema."""
    bind = op.get_bind()
    scan_status_enum.create(bind, checkfirst=True)
    finding_status_enum.create(bind, checkfirst=True)

    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("repository_id", sa.Integer(), nullable=False),
        sa.Column("triggered_by_id", sa.Integer(), nullable=True),
        sa.Column("status", scan_status_enum, server_default="QUEUED", nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("files_scanned", sa.Integer(), server_default="0", nullable=False),
        sa.Column("files_skipped", sa.Integer(), server_default="0", nullable=False),
        sa.Column("unparsable_files", sa.Integer(), server_default="0", nullable=False),
        sa.Column("total_findings", sa.Integer(), server_default="0", nullable=False),
        sa.Column("new_findings", sa.Integer(), server_default="0", nullable=False),
        sa.Column("fixed_findings", sa.Integer(), server_default="0", nullable=False),
        sa.Column("truncated", sa.Boolean(), server_default="false", nullable=False),
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
            ["repository_id"],
            ["repositories.id"],
            name=op.f("fk_scans_repository_id_repositories"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["triggered_by_id"],
            ["users.id"],
            name=op.f("fk_scans_triggered_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scans")),
    )
    op.create_index(
        "ix_scans_repository_created", "scans", ["repository_id", "created_at"], unique=False
    )
    op.create_index(op.f("ix_scans_repository_id"), "scans", ["repository_id"], unique=False)
    op.create_index("ix_scans_status_created", "scans", ["status", "created_at"], unique=False)

    op.add_column(
        "findings",
        sa.Column("status", finding_status_enum, server_default="NEW", nullable=False),
    )
    op.add_column("findings", sa.Column("first_seen_scan_id", sa.Integer(), nullable=True))
    op.add_column("findings", sa.Column("last_seen_scan_id", sa.Integer(), nullable=True))
    op.add_column("findings", sa.Column("fixed_in_scan_id", sa.Integer(), nullable=True))
    op.create_index(
        "ix_findings_repository_status", "findings", ["repository_id", "status"], unique=False
    )
    op.create_foreign_key(
        op.f("fk_findings_fixed_in_scan_id_scans"),
        "findings",
        "scans",
        ["fixed_in_scan_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        op.f("fk_findings_last_seen_scan_id_scans"),
        "findings",
        "scans",
        ["last_seen_scan_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        op.f("fk_findings_first_seen_scan_id_scans"),
        "findings",
        "scans",
        ["first_seen_scan_id"],
        ["id"],
        ondelete="SET NULL",
    )

    _backfill_scans_for_existing_findings()


def _backfill_scans_for_existing_findings() -> None:
    """Give findings from Phase 5 the scan they were never linked to."""
    op.execute(
        sa.text(
            """
            INSERT INTO scans (
                repository_id, status, attempts, started_at, finished_at,
                total_findings, new_findings, fixed_findings,
                created_at, updated_at
            )
            SELECT
                r.id,
                'COMPLETED'::scan_status,
                1,
                r.analyzed_at,
                r.analyzed_at,
                counted.total,
                counted.total,
                0,
                r.analyzed_at,
                r.analyzed_at
            FROM repositories r
            JOIN LATERAL (
                SELECT count(*) AS total FROM findings f WHERE f.repository_id = r.id
            ) counted ON TRUE
            WHERE r.analyzed_at IS NOT NULL
            """
        )
    )
    # At this point each repository has at most one scan, so the join is exact.
    op.execute(
        sa.text(
            """
            UPDATE findings f
            SET first_seen_scan_id = s.id,
                last_seen_scan_id = s.id,
                status = 'OPEN'::finding_status
            FROM scans s
            WHERE s.repository_id = f.repository_id
            """
        )
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint(op.f("fk_findings_first_seen_scan_id_scans"), "findings", type_="foreignkey")
    op.drop_constraint(op.f("fk_findings_last_seen_scan_id_scans"), "findings", type_="foreignkey")
    op.drop_constraint(op.f("fk_findings_fixed_in_scan_id_scans"), "findings", type_="foreignkey")
    op.drop_index("ix_findings_repository_status", table_name="findings")
    op.drop_column("findings", "fixed_in_scan_id")
    op.drop_column("findings", "last_seen_scan_id")
    op.drop_column("findings", "first_seen_scan_id")
    op.drop_column("findings", "status")

    op.drop_index("ix_scans_status_created", table_name="scans")
    op.drop_index(op.f("ix_scans_repository_id"), table_name="scans")
    op.drop_index("ix_scans_repository_created", table_name="scans")
    op.drop_table("scans")

    bind = op.get_bind()
    finding_status_enum.drop(bind, checkfirst=True)
    scan_status_enum.drop(bind, checkfirst=True)
