"""Add the risk snapshot to scans

Revision ID: a6c5ed2d3245
Revises: 4ce5951fa3ca
Create Date: 2026-09-26 19:56:01.738831

Three nullable columns, and no enum this time — the first migration in five
phases that autogenerate got right, because nothing here creates a type.

**Deliberately no backfill.** Existing scans have no risk score and are left
that way. The obvious alternative is to compute one now from today's findings,
and it would be wrong: a scan row records what a run concluded *at the time it
ran*, and a number calculated months later from a different set of findings
would be a fabrication wearing a historical timestamp. The chart simply starts
where the scoring does.

``risk_policy_version`` travels with every score so that a trend line cannot
silently mix two scoring policies. Two scores from different policies are not
two points on the same line, and a chart that draws them as if they were is
worse than one that refuses.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a6c5ed2d3245"
down_revision: str | Sequence[str] | None = "4ce5951fa3ca"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("scans", sa.Column("risk_score", sa.Float(), nullable=True))
    op.add_column("scans", sa.Column("risk_grade", sa.String(length=1), nullable=True))
    op.add_column("scans", sa.Column("risk_policy_version", sa.Integer(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("scans", "risk_policy_version")
    op.drop_column("scans", "risk_grade")
    op.drop_column("scans", "risk_score")
