"""Record whether a proposal had to be re-indented

Revision ID: d3a71b9c6e25
Revises: c92e5a3d1f48
Create Date: 2026-09-27 18:05:44.902117

The third of the "how much tidying did the model's output need" counters,
after `fences_stripped` and `gutters_stripped`, and added for the same reason:
it is a measurement of the model rather than of the code, and nobody can
collect it after the fact.

This one arrived from the first Java proposal the running application
produced. The model returned the corrected line flush against the margin,
having dropped eight spaces of indentation. Cosmetic in Java; in Python the
patched file would not parse and the proposal would have been refused.

Not nullable, because every row has an answer — rows written before this
migration simply did not need re-indenting, which is what the default says.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d3a71b9c6e25"
down_revision: str | Sequence[str] | None = "c92e5a3d1f48"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "patches",
        sa.Column("reindented", sa.Boolean(), server_default="false", nullable=False),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("patches", "reindented")
