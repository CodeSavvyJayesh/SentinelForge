"""Record what a refused patch actually returned, and at what temperature

Revision ID: c92e5a3d1f48
Revises: b81d4f2c9a07
Create Date: 2026-09-27 17:40:12.554031

Two nullable columns, added after the first real refusal in the running app
could only be *inferred* rather than read. The row kept the reason the
proposal was thrown away but not the proposal, so diagnosing it meant
reasoning about what the model probably did.

`rejected_code` is also the failure corpus the evaluation chapter needs, and
that is the sort of data nobody can collect after the fact.

`temperature` is recorded because it is what differs between two runs of the
same prompt: the first attempt runs at the configured default (0, for
reproducibility) and a retry runs warmer, since at 0 a retry returns the
identical failure.

Both nullable, so existing rows are untouched and no backfill is invented.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c92e5a3d1f48"
down_revision: str | Sequence[str] | None = "b81d4f2c9a07"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("patches", sa.Column("rejected_code", sa.Text(), nullable=True))
    op.add_column("patches", sa.Column("temperature", sa.Float(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("patches", "temperature")
    op.drop_column("patches", "rejected_code")
