"""Remove proposed changes that quote credentials

Revision ID: f5c93d8eab27
Revises: e4b82c7d9a16
Create Date: 2026-10-02 11:48:19.207733

A data migration, and a deliberate deletion.

A finding for a hard-coded credential is stored with the secret redacted — that
has been true since Phase 5. A proposed change for one is not: the diff quotes
the line it replaces, so `patches.diff` (and `patches.rejected_code`) held the
credential in plain text. The application no longer proposes changes for
credential findings; this removes the rows written before it stopped.

They are deleted rather than scrubbed. A patch with its diff blanked is a row
that says a proposal exists and shows nothing, and none of these were fixes in
the first place — a leaked credential is rotated, not edited. Their validations
go with them through the foreign key's ON DELETE CASCADE.

The downgrade does nothing, because there is nothing it could honestly do: the
rows are gone, and restoring secrets to a database is not a rollback anyone
should want.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f5c93d8eab27"
down_revision: str | Sequence[str] | None = "e4b82c7d9a16"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Kept as a literal here rather than imported from the application: a migration
# must mean the same thing in a year, whatever the code says by then.
CREDENTIAL_CWE = "CWE-798"


def upgrade() -> None:
    """Upgrade schema."""
    # A bound parameter even though the value is a constant in this file: this
    # project's own analyser flags SQL assembled by string formatting, and it
    # should not need an exemption from itself.
    op.get_bind().execute(
        sa.text(
            "DELETE FROM patches USING findings "
            "WHERE patches.finding_id = findings.id AND findings.cwe_id = :cwe"
        ),
        {"cwe": CREDENTIAL_CWE},
    )


def downgrade() -> None:
    """Downgrade schema. Deleted rows are not restored — see the module docstring."""
