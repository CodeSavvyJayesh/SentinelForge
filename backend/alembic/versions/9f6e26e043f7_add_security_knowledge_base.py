"""Add the security knowledge base

Revision ID: 9f6e26e043f7
Revises: a149a73f0c60
Create Date: 2026-09-25 19:56:33.494074

Hand-reviewed after autogeneration. One change, and it is the same change as in
Phases 4, 5 and 6: **the enum type is created explicitly and dropped in the
downgrade.** ``drop_table`` removes the table and leaves the PostgreSQL enum
type behind, so the generated downgrade produced a database where the next
``upgrade`` fails with "type knowledge_source already exists". The migration
test runs upgrade → downgrade → upgrade, which is the only reason this keeps
being caught rather than discovered by whoever deploys next.

There is deliberately **no backfill** here, unlike Phase 6. The knowledge base
is built from files on disk by ``scripts/build_knowledge.py``; there is no
earlier version of this data to preserve, and inventing rows to make the tables
look populated would mean shipping a knowledge base nobody indexed.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "9f6e26e043f7"
down_revision: str | Sequence[str] | None = "a149a73f0c60"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

knowledge_source_enum = postgresql.ENUM(
    "CWE", "OWASP", "SENTINELFORGE", name="knowledge_source", create_type=False
)


def upgrade() -> None:
    """Upgrade schema."""
    bind = op.get_bind()
    knowledge_source_enum.create(bind, checkfirst=True)

    op.create_table(
        "knowledge_documents",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("source", knowledge_source_enum, nullable=False),
        sa.Column("external_id", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("url", sa.String(length=500), nullable=True),
        sa.Column("source_version", sa.String(length=64), nullable=True),
        sa.Column("cwe_id", sa.String(length=32), nullable=True),
        sa.Column("owasp_category", sa.String(length=16), nullable=True),
        sa.Column("rule_id", sa.String(length=32), nullable=True),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
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
        sa.PrimaryKeyConstraint("id", name=op.f("pk_knowledge_documents")),
        sa.UniqueConstraint("source", "external_id", name="uq_knowledge_documents_source_external"),
    )
    op.create_index("ix_knowledge_documents_cwe", "knowledge_documents", ["cwe_id"], unique=False)

    op.create_table(
        "knowledge_chunks",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("document_id", sa.Integer(), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("section", sa.String(length=120), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("cwe_id", sa.String(length=32), nullable=True),
        sa.Column("owasp_category", sa.String(length=16), nullable=True),
        sa.Column("rule_id", sa.String(length=32), nullable=True),
        sa.Column("embedding", sa.LargeBinary(), nullable=True),
        sa.Column("embedding_model", sa.String(length=120), nullable=True),
        sa.Column("embedding_dimensions", sa.Integer(), nullable=True),
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
            ["document_id"],
            ["knowledge_documents.id"],
            name=op.f("fk_knowledge_chunks_document_id_knowledge_documents"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_knowledge_chunks")),
        sa.UniqueConstraint("document_id", "ordinal", name="uq_knowledge_chunks_document_ordinal"),
    )
    op.create_index("ix_knowledge_chunks_cwe", "knowledge_chunks", ["cwe_id"], unique=False)
    op.create_index(
        op.f("ix_knowledge_chunks_document_id"), "knowledge_chunks", ["document_id"], unique=False
    )
    op.create_index(
        "ix_knowledge_chunks_owasp", "knowledge_chunks", ["owasp_category"], unique=False
    )
    op.create_index("ix_knowledge_chunks_rule", "knowledge_chunks", ["rule_id"], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_knowledge_chunks_rule", table_name="knowledge_chunks")
    op.drop_index("ix_knowledge_chunks_owasp", table_name="knowledge_chunks")
    op.drop_index(op.f("ix_knowledge_chunks_document_id"), table_name="knowledge_chunks")
    op.drop_index("ix_knowledge_chunks_cwe", table_name="knowledge_chunks")
    op.drop_table("knowledge_chunks")
    op.drop_index("ix_knowledge_documents_cwe", table_name="knowledge_documents")
    op.drop_table("knowledge_documents")
    # Dropping the tables does not drop the type. Without this, the next
    # upgrade fails with "type knowledge_source already exists".
    knowledge_source_enum.drop(op.get_bind(), checkfirst=True)
