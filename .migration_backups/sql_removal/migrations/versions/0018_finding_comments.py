"""Finding comment threads with soft delete.

Revision ID: 0018_finding_comments
Revises: 0017_cert_expiry_alerts
Create Date: 2026-10-16 22:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0018_finding_comments"
down_revision: str | None = "0018_library_fix_snippets"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

from attestra.rls import COMMENT_POLICIES, POLICY_NAME  # noqa: E402

_TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "finding_comments",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("finding_id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("author_user_id", sa.Integer(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", _TS, nullable=False),
        sa.Column("edited_at", _TS, nullable=True),
        sa.Column("deleted", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"]),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["author_user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table, expr in COMMENT_POLICIES.items():
            op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            op.execute(
                f"CREATE POLICY {POLICY_NAME} ON {table} "
                f"FOR ALL USING ({expr}) WITH CHECK ({expr})"
            )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(f"DROP POLICY IF EXISTS {POLICY_NAME} ON finding_comments")
    op.drop_table("finding_comments")
