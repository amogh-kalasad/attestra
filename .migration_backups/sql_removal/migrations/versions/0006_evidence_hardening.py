"""evidence masking retention audit triggers

Revision ID: 0006_evidence
Revises: 0005_reports
Create Date: 2026-10-14 17:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_evidence"
down_revision: str | None = "0005_reports"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("evidence", schema=None) as batch_op:
        batch_op.add_column(sa.Column("masking_applied", sa.JSON(), nullable=False, server_default="{}"))
    with op.batch_alter_table("reports", schema=None) as batch_op:
        batch_op.add_column(sa.Column("legal_hold", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_table(
        "retention_policies",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("framework", sa.String(length=30), nullable=False),
        sa.Column("days", sa.Integer(), nullable=False),
        sa.Column("legal_hold", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "framework"),
    )
    # SQLite append-only triggers for audit_events
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        op.execute(
            """
            CREATE TRIGGER IF NOT EXISTS audit_events_no_update
            BEFORE UPDATE ON audit_events
            BEGIN
                SELECT RAISE(ABORT, 'audit_events is append-only');
            END;
            """
        )
        op.execute(
            """
            CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
            BEFORE DELETE ON audit_events
            BEGIN
                SELECT RAISE(ABORT, 'audit_events is append-only');
            END;
            """
        )
    elif bind.dialect.name == "postgresql":
        # Application role should not UPDATE/DELETE; document via COMMENT.
        op.execute("COMMENT ON TABLE audit_events IS 'append-only: revoke UPDATE/DELETE from app role'")


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS audit_events_no_update")
        op.execute("DROP TRIGGER IF EXISTS audit_events_no_delete")
    op.drop_table("retention_policies")
    with op.batch_alter_table("reports", schema=None) as batch_op:
        batch_op.drop_column("legal_hold")
    with op.batch_alter_table("evidence", schema=None) as batch_op:
        batch_op.drop_column("masking_applied")
