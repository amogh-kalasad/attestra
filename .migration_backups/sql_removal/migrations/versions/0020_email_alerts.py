"""Per-tenant email alert settings and once-per-finding send log.

Revision ID: 0020_email_alerts
Revises: 0019_share_links, 0018_library_fix_snippets
Create Date: 2026-10-16 22:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from attestra.rls import EMAIL_ALERT_POLICIES, POLICY_NAME

revision: str = "0020_email_alerts"
down_revision: str | tuple[str, ...] | None = ("0019_share_links", "0018_library_fix_snippets")
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "email_alert_settings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("notify_new_high", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("notify_header_change", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("notify_sla_missed", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("recipients", sa.JSON(), nullable=False),
        sa.Column("updated_by", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("updated_at", _TS, nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id"),
    )
    op.create_table(
        "email_alert_sent",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=50), nullable=False),
        sa.Column("entity_type", sa.String(length=50), nullable=False),
        sa.Column("entity_id", sa.Integer(), nullable=False),
        sa.Column("sent_at", _TS, nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_type", "entity_type", "entity_id"),
    )
    if op.get_bind().dialect.name == "postgresql":
        for table, expr in EMAIL_ALERT_POLICIES.items():
            op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
            op.execute(f"CREATE POLICY {POLICY_NAME} ON {table} USING {expr} WITH CHECK {expr}")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table in EMAIL_ALERT_POLICIES:
            op.execute(f"DROP POLICY IF EXISTS {POLICY_NAME} ON {table}")
    op.drop_table("email_alert_sent")
    op.drop_table("email_alert_settings")
