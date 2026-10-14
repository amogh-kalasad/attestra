"""tenant risk weights and suppression rules (Phase 7.4)

Revision ID: 0008_tuning
Revises: 0007_postgres_rls
Create Date: 2026-10-14 22:30:00.000000

Adds per-tenant scoring overrides and expiring suppression rules. On Postgres
both tables get the same tenant_isolation policy as the other tenant tables.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008_tuning"
down_revision: str | None = "0007_postgres_rls"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

from attestra.rls import POLICY_NAME, TUNING_POLICIES  # noqa: E402


def upgrade() -> None:
    op.create_table(
        "tenant_risk_weights",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("criticality_weights", sa.JSON(), nullable=False),
        sa.Column("internet_weight", sa.Float(), nullable=False),
        sa.Column("cde_weight", sa.Float(), nullable=False),
        sa.Column("updated_by", sa.String(length=200), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id"),
    )
    op.create_table(
        "suppression_rules",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("engagement_id", sa.Integer(), nullable=True),
        sa.Column("tool", sa.String(length=50), nullable=False),
        sa.Column("rule_id", sa.String(length=300), nullable=False),
        sa.Column("location_contains", sa.String(length=500), nullable=False),
        sa.Column("title_contains", sa.String(length=300), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(length=200), nullable=False),
        sa.Column("hits", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    if op.get_bind().dialect.name == "postgresql":
        for table, expr in TUNING_POLICIES.items():
            op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
            op.execute(f"CREATE POLICY {POLICY_NAME} ON {table} USING {expr} WITH CHECK {expr}")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table in TUNING_POLICIES:
            op.execute(f"DROP POLICY IF EXISTS {POLICY_NAME} ON {table}")
    op.drop_table("suppression_rules")
    op.drop_table("tenant_risk_weights")
