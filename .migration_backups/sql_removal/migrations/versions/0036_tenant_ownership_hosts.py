"""Organization-level ownership hosts (DNS / well-known file per hostname).

Revision ID: 0036_tenant_ownership_hosts
Revises: 0035_tenant_ownership_validity
Create Date: 2026-11-03 18:00:00.000000
"""
# @lat: [[authorization#Target ownership#Organization domain ownership]]
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from attestra.rls import POLICY_NAME, TENANT_OWNERSHIP_HOST_POLICIES

revision: str = "0036_tenant_ownership_hosts"
down_revision: str | None = "0035_tenant_ownership_validity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "tenant_ownership_hosts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("hostname", sa.String(length=253), nullable=False),
        sa.Column("ownership_token", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("ownership_verified_at", _TS, nullable=True),
        sa.Column("last_method", sa.String(length=32), nullable=False, server_default=""),
        sa.Column("created_at", _TS, nullable=False),
        sa.Column("updated_at", _TS, nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "hostname"),
    )
    if op.get_bind().dialect.name == "postgresql":
        for table, expr in TENANT_OWNERSHIP_HOST_POLICIES.items():
            op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
            op.execute(f"CREATE POLICY {POLICY_NAME} ON {table} USING {expr} WITH CHECK {expr}")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table in TENANT_OWNERSHIP_HOST_POLICIES:
            op.execute(f"DROP POLICY IF EXISTS {POLICY_NAME} ON {table}")
    op.drop_table("tenant_ownership_hosts")
