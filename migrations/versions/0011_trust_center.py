"""Trust center: per-tenant public page, published items, access requests

Revision ID: 0011_trust_center
Revises: 0010_iso_soa
Create Date: 2026-10-14 23:30:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011_trust_center"
down_revision: str | None = "0010_iso_soa"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

from attestra.rls import POLICY_NAME, TRUST_POLICIES  # noqa: E402


def upgrade() -> None:
    op.create_table(
        "trust_centers",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("slug", sa.String(length=80), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("updated_by", sa.String(length=200), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id"),
        sa.UniqueConstraint("slug"),
    )
    op.create_table(
        "trust_items",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=20), nullable=False),
        sa.Column("ref_id", sa.Integer(), nullable=True),
        sa.Column("ref_key", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("access", sa.String(length=10), nullable=False),
        sa.Column("path", sa.String(length=500), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("published", sa.Boolean(), nullable=False),
        sa.Column("published_by", sa.String(length=200), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "trust_access_requests",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("item_id", sa.Integer(), nullable=False),
        sa.Column("requester_name", sa.String(length=200), nullable=False),
        sa.Column("requester_email", sa.String(length=200), nullable=False),
        sa.Column("company", sa.String(length=200), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("nda_accepted", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(length=10), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("decided_by", sa.String(length=200), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["item_id"], ["trust_items.id"]),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    if op.get_bind().dialect.name == "postgresql":
        for table, expr in TRUST_POLICIES.items():
            op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
            op.execute(f"CREATE POLICY {POLICY_NAME} ON {table} USING {expr} WITH CHECK {expr}")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table in TRUST_POLICIES:
            op.execute(f"DROP POLICY IF EXISTS {POLICY_NAME} ON {table}")
    op.drop_table("trust_access_requests")
    op.drop_table("trust_items")
    op.drop_table("trust_centers")
