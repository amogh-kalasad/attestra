"""Organization test-run credit accounts, ledger, and renewal requests.

Revision ID: 0023_subscription_credits
Revises: 0022_auth_web
Create Date: 2026-10-27 12:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from attestra.rls import POLICY_NAME, SUBSCRIPTION_CREDIT_POLICIES

revision: str = "0023_subscription_credits"
down_revision: str | None = "0022_auth_web"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "tenant_credit_accounts",
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("balance", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("grant_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_at", _TS, nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("tenant_id"),
    )
    op.create_table(
        "credit_renewal_requests",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("requested_by", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("requested_by_user_id", sa.Integer(), nullable=True),
        sa.Column("credits_requested", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="pending"),
        sa.Column("note", sa.Text(), nullable=False, server_default=""),
        sa.Column("admin_note", sa.Text(), nullable=False, server_default=""),
        sa.Column("resolved_by", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("resolved_at", _TS, nullable=True),
        sa.Column("created_at", _TS, nullable=False),
        sa.Column("idempotency_key", sa.String(length=200), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["requested_by_user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotency_key"),
    )
    op.create_table(
        "credit_transactions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("amount", sa.Integer(), nullable=False),
        sa.Column("balance_after", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("reason", sa.String(length=40), nullable=False, server_default=""),
        sa.Column("actor", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("engagement_id", sa.Integer(), nullable=True),
        sa.Column("scan_run_id", sa.Integer(), nullable=True),
        sa.Column("renewal_request_id", sa.Integer(), nullable=True),
        sa.Column("idempotency_key", sa.String(length=200), nullable=True),
        sa.Column("note", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", _TS, nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_runs.id"]),
        sa.ForeignKeyConstraint(["renewal_request_id"], ["credit_renewal_requests.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotency_key"),
    )
    if op.get_bind().dialect.name == "postgresql":
        for table, expr in SUBSCRIPTION_CREDIT_POLICIES.items():
            op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
            op.execute(f"CREATE POLICY {POLICY_NAME} ON {table} USING {expr} WITH CHECK {expr}")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table in SUBSCRIPTION_CREDIT_POLICIES:
            op.execute(f"DROP POLICY IF EXISTS {POLICY_NAME} ON {table}")
    op.drop_table("credit_transactions")
    op.drop_table("credit_renewal_requests")
    op.drop_table("tenant_credit_accounts")
