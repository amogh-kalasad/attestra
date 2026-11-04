"""users_api_keys_tenancy

Revision ID: 0003_users
Revises: 0002_runner
Create Date: 2026-10-14 14:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_users"
down_revision: str | None = "0002_runner"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("tenants", schema=None) as batch_op:
        batch_op.add_column(sa.Column("data_region", sa.String(length=50), nullable=False, server_default="default"))
        batch_op.add_column(sa.Column("plan", sa.String(length=50), nullable=False, server_default="standard"))

    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=True),
        sa.Column("username", sa.String(length=100), nullable=False),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column("password_hash", sa.String(length=200), nullable=False),
        sa.Column("role", sa.String(length=30), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("username"),
    )
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("prefix", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("key_hash"),
    )
    op.create_table(
        "tenant_memberships",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(length=30), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "tenant_id"),
    )
    with op.batch_alter_table("reports", schema=None) as batch_op:
        batch_op.add_column(sa.Column("generated_by_user_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("approved_by_user_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key("fk_reports_generated_by_user", "users", ["generated_by_user_id"], ["id"])
        batch_op.create_foreign_key("fk_reports_approved_by_user", "users", ["approved_by_user_id"], ["id"])


def downgrade() -> None:
    with op.batch_alter_table("reports", schema=None) as batch_op:
        batch_op.drop_constraint("fk_reports_approved_by_user", type_="foreignkey")
        batch_op.drop_constraint("fk_reports_generated_by_user", type_="foreignkey")
        batch_op.drop_column("approved_by_user_id")
        batch_op.drop_column("generated_by_user_id")
    op.drop_table("tenant_memberships")
    op.drop_table("api_keys")
    op.drop_table("users")
    with op.batch_alter_table("tenants", schema=None) as batch_op:
        batch_op.drop_column("plan")
        batch_op.drop_column("data_region")
