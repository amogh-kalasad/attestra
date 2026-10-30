"""Elite automated security-testing execution rows.

Revision ID: 0034_automated_test_executions
Revises: 0033_auth_profile_extra_cookies
Create Date: 2026-10-30 12:00:00.000000
"""
# @lat: [[architecture#Elite automated security testing]]
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0034_automated_test_executions"
down_revision: str | None = "0033_auth_profile_extra_cookies"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "automated_test_executions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("engagement_id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("asset_id", sa.Integer(), nullable=True),
        sa.Column("target_base_url", sa.String(length=500), nullable=False, server_default=""),
        sa.Column("profile", sa.String(length=50), nullable=False, server_default="baseline"),
        sa.Column("test_case_ids", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="QUEUED"),
        sa.Column("requested_by", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("allow_private", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("result_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("error", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", _TS, nullable=False),
        sa.Column("started_at", _TS, nullable=True),
        sa.Column("ended_at", _TS, nullable=True),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_automated_test_executions_engagement_id",
        "automated_test_executions",
        ["engagement_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_automated_test_executions_engagement_id", table_name="automated_test_executions")
    op.drop_table("automated_test_executions")
