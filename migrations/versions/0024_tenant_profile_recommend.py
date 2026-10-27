"""Tenant country, regulatory status, and technical scope for framework recommendations.

Revision ID: 0024_tenant_profile_recommend
Revises: 0023_subscription_credits
Create Date: 2026-10-27 18:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0024_tenant_profile_recommend"
down_revision: str | None = "0023_subscription_credits"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("tenants", sa.Column("country", sa.String(length=8), nullable=False, server_default=""))
    op.add_column("tenants", sa.Column("regulatory_status", sa.Text(), nullable=False, server_default=""))
    op.add_column("tenants", sa.Column("technical_scope", sa.JSON(), nullable=False, server_default="[]"))


def downgrade() -> None:
    op.drop_column("tenants", "technical_scope")
    op.drop_column("tenants", "regulatory_status")
    op.drop_column("tenants", "country")
