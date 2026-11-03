"""Per-tenant ownership verification validity window (days).

Revision ID: 0035_tenant_ownership_validity
Revises: 0034_automated_test_executions
Create Date: 2026-11-03 12:00:00.000000
"""
# @lat: [[authorization#Target ownership#Validity window]]
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0035_tenant_ownership_validity"
down_revision: str | None = "0034_automated_test_executions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column("ownership_validity_days", sa.Integer(), nullable=False, server_default="30"),
    )


def downgrade() -> None:
    op.drop_column("tenants", "ownership_validity_days")
