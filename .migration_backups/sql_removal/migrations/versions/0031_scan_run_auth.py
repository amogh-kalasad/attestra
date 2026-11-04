"""Authenticated scanning: link a scan run to an auth credential profile + result.

Revision ID: 0031_scan_run_auth
Revises: 0030_crawl_settings
Create Date: 2026-10-29 00:00:00.000000
"""
# @lat: [[architecture#Schema migrations]]
# @lat: [[runner#Authenticated scan wiring]]
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0031_scan_run_auth"
down_revision: str | None = "0030_crawl_settings"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("scan_runs", schema=None) as b:
        b.add_column(sa.Column("auth_profile_id", sa.Integer(), nullable=True))
        b.add_column(sa.Column("authenticated", sa.Boolean(), nullable=False, server_default=sa.false()))
        b.add_column(sa.Column("auth_note", sa.String(length=500), nullable=False, server_default=""))
        b.create_index("ix_scan_runs_auth_profile_id", ["auth_profile_id"])


def downgrade() -> None:
    with op.batch_alter_table("scan_runs", schema=None) as b:
        b.drop_index("ix_scan_runs_auth_profile_id")
        b.drop_column("auth_note")
        b.drop_column("authenticated")
        b.drop_column("auth_profile_id")
