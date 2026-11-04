"""Auth profiles: optional non-secret extra request headers (one 'Name: value' per line).

Revision ID: 0032_auth_profile_extra_headers
Revises: 0031_scan_run_auth
Create Date: 2026-10-29 18:00:00.000000
"""
# @lat: [[architecture#Schema migrations]]
# @lat: [[runner#Authenticated scan wiring]]
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0032_auth_profile_extra_headers"
down_revision: str | None = "0031_scan_run_auth"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("auth_credential_profiles", schema=None) as b:
        b.add_column(sa.Column("extra_headers", sa.Text(), nullable=False, server_default=""))


def downgrade() -> None:
    with op.batch_alter_table("auth_credential_profiles", schema=None) as b:
        b.drop_column("extra_headers")
