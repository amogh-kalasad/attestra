"""Auth profiles: optional ENCRYPTED extra cookies (credential-store ref + cookie names only).

Revision ID: 0033_auth_profile_extra_cookies
Revises: 0032_auth_profile_extra_headers
Create Date: 2026-10-29 18:30:00.000000
"""
# @lat: [[architecture#Schema migrations]]
# @lat: [[runner#Authenticated scan wiring]]
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0033_auth_profile_extra_cookies"
down_revision: str | None = "0032_auth_profile_extra_headers"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("auth_credential_profiles", schema=None) as b:
        b.add_column(sa.Column("extra_cookies_ref", sa.String(length=300), nullable=False, server_default=""))
        b.add_column(sa.Column("extra_cookie_names", sa.String(length=1200), nullable=False, server_default=""))


def downgrade() -> None:
    with op.batch_alter_table("auth_credential_profiles", schema=None) as b:
        b.drop_column("extra_cookie_names")
        b.drop_column("extra_cookies_ref")
