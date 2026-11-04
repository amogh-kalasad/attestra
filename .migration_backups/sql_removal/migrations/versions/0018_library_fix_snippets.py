"""Add importance, effort, fix steps and server config snippets to library entries.

Revision ID: 0018_library_fix_snippets
Revises: 0017_cert_expiry_alerts
Create Date: 2026-10-16 22:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0018_library_fix_snippets"
down_revision: str | None = "0017_cert_expiry_alerts"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COLS = (
    ("importance", sa.String(length=10)),
    ("effort", sa.String(length=10)),
    ("fix_steps", sa.Text()),
    ("snippet_nginx", sa.Text()),
    ("snippet_apache", sa.Text()),
    ("snippet_iis", sa.Text()),
    ("snippet_cloudflare", sa.Text()),
)


def upgrade() -> None:
    with op.batch_alter_table("library_entries", schema=None) as b:
        for name, col_type in _COLS:
            b.add_column(sa.Column(name, col_type, nullable=False, server_default=""))


def downgrade() -> None:
    with op.batch_alter_table("library_entries", schema=None) as b:
        for name, _ in _COLS:
            b.drop_column(name)
