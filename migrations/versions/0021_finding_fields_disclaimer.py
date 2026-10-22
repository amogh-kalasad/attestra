"""Finding impact/affected_urls/references and tenant report disclaimer.

Revision ID: 0021_finding_fields_disclaimer
Revises: 0020_email_alerts
Create Date: 2026-10-22 12:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0021_finding_fields_disclaimer"
down_revision: str | None = "0020_email_alerts"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("findings", schema=None) as b:
        b.add_column(sa.Column("impact", sa.Text(), nullable=False, server_default=""))
        b.add_column(sa.Column("affected_urls", sa.JSON(), nullable=False, server_default="[]"))
        b.add_column(sa.Column("references", sa.JSON(), nullable=False, server_default="[]"))
    with op.batch_alter_table("report_templates", schema=None) as b:
        b.add_column(sa.Column("disclaimer", sa.Text(), nullable=False, server_default=""))


def downgrade() -> None:
    with op.batch_alter_table("report_templates", schema=None) as b:
        b.drop_column("disclaimer")
    with op.batch_alter_table("findings", schema=None) as b:
        b.drop_column("references")
        b.drop_column("affected_urls")
        b.drop_column("impact")
