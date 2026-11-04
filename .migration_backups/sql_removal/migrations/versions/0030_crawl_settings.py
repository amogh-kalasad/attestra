"""Per-target crawl settings: extra start URLs and crawl minutes (ZAP / nuclei).

Revision ID: 0030_crawl_settings
Revises: 0029_cross_tool_merge
Create Date: 2026-10-29 11:30:00.000000
"""
# @lat: [[architecture#Schema migrations]]
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0030_crawl_settings"
down_revision: str | None = "0029_cross_tool_merge"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("assets", schema=None) as b:
        b.add_column(sa.Column("crawl_seed_urls", sa.Text(), nullable=False, server_default=""))
        b.add_column(sa.Column("crawl_spider_minutes", sa.Integer(), nullable=True))
        b.add_column(sa.Column("crawl_ajax_minutes", sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("assets", schema=None) as b:
        b.drop_column("crawl_ajax_minutes")
        b.drop_column("crawl_spider_minutes")
        b.drop_column("crawl_seed_urls")
