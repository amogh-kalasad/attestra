"""Cross-tool merge links on findings (related row -> primary row).

Revision ID: 0029_cross_tool_merge
Revises: 0028_certification_authority
Create Date: 2026-10-28 17:30:00.000000
"""
# @lat: [[architecture#Schema migrations]]
# @lat: [[findings#Deduplication#Cross-tool merge]]
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0029_cross_tool_merge"
down_revision: str | None = "0028_certification_authority"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("findings", schema=None) as b:
        b.add_column(sa.Column("merged_into_id", sa.Integer(), nullable=True))
        b.add_column(sa.Column("merge_rationale", sa.String(length=500), nullable=False, server_default=""))
        b.create_index("ix_findings_merged_into_id", ["merged_into_id"])


def downgrade() -> None:
    with op.batch_alter_table("findings", schema=None) as b:
        b.drop_index("ix_findings_merged_into_id")
        b.drop_column("merge_rationale")
        b.drop_column("merged_into_id")
