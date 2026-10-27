"""Canonical finding observations and dedup metadata (master Phase 6).

Revision ID: 0025_finding_observations
Revises: 0024_tenant_profile_recommend
Create Date: 2026-10-27 20:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0025_finding_observations"
down_revision: str | None = "0024_tenant_profile_recommend"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.add_column("findings", sa.Column("dedup_confidence", sa.Float(), nullable=True))
    op.add_column(
        "findings",
        sa.Column("dedup_rationale", sa.String(length=500), nullable=False, server_default=""),
    )
    op.create_table(
        "finding_observations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("finding_id", sa.Integer(), nullable=False),
        sa.Column("engagement_id", sa.Integer(), nullable=False),
        sa.Column("import_run_id", sa.Integer(), nullable=True),
        sa.Column("scan_run_id", sa.Integer(), nullable=True),
        sa.Column("tool", sa.String(length=50), nullable=False, server_default=""),
        sa.Column("tool_version", sa.String(length=100), nullable=False, server_default=""),
        sa.Column("original_id", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("title", sa.String(length=500), nullable=False, server_default=""),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("severity", sa.String(length=10), nullable=False, server_default=""),
        sa.Column("confidence", sa.String(length=50), nullable=False, server_default=""),
        sa.Column("location", sa.String(length=1000), nullable=False, server_default=""),
        sa.Column("param", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("package", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("package_version", sa.String(length=100), nullable=False, server_default=""),
        sa.Column("fixed_version", sa.String(length=100), nullable=False, server_default=""),
        sa.Column("cwe", sa.Integer(), nullable=True),
        sa.Column("cves", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("rule_ids", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("line_start", sa.Integer(), nullable=True),
        sa.Column("line_end", sa.Integer(), nullable=True),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("fingerprint", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("match_confidence", sa.Float(), nullable=True),
        sa.Column("match_rationale", sa.String(length=500), nullable=False, server_default=""),
        sa.Column("possible_duplicate_of", sa.Integer(), nullable=True),
        sa.Column("observed_at", _TS, nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"]),
        sa.ForeignKeyConstraint(["import_run_id"], ["import_runs.id"]),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_runs.id"]),
        sa.ForeignKeyConstraint(["possible_duplicate_of"], ["findings.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_finding_observations_finding_id", "finding_observations", ["finding_id"])
    op.create_index("ix_finding_observations_engagement_id", "finding_observations", ["engagement_id"])


def downgrade() -> None:
    op.drop_index("ix_finding_observations_engagement_id", table_name="finding_observations")
    op.drop_index("ix_finding_observations_finding_id", table_name="finding_observations")
    op.drop_table("finding_observations")
    op.drop_column("findings", "dedup_rationale")
    op.drop_column("findings", "dedup_confidence")
