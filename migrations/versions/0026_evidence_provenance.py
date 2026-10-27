"""Evidence provenance, annotated derivatives, and capture-failure fields (master Phase 7).

Revision ID: 0026_evidence_provenance
Revises: 0025_finding_observations
Create Date: 2026-10-27 22:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0026_evidence_provenance"
down_revision: str | None = "0025_finding_observations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("evidence", sa.Column("content_type", sa.String(length=100), nullable=False, server_default=""))
    op.add_column("evidence", sa.Column("source_tool", sa.String(length=50), nullable=False, server_default=""))
    op.add_column("evidence", sa.Column("observation_id", sa.Integer(), nullable=True))
    op.add_column("evidence", sa.Column("import_run_id", sa.Integer(), nullable=True))
    op.add_column("evidence", sa.Column("parent_evidence_id", sa.Integer(), nullable=True))
    op.add_column("evidence", sa.Column("role", sa.String(length=20), nullable=False, server_default="original"))
    op.add_column("evidence", sa.Column("redaction_status", sa.String(length=20), nullable=False, server_default=""))
    op.add_column("evidence", sa.Column("capture_status", sa.String(length=20), nullable=False, server_default="success"))
    op.add_column(
        "evidence",
        sa.Column("capture_failure_reason", sa.String(length=500), nullable=False, server_default=""),
    )
    op.add_column("evidence", sa.Column("annotation_meta", sa.JSON(), nullable=False, server_default="{}"))
    op.create_foreign_key(
        "fk_evidence_observation_id",
        "evidence",
        "finding_observations",
        ["observation_id"],
        ["id"],
    )
    op.create_foreign_key(
        "fk_evidence_import_run_id",
        "evidence",
        "import_runs",
        ["import_run_id"],
        ["id"],
    )
    op.create_foreign_key(
        "fk_evidence_parent_evidence_id",
        "evidence",
        "evidence",
        ["parent_evidence_id"],
        ["id"],
    )
    op.create_index("ix_evidence_parent_evidence_id", "evidence", ["parent_evidence_id"])
    op.create_index("ix_evidence_observation_id", "evidence", ["observation_id"])


def downgrade() -> None:
    op.drop_index("ix_evidence_observation_id", table_name="evidence")
    op.drop_index("ix_evidence_parent_evidence_id", table_name="evidence")
    op.drop_constraint("fk_evidence_parent_evidence_id", "evidence", type_="foreignkey")
    op.drop_constraint("fk_evidence_import_run_id", "evidence", type_="foreignkey")
    op.drop_constraint("fk_evidence_observation_id", "evidence", type_="foreignkey")
    for col in (
        "annotation_meta",
        "capture_failure_reason",
        "capture_status",
        "redaction_status",
        "role",
        "parent_evidence_id",
        "import_run_id",
        "observation_id",
        "source_tool",
        "content_type",
    ):
        op.drop_column("evidence", col)
