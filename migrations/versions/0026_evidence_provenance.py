"""Evidence provenance, annotated derivatives, and capture-failure fields (master Phase 7).

Revision ID: 0026_evidence_provenance
Revises: 0025_finding_observations
Create Date: 2026-10-27 22:00:00.000000

Uses batch_alter_table so SQLite can add foreign keys. Column adds are idempotent so a
partial apply (columns present, alembic_version still at 0025) can finish safely.
"""
# @lat: [[architecture#Schema migrations]]
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "0026_evidence_provenance"
down_revision: str | None = "0025_finding_observations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PROVENANCE_COLUMNS: tuple[tuple[str, sa.Column], ...] = (
    ("content_type", sa.Column("content_type", sa.String(length=100), nullable=False, server_default="")),
    ("source_tool", sa.Column("source_tool", sa.String(length=50), nullable=False, server_default="")),
    ("observation_id", sa.Column("observation_id", sa.Integer(), nullable=True)),
    ("import_run_id", sa.Column("import_run_id", sa.Integer(), nullable=True)),
    ("parent_evidence_id", sa.Column("parent_evidence_id", sa.Integer(), nullable=True)),
    ("role", sa.Column("role", sa.String(length=20), nullable=False, server_default="original")),
    ("redaction_status", sa.Column("redaction_status", sa.String(length=20), nullable=False, server_default="")),
    ("capture_status", sa.Column("capture_status", sa.String(length=20), nullable=False, server_default="success")),
    (
        "capture_failure_reason",
        sa.Column("capture_failure_reason", sa.String(length=500), nullable=False, server_default=""),
    ),
    ("annotation_meta", sa.Column("annotation_meta", sa.JSON(), nullable=False, server_default="{}")),
)


def upgrade() -> None:
    bind = op.get_bind()
    existing_cols = {c["name"] for c in inspect(bind).get_columns("evidence")}
    existing_fks = {fk.get("name") for fk in inspect(bind).get_foreign_keys("evidence")}
    existing_ix = {ix["name"] for ix in inspect(bind).get_indexes("evidence")}

    with op.batch_alter_table("evidence", schema=None) as batch_op:
        for name, col in _PROVENANCE_COLUMNS:
            if name not in existing_cols:
                batch_op.add_column(col)
        if "fk_evidence_observation_id" not in existing_fks:
            batch_op.create_foreign_key(
                "fk_evidence_observation_id",
                "finding_observations",
                ["observation_id"],
                ["id"],
            )
        if "fk_evidence_import_run_id" not in existing_fks:
            batch_op.create_foreign_key(
                "fk_evidence_import_run_id",
                "import_runs",
                ["import_run_id"],
                ["id"],
            )
        if "fk_evidence_parent_evidence_id" not in existing_fks:
            batch_op.create_foreign_key(
                "fk_evidence_parent_evidence_id",
                "evidence",
                ["parent_evidence_id"],
                ["id"],
            )
        if "ix_evidence_parent_evidence_id" not in existing_ix:
            batch_op.create_index("ix_evidence_parent_evidence_id", ["parent_evidence_id"])
        if "ix_evidence_observation_id" not in existing_ix:
            batch_op.create_index("ix_evidence_observation_id", ["observation_id"])


def downgrade() -> None:
    with op.batch_alter_table("evidence", schema=None) as batch_op:
        batch_op.drop_index("ix_evidence_observation_id")
        batch_op.drop_index("ix_evidence_parent_evidence_id")
        batch_op.drop_constraint("fk_evidence_parent_evidence_id", type_="foreignkey")
        batch_op.drop_constraint("fk_evidence_import_run_id", type_="foreignkey")
        batch_op.drop_constraint("fk_evidence_observation_id", type_="foreignkey")
        for name, _ in reversed(_PROVENANCE_COLUMNS):
            batch_op.drop_column(name)
