"""report workflow and retests

Revision ID: 0005_reports
Revises: 0004_compliance
Create Date: 2026-10-14 16:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_reports"
down_revision: str | None = "0004_compliance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "retests",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("finding_id", sa.Integer(), nullable=False),
        sa.Column("scan_run_id", sa.Integer(), nullable=True),
        sa.Column("result", sa.String(length=30), nullable=False),
        sa.Column("requested_by", sa.String(length=200), nullable=False),
        sa.Column("requested_by_user_id", sa.Integer(), nullable=True),
        sa.Column("finalized_by", sa.String(length=200), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("asset_reached", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finalized_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"]),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_runs.id"]),
        sa.ForeignKeyConstraint(["requested_by_user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("reports", schema=None) as batch_op:
        batch_op.add_column(sa.Column("qa_by", sa.String(length=200), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("qa_by_user_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("rejection_note", sa.Text(), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("algorithm", sa.String(length=40), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("docx_path", sa.String(length=500), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("docx_sha256", sa.String(length=64), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("pdf_path", sa.String(length=500), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("pdf_sha256", sa.String(length=64), nullable=False, server_default=""))
        batch_op.create_foreign_key("fk_reports_qa_by_user", "users", ["qa_by_user_id"], ["id"])
        batch_op.alter_column("signature", existing_type=sa.String(length=200), type_=sa.String(length=500))


def downgrade() -> None:
    with op.batch_alter_table("reports", schema=None) as batch_op:
        batch_op.drop_constraint("fk_reports_qa_by_user", type_="foreignkey")
        batch_op.drop_column("pdf_sha256")
        batch_op.drop_column("pdf_path")
        batch_op.drop_column("docx_sha256")
        batch_op.drop_column("docx_path")
        batch_op.drop_column("algorithm")
        batch_op.drop_column("rejection_note")
        batch_op.drop_column("qa_by_user_id")
        batch_op.drop_column("qa_by")
        batch_op.alter_column("signature", existing_type=sa.String(length=500), type_=sa.String(length=200))
    op.drop_table("retests")
