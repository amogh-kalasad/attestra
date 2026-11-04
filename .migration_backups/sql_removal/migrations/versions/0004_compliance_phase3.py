"""compliance phase 3 records

Revision ID: 0004_compliance
Revises: 0003_users
Create Date: 2026-10-14 15:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_compliance"
down_revision: str | None = "0003_users"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.add_column(sa.Column("owasp_top10", sa.String(length=100), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("asvs_ref", sa.String(length=50), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("wstg_ref", sa.String(length=50), nullable=False, server_default=""))

    op.create_table(
        "risk_acceptances",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("engagement_id", sa.Integer(), nullable=False),
        sa.Column("finding_id", sa.Integer(), nullable=False),
        sa.Column("owner_user_id", sa.Integer(), nullable=True),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_on", sa.Date(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"]),
        sa.ForeignKeyConstraint(["owner_user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "asv_scans",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("engagement_id", sa.Integer(), nullable=False),
        sa.Column("vendor", sa.String(length=200), nullable=False),
        sa.Column("scan_date", sa.Date(), nullable=False),
        sa.Column("passing", sa.Boolean(), nullable=False),
        sa.Column("attestation_path", sa.String(length=500), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "segmentation_tests",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("engagement_id", sa.Integer(), nullable=False),
        sa.Column("boundary", sa.String(length=300), nullable=False),
        sa.Column("method", sa.String(length=200), nullable=False),
        sa.Column("result", sa.String(length=50), nullable=False),
        sa.Column("tested_on", sa.Date(), nullable=False),
        sa.Column("evidence_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "scan_schedules",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("engagement_id", sa.Integer(), nullable=False),
        sa.Column("asset_id", sa.Integer(), nullable=False),
        sa.Column("tool", sa.String(length=50), nullable=False),
        sa.Column("cadence", sa.String(length=20), nullable=False),
        sa.Column("next_due", sa.Date(), nullable=False),
        sa.Column("last_enqueued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("quarter_clean", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"]),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "nonconformities",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("engagement_id", sa.Integer(), nullable=False),
        sa.Column("control_ref", sa.String(length=50), nullable=False),
        sa.Column("finding_id", sa.Integer(), nullable=True),
        sa.Column("corrective_action", sa.Text(), nullable=False),
        sa.Column("owner", sa.String(length=200), nullable=False),
        sa.Column("due", sa.Date(), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retest_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"]),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("nonconformities")
    op.drop_table("scan_schedules")
    op.drop_table("segmentation_tests")
    op.drop_table("asv_scans")
    op.drop_table("risk_acceptances")
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.drop_column("wstg_ref")
        batch_op.drop_column("asvs_ref")
        batch_op.drop_column("owasp_top10")
