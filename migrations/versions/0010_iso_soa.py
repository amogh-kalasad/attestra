"""ISO 27001 Statement of Applicability, NC/CA workflow, 9.2 audit sampling (C10)

Revision ID: 0010_iso_soa
Revises: 0009_pci_asv
Create Date: 2026-10-14 23:10:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010_iso_soa"
down_revision: str | None = "0009_pci_asv"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

from attestra.rls import ISO_POLICIES, POLICY_NAME  # noqa: E402


def upgrade() -> None:
    with op.batch_alter_table("nonconformities", schema=None) as b:
        b.add_column(sa.Column("description", sa.Text(), nullable=False, server_default=""))
        b.add_column(sa.Column("grade", sa.String(length=10), nullable=False, server_default="minor"))
        b.add_column(sa.Column("root_cause", sa.Text(), nullable=False, server_default=""))
        b.add_column(sa.Column("status", sa.String(length=20), nullable=False, server_default="open"))
        b.add_column(sa.Column("verified_by", sa.String(length=200), nullable=False, server_default=""))
        b.add_column(sa.Column("created_at", sa.DateTime(timezone=True), nullable=True))
    op.create_table(
        "soa_entries",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("engagement_id", sa.Integer(), nullable=False),
        sa.Column("control_ref", sa.String(length=50), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("applicable", sa.Boolean(), nullable=False),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("implementation", sa.String(length=20), nullable=False),
        sa.Column("updated_by", sa.String(length=200), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("engagement_id", "control_ref"),
    )
    op.create_table(
        "audit_samples",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("engagement_id", sa.Integer(), nullable=False),
        sa.Column("clause", sa.String(length=20), nullable=False),
        sa.Column("population", sa.String(length=50), nullable=False),
        sa.Column("population_size", sa.Integer(), nullable=False),
        sa.Column("sample_size", sa.Integer(), nullable=False),
        sa.Column("seed", sa.String(length=64), nullable=False),
        sa.Column("items", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    if op.get_bind().dialect.name == "postgresql":
        for table, expr in ISO_POLICIES.items():
            op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
            op.execute(f"CREATE POLICY {POLICY_NAME} ON {table} USING {expr} WITH CHECK {expr}")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table in ISO_POLICIES:
            op.execute(f"DROP POLICY IF EXISTS {POLICY_NAME} ON {table}")
    op.drop_table("audit_samples")
    op.drop_table("soa_entries")
    with op.batch_alter_table("nonconformities", schema=None) as b:
        for col in ("created_at", "verified_by", "status", "root_cause", "grade", "description"):
            b.drop_column(col)
