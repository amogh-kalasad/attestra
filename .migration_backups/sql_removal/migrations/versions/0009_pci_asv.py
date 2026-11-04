"""PCI quarterly scan calendar, ASV result import, segmentation details (C9)

Revision ID: 0009_pci_asv
Revises: 0008_tuning
Create Date: 2026-10-14 23:00:00.000000

Adds per-component ASV result rows, import metadata on asv_scans, and extra
detail columns on segmentation_tests. On Postgres the new table gets the same
tenant_isolation policy as the other tenant tables.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009_pci_asv"
down_revision: str | None = "0008_tuning"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

from attestra.rls import ASV_POLICIES, POLICY_NAME  # noqa: E402


def upgrade() -> None:
    with op.batch_alter_table("asv_scans", schema=None) as b:
        b.add_column(sa.Column("source", sa.String(length=20), nullable=False, server_default="manual"))
        b.add_column(sa.Column("filename", sa.String(length=300), nullable=False, server_default=""))
        b.add_column(sa.Column("item_count", sa.Integer(), nullable=False, server_default="0"))
        b.add_column(sa.Column("failing_count", sa.Integer(), nullable=False, server_default="0"))
    with op.batch_alter_table("segmentation_tests", schema=None) as b:
        b.add_column(sa.Column("source_zone", sa.String(length=200), nullable=False, server_default=""))
        b.add_column(sa.Column("target_zone", sa.String(length=200), nullable=False, server_default=""))
        b.add_column(sa.Column("tester", sa.String(length=200), nullable=False, server_default=""))
        b.add_column(sa.Column("notes", sa.Text(), nullable=False, server_default=""))
    op.create_table(
        "asv_scan_items",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("asv_scan_id", sa.Integer(), nullable=False),
        sa.Column("host", sa.String(length=300), nullable=False),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("severity", sa.String(length=10), nullable=False),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cve", sa.String(length=50), nullable=False),
        sa.Column("passing", sa.Boolean(), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["asv_scan_id"], ["asv_scans.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    if op.get_bind().dialect.name == "postgresql":
        for table, expr in ASV_POLICIES.items():
            op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
            op.execute(f"CREATE POLICY {POLICY_NAME} ON {table} USING {expr} WITH CHECK {expr}")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table in ASV_POLICIES:
            op.execute(f"DROP POLICY IF EXISTS {POLICY_NAME} ON {table}")
    op.drop_table("asv_scan_items")
    with op.batch_alter_table("segmentation_tests", schema=None) as b:
        for col in ("notes", "tester", "target_zone", "source_zone"):
            b.drop_column(col)
    with op.batch_alter_table("asv_scans", schema=None) as b:
        for col in ("failing_count", "item_count", "filename", "source"):
            b.drop_column(col)
