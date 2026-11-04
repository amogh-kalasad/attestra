"""Findings library writeups and tenant report templates

Revision ID: 0012_findings_library
Revises: 0011_trust_center
Create Date: 2026-10-14 23:30:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012_findings_library"
down_revision: str | None = "0011_trust_center"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

from attestra.rls import LIBRARY_POLICIES, POLICY_NAME  # noqa: E402


def upgrade() -> None:
    op.create_table(
        "library_entries",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("impact", sa.Text(), nullable=False),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.Column("references", sa.JSON(), nullable=False),
        sa.Column("cwe", sa.Integer(), nullable=True),
        sa.Column("default_severity", sa.String(length=10), nullable=False),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("rule_ids", sa.JSON(), nullable=False),
        sa.Column("updated_by", sa.String(length=200), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "title"),
    )
    op.create_table(
        "report_templates",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=30), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("cover_title", sa.String(length=300), nullable=False),
        sa.Column("logo", sa.Text(), nullable=False),
        sa.Column("sections", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("updated_by", sa.String(length=200), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "kind"),
    )
    if op.get_bind().dialect.name == "postgresql":
        for table, expr in LIBRARY_POLICIES.items():
            op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
            op.execute(f"CREATE POLICY {POLICY_NAME} ON {table} USING {expr} WITH CHECK {expr}")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table in LIBRARY_POLICIES:
            op.execute(f"DROP POLICY IF EXISTS {POLICY_NAME} ON {table}")
    op.drop_table("report_templates")
    op.drop_table("library_entries")
