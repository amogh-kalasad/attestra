"""Authenticated website testing tables (credential profiles, routes, elements, checklist).

Revision ID: 0022_auth_web
Revises: 0021_finding_fields_disclaimer
Create Date: 2026-10-23 12:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from attestra.rls import AUTH_WEB_POLICIES, POLICY_NAME

revision: str = "0022_auth_web"
down_revision: str | None = "0021_finding_fields_disclaimer"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "auth_credential_profiles",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("engagement_id", sa.Integer(), nullable=False),
        sa.Column("asset_id", sa.Integer(), nullable=True),
        sa.Column("label", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("role_name", sa.String(length=100), nullable=False, server_default=""),
        sa.Column("purpose", sa.Text(), nullable=False, server_default=""),
        sa.Column("method", sa.String(length=30), nullable=False, server_default="form"),
        sa.Column("login_url", sa.String(length=1000), nullable=False, server_default=""),
        sa.Column("username_selector", sa.String(length=300), nullable=False, server_default=""),
        sa.Column("password_selector", sa.String(length=300), nullable=False, server_default=""),
        sa.Column("submit_selector", sa.String(length=300), nullable=False, server_default=""),
        sa.Column("success_url_contains", sa.String(length=500), nullable=False, server_default=""),
        sa.Column("secret_ref", sa.String(length=300), nullable=False, server_default=""),
        sa.Column("config_json", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False, server_default="pending"),
        sa.Column("last_validated_at", _TS, nullable=True),
        sa.Column("last_validation_note", sa.String(length=500), nullable=False, server_default=""),
        sa.Column("created_by", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("updated_by", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("created_at", _TS, nullable=False),
        sa.Column("updated_at", _TS, nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "auth_route_inventory",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("engagement_id", sa.Integer(), nullable=False),
        sa.Column("asset_id", sa.Integer(), nullable=False),
        sa.Column("scan_run_id", sa.Integer(), nullable=True),
        sa.Column("url", sa.String(length=2000), nullable=False),
        sa.Column("http_method", sa.String(length=10), nullable=False, server_default="GET"),
        sa.Column("title", sa.String(length=300), nullable=False, server_default=""),
        sa.Column("role_name", sa.String(length=100), nullable=False, server_default=""),
        sa.Column("status", sa.String(length=30), nullable=False, server_default="discovered"),
        sa.Column("skip_reason", sa.String(length=500), nullable=False, server_default=""),
        sa.Column("discovered_from", sa.String(length=2000), nullable=False, server_default=""),
        sa.Column("authenticated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("depth", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("visited_at", _TS, nullable=True),
        sa.Column("created_at", _TS, nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"]),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_runs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("engagement_id", "asset_id", "url", "role_name", "http_method"),
    )
    op.create_table(
        "auth_element_inventory",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("engagement_id", sa.Integer(), nullable=False),
        sa.Column("route_id", sa.Integer(), nullable=False),
        sa.Column("selector", sa.String(length=500), nullable=False, server_default=""),
        sa.Column("accessible_name", sa.String(length=300), nullable=False, server_default=""),
        sa.Column("element_type", sa.String(length=50), nullable=False, server_default=""),
        sa.Column("input_type", sa.String(length=50), nullable=False, server_default=""),
        sa.Column("required", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("test_status", sa.String(length=30), nullable=False, server_default="not_tested"),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", _TS, nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.ForeignKeyConstraint(["route_id"], ["auth_route_inventory.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "auth_checklist_items",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("engagement_id", sa.Integer(), nullable=False),
        sa.Column("ref", sa.String(length=80), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False, server_default=""),
        sa.Column("mapping_version", sa.String(length=40), nullable=False, server_default=""),
        sa.Column("status", sa.String(length=30), nullable=False, server_default="not_started"),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("evidence_ids", sa.JSON(), nullable=False),
        sa.Column("finding_ids", sa.JSON(), nullable=False),
        sa.Column("executed_at", _TS, nullable=True),
        sa.Column("updated_by", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("updated_at", _TS, nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("engagement_id", "ref"),
    )
    if op.get_bind().dialect.name == "postgresql":
        for table, expr in AUTH_WEB_POLICIES.items():
            op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
            op.execute(f"CREATE POLICY {POLICY_NAME} ON {table} USING {expr} WITH CHECK {expr}")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table in AUTH_WEB_POLICIES:
            op.execute(f"DROP POLICY IF EXISTS {POLICY_NAME} ON {table}")
    op.drop_table("auth_element_inventory")
    op.drop_table("auth_route_inventory")
    op.drop_table("auth_checklist_items")
    op.drop_table("auth_credential_profiles")
