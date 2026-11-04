"""Proof/replay records, outbound webhooks, workflow rules

Revision ID: 0013_proof_webhooks
Revises: 0012_findings_library
Create Date: 2026-10-14 23:30:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013_proof_webhooks"
down_revision: str | None = "0012_findings_library"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

from attestra.rls import POLICY_NAME, PROOF_WEBHOOK_POLICIES  # noqa: E402

_TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "webhook_endpoints",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("url", sa.String(length=2000), nullable=False),
        sa.Column("secret", sa.String(length=128), nullable=False),
        sa.Column("format", sa.String(length=20), nullable=False),
        sa.Column("events", sa.JSON(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.Column("created_at", _TS, nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "webhook_deliveries",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("endpoint_id", sa.Integer(), nullable=False),
        sa.Column("event", sa.String(length=50), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", _TS, nullable=False),
        sa.Column("last_status_code", sa.Integer(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=False),
        sa.Column("created_at", _TS, nullable=False),
        sa.Column("delivered_at", _TS, nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["endpoint_id"], ["webhook_endpoints.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_webhook_deliveries_due", "webhook_deliveries", ["status", "next_attempt_at"])
    op.create_table(
        "workflow_rules",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("event", sa.String(length=50), nullable=False),
        sa.Column("min_severity", sa.String(length=10), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("action", sa.String(length=20), nullable=False),
        sa.Column("endpoint_id", sa.Integer(), nullable=True),
        sa.Column("assignee", sa.String(length=200), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.Column("created_at", _TS, nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["endpoint_id"], ["webhook_endpoints.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "finding_assignments",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("finding_id", sa.Integer(), nullable=False),
        sa.Column("assignee", sa.String(length=200), nullable=False),
        sa.Column("rule_id", sa.Integer(), nullable=True),
        sa.Column("assigned_by", sa.String(length=200), nullable=False),
        sa.Column("created_at", _TS, nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"]),
        sa.ForeignKeyConstraint(["rule_id"], ["workflow_rules.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "proof_replays",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("finding_id", sa.Integer(), nullable=False),
        sa.Column("evidence_id", sa.Integer(), nullable=False),
        sa.Column("response_evidence_id", sa.Integer(), nullable=True),
        sa.Column("retest_id", sa.Integer(), nullable=True),
        sa.Column("method", sa.String(length=10), nullable=False),
        sa.Column("url", sa.String(length=2000), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("error", sa.Text(), nullable=False),
        sa.Column("suggested", sa.String(length=20), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("confirmed_result", sa.String(length=20), nullable=False),
        sa.Column("confirmed_by", sa.String(length=200), nullable=False),
        sa.Column("confirmed_at", _TS, nullable=True),
        sa.Column("unsafe_allowed_by", sa.String(length=200), nullable=False),
        sa.Column("replayed_by", sa.String(length=200), nullable=False),
        sa.Column("created_at", _TS, nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"]),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence.id"]),
        sa.ForeignKeyConstraint(["response_evidence_id"], ["evidence.id"]),
        sa.ForeignKeyConstraint(["retest_id"], ["retests.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    if op.get_bind().dialect.name == "postgresql":
        for table, expr in PROOF_WEBHOOK_POLICIES.items():
            op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
            op.execute(f"CREATE POLICY {POLICY_NAME} ON {table} USING {expr} WITH CHECK {expr}")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table in PROOF_WEBHOOK_POLICIES:
            op.execute(f"DROP POLICY IF EXISTS {POLICY_NAME} ON {table}")
    op.drop_table("proof_replays")
    op.drop_table("finding_assignments")
    op.drop_table("workflow_rules")
    op.drop_index("ix_webhook_deliveries_due", table_name="webhook_deliveries")
    op.drop_table("webhook_deliveries")
    op.drop_table("webhook_endpoints")
