"""Track which certificate expiry bands already sent a webhook.

Revision ID: 0017_cert_expiry_alerts
Revises: 0016_import_notes
Create Date: 2026-10-16 20:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017_cert_expiry_alerts"
down_revision: str | None = "0016_import_notes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

from attestra.rls import POLICY_NAME  # noqa: E402

_TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "cert_expiry_alerts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("engagement_id", sa.Integer(), nullable=False),
        sa.Column("asset_id", sa.Integer(), nullable=False),
        sa.Column("end_date", sa.Date(), nullable=False),
        sa.Column("alerted_bands", sa.JSON(), nullable=False),
        sa.Column("updated_at", _TS, nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id"),
    )
    # Postgres RLS (no-op on SQLite).
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        expr = "tenant_id = NULLIF(current_setting('attestra.tenant_id', true), '')::int"
        op.execute(f"ALTER TABLE cert_expiry_alerts ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY {POLICY_NAME} ON cert_expiry_alerts "
            f"FOR ALL USING ({expr}) WITH CHECK ({expr})"
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(f"DROP POLICY IF EXISTS {POLICY_NAME} ON cert_expiry_alerts")
    op.drop_table("cert_expiry_alerts")
