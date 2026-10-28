"""Platform Certification Authority singleton for issuer branding on reports.

Revision ID: 0028_certification_authority
Revises: 0027_finding_observations_rls
Create Date: 2026-10-28 13:30:00.000000
"""
# @lat: [[architecture#Schema migrations]]
# @lat: [[reports#Certification Authority branding]]
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0028_certification_authority"
down_revision: str | None = "0027_finding_observations_rls"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "certification_authority",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("legal_name", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("signer_name", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("signer_title", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("authorization_statement", sa.Text(), nullable=False, server_default=""),
        sa.Column("logo", sa.Text(), nullable=False, server_default=""),
        sa.Column("address_line1", sa.String(length=300), nullable=False, server_default=""),
        sa.Column("address_line2", sa.String(length=300), nullable=False, server_default=""),
        sa.Column("city", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("state", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("postal_code", sa.String(length=40), nullable=False, server_default=""),
        sa.Column("country", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("contact_name", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("contact_email", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("contact_phone", sa.String(length=80), nullable=False, server_default=""),
        sa.Column("website", sa.String(length=300), nullable=False, server_default=""),
        sa.Column("updated_by", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("certification_authority")
