"""Add notes_json to scan_runs and import_runs for scanner tool notes.

Revision ID: 0016_import_notes
Revises: 0015_passed_checks
Create Date: 2026-10-16 18:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0016_import_notes"
down_revision: str | None = "0015_passed_checks"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("scan_runs", schema=None) as b:
        b.add_column(sa.Column("notes_json", sa.Text(), nullable=False, server_default=""))
    with op.batch_alter_table("import_runs", schema=None) as b:
        b.add_column(sa.Column("notes_json", sa.Text(), nullable=False, server_default=""))


def downgrade() -> None:
    with op.batch_alter_table("import_runs", schema=None) as b:
        b.drop_column("notes_json")
    with op.batch_alter_table("scan_runs", schema=None) as b:
        b.drop_column("notes_json")
