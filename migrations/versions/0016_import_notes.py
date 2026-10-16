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


def _has_column(table: str, column: str) -> bool:
    bind = op.get_bind()
    rows = bind.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()
    # PRAGMA row: cid, name, type, notnull, dflt_value, pk
    return any(r[1] == column for r in rows)


def upgrade() -> None:
    # Idempotent: some DBs already have notes_json from model create_all / partial apply.
    if not _has_column("scan_runs", "notes_json"):
        with op.batch_alter_table("scan_runs", schema=None) as b:
            b.add_column(sa.Column("notes_json", sa.Text(), nullable=False, server_default=""))
    if not _has_column("import_runs", "notes_json"):
        with op.batch_alter_table("import_runs", schema=None) as b:
            b.add_column(sa.Column("notes_json", sa.Text(), nullable=False, server_default=""))


def downgrade() -> None:
    with op.batch_alter_table("import_runs", schema=None) as b:
        b.drop_column("notes_json")
    with op.batch_alter_table("scan_runs", schema=None) as b:
        b.drop_column("notes_json")
