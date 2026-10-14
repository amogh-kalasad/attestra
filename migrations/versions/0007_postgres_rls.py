"""postgres row-level security per tenant (Phase 6.1)

Revision ID: 0007_postgres_rls
Revises: 0006_evidence
Create Date: 2026-10-14 20:45:00.000000

Postgres only; a no-op on SQLite. Policies read the transaction-local setting
``app.tenant_id`` (comma-separated tenant ids) that ``attestra.db.session``
sets per request. When the setting is unset or empty the session is
unrestricted (admin / platform operator / CLI), mirroring
``services.tenant_ids_for() is None``. FORCE is used so the table owner is
also subject to the policies; superusers still bypass RLS, so the app must
connect as a non-superuser role in production.
"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0007_postgres_rls"
down_revision: str | None = "0006_evidence"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Shared with attestra.db so tests can assert coverage.
from attestra.rls import POLICY_NAME, rls_drop_statements, rls_statements  # noqa: E402


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for stmt in rls_statements():
        op.execute(stmt)


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for stmt in rls_drop_statements():
        op.execute(stmt)


__all__ = ["POLICY_NAME"]