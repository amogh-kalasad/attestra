"""Enable Postgres RLS on finding_observations (master Phase 10).

Revision ID: 0027_finding_observations_rls
Revises: 0026_evidence_provenance
Create Date: 2026-10-27 23:30:00.000000

No-op on SQLite. Does not alter rows; only adds tenant isolation policy for
engagement-scoped observation history created in 0025.
"""
# @lat: [[architecture#Schema migrations]]
from __future__ import annotations

from collections.abc import Sequence

from alembic import op

from attestra.rls import FINDING_OBSERVATION_POLICIES, POLICY_NAME

revision: str = "0027_finding_observations_rls"
down_revision: str | None = "0026_evidence_provenance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table, expr in FINDING_OBSERVATION_POLICIES.items():
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"DROP POLICY IF EXISTS {POLICY_NAME} ON {table}")
        op.execute(f"CREATE POLICY {POLICY_NAME} ON {table} USING {expr} WITH CHECK {expr}")


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table in FINDING_OBSERVATION_POLICIES:
        op.execute(f"DROP POLICY IF EXISTS {POLICY_NAME} ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
