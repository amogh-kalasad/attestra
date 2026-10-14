"""PostgreSQL row-level security definitions (Phase 6.1).

Single source of truth for which tables are tenant-isolated and how. Used by
migration ``0007_postgres_rls`` and by tests.
"""
from __future__ import annotations

POLICY_NAME = "tenant_isolation"
SETTING = "app.tenant_id"

# Expression true when the session is unrestricted (setting unset or empty).
_UNRESTRICTED = f"coalesce(current_setting('{SETTING}', true), '') = ''"
# Tenant ids allowed for this transaction.
_ALLOWED = f"string_to_array(current_setting('{SETTING}', true), ',')::int[]"


def _tenant(col: str) -> str:
    return f"({_UNRESTRICTED} OR {col} = ANY({_ALLOWED}))"


def _via_engagement(col: str = "engagement_id") -> str:
    return (
        f"({_UNRESTRICTED} OR EXISTS (SELECT 1 FROM engagements e "
        f"WHERE e.id = {col} AND e.tenant_id = ANY({_ALLOWED})))"
    )


def _via_finding(col: str = "finding_id") -> str:
    return (
        f"({_UNRESTRICTED} OR EXISTS (SELECT 1 FROM findings f JOIN engagements e ON e.id = f.engagement_id "
        f"WHERE f.id = {col} AND e.tenant_id = ANY({_ALLOWED})))"
    )


# table -> USING / WITH CHECK expression
POLICIES: dict[str, str] = {
    "tenants": _tenant("id"),
    "engagements": _tenant("tenant_id"),
    "retention_policies": _tenant("tenant_id"),
    "tenant_memberships": _tenant("tenant_id"),
    "assets": _via_engagement(),
    "asv_scans": _via_engagement(),
    "authorizations": _via_engagement(),
    "control_assessments": _via_engagement(),
    "import_runs": _via_engagement(),
    "reports": _via_engagement(),
    "scope_rules": _via_engagement(),
    "findings": _via_engagement(),
    "scan_runs": _via_engagement(),
    "scan_schedules": _via_engagement(),
    "segmentation_tests": _via_engagement(),
    "nonconformities": _via_engagement(),
    "risk_acceptances": _via_engagement(),
    "evidence": _via_finding(),
    "retests": _via_finding(),
}
# Deliberately not isolated: users/api_keys (needed to authenticate before the
# tenant is known), jobs (worker queue), audit_events (global hash chain).


def rls_statements() -> list[str]:
    out: list[str] = []
    for table, expr in POLICIES.items():
        out += [
            f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",
            f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY",
            f"DROP POLICY IF EXISTS {POLICY_NAME} ON {table}",
            f"CREATE POLICY {POLICY_NAME} ON {table} USING {expr} WITH CHECK {expr}",
        ]
    return out


def rls_drop_statements() -> list[str]:
    out: list[str] = []
    for table in POLICIES:
        out += [
            f"DROP POLICY IF EXISTS {POLICY_NAME} ON {table}",
            f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY",
            f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY",
        ]
    return out


def setting_value(tenant_ids) -> str:
    """Serialize allowed tenant ids. ``None`` = unrestricted (''); empty set = no access ('0')."""
    if tenant_ids is None:
        return ""
    ids = sorted(int(t) for t in tenant_ids)
    return ",".join(str(i) for i in ids) if ids else "0"