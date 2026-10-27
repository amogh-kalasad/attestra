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


def _via_asv_scan(col: str = "asv_scan_id") -> str:
    return (
        f"({_UNRESTRICTED} OR EXISTS (SELECT 1 FROM asv_scans a JOIN engagements e ON e.id = a.engagement_id "
        f"WHERE a.id = {col} AND e.tenant_id = ANY({_ALLOWED})))"
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
# Tables created by migration 0007 itself; later migrations add their own.
PHASE6_TABLES: tuple[str, ...] = tuple(POLICIES)
# Phase 7.4 (migration 0008_tuning).
TUNING_POLICIES: dict[str, str] = {
    "tenant_risk_weights": _tenant("tenant_id"),
    "suppression_rules": _tenant("tenant_id"),
}
POLICIES.update(TUNING_POLICIES)
# C9 (migration 0009_pci_asv).
ASV_POLICIES: dict[str, str] = {"asv_scan_items": _via_asv_scan()}
POLICIES.update(ASV_POLICIES)
# C10 (migration 0010_iso_soa).
ISO_POLICIES: dict[str, str] = {
    "soa_entries": _via_engagement(),
    "audit_samples": _via_engagement(),
}
POLICIES.update(ISO_POLICIES)
# Proof replay + webhooks (migration 0013_proof_webhooks).
PROOF_WEBHOOK_POLICIES: dict[str, str] = {
    "proof_replays": _via_finding(),
    "finding_assignments": _via_finding(),
    "webhook_endpoints": _tenant("tenant_id"),
    "webhook_deliveries": _tenant("tenant_id"),
    "workflow_rules": _tenant("tenant_id"),
}
POLICIES.update(PROOF_WEBHOOK_POLICIES)
# Trust center (migration 0011_trust_center).
TRUST_POLICIES: dict[str, str] = {
    "trust_centers": _tenant("tenant_id"),
    "trust_items": _tenant("tenant_id"),
    "trust_access_requests": _tenant("tenant_id"),
}
POLICIES.update(TRUST_POLICIES)
# Findings library + report templates (migration 0012_findings_library).
LIBRARY_POLICIES: dict[str, str] = {
    "library_entries": _tenant("tenant_id"),
    "report_templates": _tenant("tenant_id"),
}
POLICIES.update(LIBRARY_POLICIES)
# User management (migration 0014_user_invites).
USER_POLICIES: dict[str, str] = {"user_invites": _tenant("tenant_id")}
POLICIES.update(USER_POLICIES)
# Certificate expiry webhook state (migration 0017_cert_expiry_alerts).
CERT_EXPIRY_POLICIES: dict[str, str] = {"cert_expiry_alerts": _tenant("tenant_id")}
POLICIES.update(CERT_EXPIRY_POLICIES)
# Finding comments (migration 0018_finding_comments).
COMMENT_POLICIES: dict[str, str] = {"finding_comments": _tenant("tenant_id")}
POLICIES.update(COMMENT_POLICIES)
# Share links (migration 0019_share_links).
SHARE_POLICIES: dict[str, str] = {"share_links": _tenant("tenant_id")}
POLICIES.update(SHARE_POLICIES)
# Email alerts (migration 0020_email_alerts).
EMAIL_ALERT_POLICIES: dict[str, str] = {
    "email_alert_settings": _tenant("tenant_id"),
    "email_alert_sent": _tenant("tenant_id"),
}
POLICIES.update(EMAIL_ALERT_POLICIES)
# Authenticated website testing (migration 0022_auth_web).
AUTH_WEB_POLICIES: dict[str, str] = {
    "auth_credential_profiles": _tenant("tenant_id"),
    "auth_route_inventory": _tenant("tenant_id"),
    "auth_element_inventory": _tenant("tenant_id"),
    "auth_checklist_items": _tenant("tenant_id"),
}
POLICIES.update(AUTH_WEB_POLICIES)
# Organization test-run credits (migration 0023_subscription_credits).
SUBSCRIPTION_CREDIT_POLICIES: dict[str, str] = {
    "tenant_credit_accounts": _tenant("tenant_id"),
    "credit_transactions": _tenant("tenant_id"),
    "credit_renewal_requests": _tenant("tenant_id"),
}
POLICIES.update(SUBSCRIPTION_CREDIT_POLICIES)
# Deliberately not isolated: users/api_keys (needed to authenticate before the
# tenant is known), jobs (worker queue), audit_events (global hash chain).


def rls_statements(tables=None) -> list[str]:
    out: list[str] = []
    for table in tables if tables is not None else POLICIES:
        expr = POLICIES[table]
        out += [
            f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",
            f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY",
            f"DROP POLICY IF EXISTS {POLICY_NAME} ON {table}",
            f"CREATE POLICY {POLICY_NAME} ON {table} USING {expr} WITH CHECK {expr}",
        ]
    return out


def rls_drop_statements(tables=None) -> list[str]:
    out: list[str] = []
    for table in tables if tables is not None else POLICIES:
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