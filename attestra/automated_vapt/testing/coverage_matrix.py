"""Phase 3 PT coverage matrix — categories → modules/test ids → status.

Importable by a coverage tracker. Status values: ``implemented`` | ``partial`` | ``deferred``.
Safe non-destructive probes only; destructive / spray / forge paths stay deferred.
"""

from __future__ import annotations

from typing import Any, Literal

CoverageStatus = Literal["implemented", "partial", "deferred"]

# @lat: [[architecture#Elite automated security testing#Authz test modules]]
# @lat: [[architecture#World-class PT coverage honesty (Phase 3)]]

PHASE3_COVERAGE: dict[str, list[dict[str, Any]]] = {
    "authentication": [
        {
            "capability": "authentication_bypass_gates",
            "module": "authentication_tests",
            "test_ids": ["T03"],
            "status": "implemented",
            "notes": "Unauth /app and /app/settings gate checks",
        },
        {
            "capability": "account_enumeration_differential",
            "module": "authentication_tests",
            "test_ids": ["T03"],
            "status": "implemented",
            "notes": "Two-probe unknown vs known username; no spraying",
        },
        {
            "capability": "authentication_state_handling",
            "module": "authentication_tests",
            "test_ids": ["T03"],
            "status": "implemented",
            "notes": "Protected route after cookie clear must deny",
        },
        {
            "capability": "password_reset_weaknesses",
            "module": None,
            "test_ids": [],
            "status": "deferred",
            "notes": "Destructive/reset flows not automated",
        },
        {
            "capability": "mfa_weaknesses",
            "module": None,
            "test_ids": [],
            "status": "deferred",
            "notes": "Requires MFA fixtures per target",
        },
        {
            "capability": "brute_force_protection",
            "module": None,
            "test_ids": [],
            "status": "deferred",
            "notes": "No brute-force loops by policy",
        },
        {
            "capability": "api_auth_bypass_replay",
            "module": "replay_checks",
            "test_ids": ["T19"],
            "status": "implemented",
            "notes": "API GET replay without session / bad bearer",
        },
    ],
    "authorization": [
        {
            "capability": "idor_bola",
            "module": "idor_bola_tests",
            "test_ids": ["T04"],
            "status": "implemented",
            "notes": "Two-account object-level access",
        },
        {
            "capability": "role_based_access_control",
            "module": "authorization_tests",
            "test_ids": ["T05"],
            "status": "implemented",
            "notes": "Member vs admin on /admin",
        },
        {
            "capability": "vertical_privilege_escalation",
            "module": "privilege_escalation_tests",
            "test_ids": ["T05-PRIV", "T05"],
            "status": "implemented",
            "notes": "probe_vertical_privilege; T05-PRIV helper id",
        },
        {
            "capability": "horizontal_privilege_escalation",
            "module": "privilege_escalation_tests",
            "test_ids": ["T05-PRIV", "T04"],
            "status": "implemented",
            "notes": "probe_horizontal_privilege; full BOLA via T04",
        },
        {
            "capability": "tenant_isolation",
            "module": "tenant_isolation_tests",
            "test_ids": ["T06"],
            "status": "implemented",
            "notes": "Cross-tenant project access",
        },
        {
            "capability": "api_idor_bola_replay",
            "module": "replay_checks",
            "test_ids": ["T20"],
            "status": "implemented",
            "notes": "Harvested object-id swap on GET",
        },
        {
            "capability": "api_object_mutation_bola_write",
            "module": "body_mutation",
            "test_ids": ["T22"],
            "status": "partial",
            "notes": "Off by default; never DELETE; local/dev only",
        },
    ],
    "session": [
        {
            "capability": "session_cookie_presence",
            "module": "session_security_tests",
            "test_ids": ["SESSION"],
            "status": "implemented",
            "notes": "Detect session-like cookies after login",
        },
        {
            "capability": "cookie_security_flags",
            "module": "session_security_tests",
            "test_ids": ["SESSION"],
            "status": "implemented",
            "notes": "Secure/HttpOnly/SameSite observation; Secure finding on HTTPS only",
        },
        {
            "capability": "jwt_structure_alg_none",
            "module": "session_security_tests",
            "test_ids": ["SESSION"],
            "status": "implemented",
            "notes": "Header decode only; no token forging",
        },
        {
            "capability": "session_fixation",
            "module": "session_lifecycle",
            "test_ids": ["SESSLIFE"],
            "status": "partial",
            "notes": "Session id rotation on login (lab); passive on engagements",
        },
        {
            "capability": "session_expiration_invalidation_rotation",
            "module": "attestra.auth_web.session_guard",
            "test_ids": ["SESSION", "SESSLIFE"],
            "status": "partial",
            "notes": "SESSLIFE logout invalidation (lab) + passive expiry/JWT lifetime; mid-scan expiry detection, bounded re-login, and optional JSON/cookie refresh via session_guard; full timed logout/invalidation catalogue still limited",
        },
        {
            "capability": "session_lifecycle",
            "module": "session_lifecycle",
            "test_ids": ["SESSLIFE"],
            "status": "partial",
            "notes": "Rotation on login, invalidation on logout (lab), passive expiry/JWT lifetime on engagements",
        },
        {
            "capability": "jwt_posture",
            "module": "jwt_posture",
            "test_ids": ["SESSION"],
            "status": "implemented",
            "notes": "Passive JWT header/claims review (alg, exp, lifetime); never forges tokens",
        },
    ],
    "injection": [
        {
            "capability": "reflected_injection_canary",
            "module": "injection_tests",
            "test_ids": ["INJ"],
            "status": "implemented",
            "notes": "Safe ATTSTRA_CANARY reflection; catalogue id INJ",
        },
        {
            "capability": "api_input_validation_replay",
            "module": "replay_checks",
            "test_ids": ["T21"],
            "status": "partial",
            "notes": "Quotes/long/wrong-type/XSS/path probes on captured GETs",
        },
        {
            "capability": "sql_nosql_command_ldap_template",
            "module": None,
            "test_ids": [],
            "status": "deferred",
            "notes": "No destructive injection campaigns",
        },
        {
            "capability": "ssrf_canary",
            "module": "ssrf_tests",
            "test_ids": ["SSRF"],
            "status": "partial",
            "notes": "Scoped URL-fetcher canary; blocked metadata hosts; target-environment policy (dev/demo) + flag",
        },
        {
            "capability": "server_side_sink_indicators",
            "module": "server_side_indicators",
            "test_ids": ["SSIND"],
            "status": "partial",
            "notes": "Passive SSRF/XXE/SSTI suspicion from captured traffic; never a confirmed finding",
        },
    ],
    "xss": [
        {
            "capability": "reflected_xss_canary",
            "module": "xss_tests",
            "test_ids": ["XSS"],
            "status": "implemented",
            "notes": "Quote-break canary; no stored writes; catalogue id XSS",
        },
        {
            "capability": "stored_dom_xss",
            "module": "xss_tests",
            "test_ids": ["XSSDOM", "XSSSTORE"],
            "status": "partial",
            "notes": "DOM sink source check + lab stored guestbook canary with cleanup",
        },
        {
            "capability": "open_redirect",
            "module": "open_redirect_tests",
            "test_ids": ["OREDIR"],
            "status": "implemented",
            "notes": "Redirect params to a non-routable marker; never followed off-site; off unless ATTESTRA_PROBES_WEB_SAFE=1",
        },
    ],
    "api_security": [
        {
            "capability": "missing_auth_and_excessive_data",
            "module": "api_security_tests",
            "test_ids": ["T07"],
            "status": "implemented",
            "notes": "Unauth API + directory exposure",
        },
        {
            "capability": "graphql_oauth_mass_assignment_rate_limit",
            "module": "graphql_tests",
            "test_ids": ["GRAPHQL", "APIPOST"],
            "status": "partial",
            "notes": "GraphQL introspection/field exposure + rate-limit headers; OAuth/mass-assignment still deferred",
        },
        {
            "capability": "graphql",
            "module": "graphql_tests",
            "test_ids": ["GRAPHQL"],
            "status": "implemented",
            "notes": "Detection + one bounded introspection; mutations never sent; off unless ATTESTRA_GRAPHQL_PROBE=1",
        },
        {
            "capability": "api_rate_limit_headers",
            "module": "api_posture_tests",
            "test_ids": ["APIPOST"],
            "status": "implemented",
            "notes": "Passive rate-limit / version header review",
        },
        {
            "capability": "api_spec_coverage",
            "module": "api_inventory",
            "test_ids": [],
            "status": "implemented",
            "notes": "OpenAPI/Swagger/Postman/HAR import; spec endpoint coverage in result_json.api_coverage; ATTESTRA_API_IMPORT_ENABLED=1",
        },
        {
            "capability": "oidc_metadata",
            "module": "oidc_metadata_tests",
            "test_ids": ["OIDCMETA"],
            "status": "partial",
            "notes": "One anonymous GET of the OIDC discovery document",
        },
    ],
    "business_logic": [
        {
            "capability": "owner_access_sanity",
            "module": "business_logic_tests",
            "test_ids": ["BIZ"],
            "status": "implemented",
            "notes": "Catalogue id BIZ: owner GET + foreign object deny; lab mock accounts",
        },
        {
            "capability": "multi_role_comparison",
            "module": "role_diff_tests",
            "test_ids": ["ROLEDIFF"],
            "status": "implemented",
            "notes": "Catalogue id ROLEDIFF: read-only account_a vs account_b compare",
        },
        {
            "capability": "workflow_approval_transaction_abuse",
            "module": None,
            "test_ids": [],
            "status": "deferred",
            "notes": "App-specific workflows",
        },
        {
            "capability": "guided_business_flows",
            "module": "attestra.automated_vapt.guided",
            "test_ids": [],
            "status": "deferred",
            "notes": "Guided manual plans (ATTESTRA_GUIDED_PLANS=1); tester records results, no automated sends",
        },
    ],
    "file_security": [
        {
            "capability": "path_traversal_content_proof",
            "module": "file_security_tests",
            "test_ids": ["FILE"],
            "status": "implemented",
            "notes": "Fake ....// probe; finding only with content markers; catalogue id FILE",
        },
        {
            "capability": "upload_file_inclusion",
            "module": "file_upload_tests",
            "test_ids": ["UPLOAD"],
            "status": "partial",
            "notes": "Safe HTML marker upload; ATTESTRA_AUTOMATED_VAPT_UPLOAD=1 + dev/demo asset + cleanup plan",
        },
    ],
    "infrastructure": [
        {
            "capability": "tls_headers_cors_dns_cdn",
            "module": "webcheck",
            "test_ids": [],
            "status": "partial",
            "notes": "Runner webcheck; disclosure observe_security_headers/observe_cors",
        },
        {
            "capability": "security_header_cors_observation",
            "module": "information_disclosure_tests",
            "test_ids": ["T07"],
            "status": "implemented",
            "notes": "Observation-only; does not set finding_candidate alone",
        },
        {
            "capability": "cors_validation",
            "module": "cors_tests",
            "test_ids": ["CORS"],
            "status": "implemented",
            "notes": "Origin variation + one preflight; finding only for credentialed cross-origin read; ATTESTRA_PROBES_WEB_SAFE=1",
        },
        {
            "capability": "host_header",
            "module": "host_header_tests",
            "test_ids": ["HOSTHDR"],
            "status": "implemented",
            "notes": "Host / X-Forwarded-Host to an .invalid marker; destination pinned; ATTESTRA_PROBES_WEB_SAFE=1",
        },
        {
            "capability": "cache_posture",
            "module": "cache_posture_tests",
            "test_ids": ["CACHE"],
            "status": "implemented",
            "notes": "Authenticated cache headers; ATTESTRA_PROBES_WEB_SAFE=1",
        },
    ],
    "disclosure": [
        {
            "capability": "sensitive_data_exposure",
            "module": "information_disclosure_tests",
            "test_ids": ["T07"],
            "status": "implemented",
            "notes": "Wraps api_security_tests; header/CORS observation-only",
        },
    ],
}


def list_phase3_categories() -> list[str]:
    return sorted(PHASE3_COVERAGE.keys())


def rows_for_category(category: str) -> list[dict[str, Any]]:
    return list(PHASE3_COVERAGE.get((category or "").strip().lower()) or [])


def implemented_test_ids() -> list[str]:
    """Unique catalogue/helper ids marked implemented or partial."""
    out: list[str] = []
    seen: set[str] = set()
    for rows in PHASE3_COVERAGE.values():
        for row in rows:
            if row.get("status") not in {"implemented", "partial"}:
                continue
            for tid in row.get("test_ids") or []:
                key = str(tid).upper()
                if key not in seen:
                    seen.add(key)
                    out.append(str(tid))
    return out


def deferred_capabilities() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for category, items in PHASE3_COVERAGE.items():
        for row in items:
            if row.get("status") == "deferred":
                rows.append({"category": category, **row})
    return rows


def injection_catalog_rows() -> list[dict[str, Any]]:
    """WP2 B-05 injection catalogue rows (own vocabulary: ``assessed`` / ``not_assessed``).

    Rendered separately from :data:`PHASE3_COVERAGE` so its status vocabulary stays
    ``implemented | partial | deferred`` (INT decision).
    """
    from attestra.automated_vapt.testing.injection_catalog import coverage_rows

    return coverage_rows()
