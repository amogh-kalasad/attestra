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
            "module": None,
            "test_ids": [],
            "status": "deferred",
            "notes": "Needs pre-login cookie injection fixture",
        },
        {
            "capability": "session_expiration_invalidation_rotation",
            "module": None,
            "test_ids": [],
            "status": "deferred",
            "notes": "Requires timed logout/refresh endpoints",
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
            "notes": "Scoped URL-fetcher canary; blocked metadata hosts; local/test/dev gated",
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
            "module": None,
            "test_ids": ["T21"],
            "status": "deferred",
            "notes": "T21 may tip XSS payloads; stored/DOM deferred",
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
            "module": None,
            "test_ids": [],
            "status": "deferred",
            "notes": "Target-specific; not in default catalogue",
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
            "notes": "Safe HTML marker upload; local/test/dev or ATTESTRA_AUTOMATED_VAPT_UPLOAD=1",
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
