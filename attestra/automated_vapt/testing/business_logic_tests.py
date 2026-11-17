"""Business-logic catalogue case (BIZ): owner access + safe order/replay sanity.

Read-only GETs only. Expands beyond a single owner GET to confirm the caller's
own object succeeds and a foreign object is denied (or flagged when exposed).
"""

from __future__ import annotations

from typing import Any

from attestra.automated_vapt.core.response_classifier import (
    ResponseClass,
    classify_pair,
    is_blocking,
    samples_to_json,
    skip_reason_for,
)
from attestra.automated_vapt.testing._http import absolute, clear_cookies, login, request_json, request_pair
from attestra.automated_vapt.testing._session import (
    SKIP_NO_AUTH_SESSION,
    is_substantive_json,
    parse_json,
    probe_urls,
    ready_auth,
    request_auth,
    resolve_mode,
    scrub_pair,
    skip_result,
)
from attestra.automated_vapt.testing.tenant_isolation_tests import compare_identities, identity_values

# @lat: [[architecture#Elite automated security testing#Authz test modules]]

SKIP_LOGIN_FAILED = "biz_login_failed"


def _login_ok(client, base_url: str, user: str, password: str) -> bool:
    clear_cookies(client)
    try:
        code = login(client, base_url, user, password)
    except Exception:
        return False
    return int(code or 0) in (200, 302, 303)


def _run_with_session(client, base_url: str, auth: Any, **kwargs) -> dict[str, Any]:
    """Confirm the engagement session can read in-scope resources (read-only).

    D-04: "owner access works" needs an application ``APP_OK`` answer; WAF / challenge /
    expired-session answers make the case BLOCKED and a plain denial INCONCLUSIVE,
    never a finding. Foreign exposure is flagged only when the secondary profile sees
    identity values (tenant / owner keys) that only the primary sees elsewhere,
    i.e. a proven different identity, not merely an identical shared body.
    """
    urls = probe_urls(base_url, kwargs, api=True, limit=6)
    if not urls:
        urls = probe_urls(base_url, kwargs, api=False, limit=6)
    secondary = ready_auth(kwargs, "_secondary_session_auth")
    evidence: list[Any] = []
    rows: list[dict[str, Any]] = []
    samples = []
    owner_ok = False
    owner_status = None
    foreign_status = None
    value_rows: list[tuple[set[str], set[str]]] = []
    others: list[Any] = []
    for url in urls:
        pair = request_auth(client, "GET", url, auth, base_url)
        c = classify_pair(pair, authed=True)
        samples.append(c)
        status = int(pair.status or 0)
        if owner_status is None:
            owner_status = status
        if c.cls is ResponseClass.APP_OK:
            owner_ok = True
        rows.append({"url": url, "primary_status": status, "primary_class": c.cls.value})
        if secondary is not None:
            other = request_auth(client, "GET", url, secondary, base_url)
            oc = classify_pair(other, authed=True)
            samples.append(oc)
            ostatus = int(other.status or 0)
            foreign_status = ostatus if foreign_status is None else foreign_status
            a_sub = c.cls is ResponseClass.APP_OK and is_substantive_json(status, pair.response_body)
            b_sub = oc.cls is ResponseClass.APP_OK and is_substantive_json(ostatus, other.response_body)
            same = a_sub and b_sub and (pair.response_body or "").strip() == (other.response_body or "").strip()
            value_rows.append(
                (
                    set(identity_values(parse_json(pair.response_body) if a_sub else None)),
                    set(identity_values(parse_json(other.response_body) if b_sub else None)),
                )
            )
            others.append(other)
            rows[-1]["secondary_status"] = ostatus
            rows[-1]["secondary_class"] = oc.cls.value
            rows[-1]["same_body"] = same
    cmp = compare_identities(value_rows) if value_rows else {"distinct_identities": False, "cross_rows": []}
    for i in cmp["cross_rows"]:
        rows[i]["foreign_exposed"] = True
        evidence.append(scrub_pair(others[i], auth, secondary))
    foreign_exposed = bool(cmp["cross_rows"])
    result: dict[str, Any] = {
        "test_id": "BIZ",
        "category": "authorization",
        "observations": {
            "mode": "engagement_session",
            "owner_access_ok": owner_ok,
            "owner_status": owner_status,
            "foreign_status": foreign_status,
            "foreign_exposed": foreign_exposed,
            "foreign_assessed": secondary is not None,
            "distinct_identities": cmp["distinct_identities"],
            "probes": rows,
        },
        "finding_candidate": foreign_exposed,
        "evidence_pairs": evidence,
        "evidence_hints": [f"GET {u} with engagement session" for u in urls],
        "validity_samples": samples_to_json(samples),
    }
    if not foreign_exposed and owner_ok and any(is_blocking(x) for x in samples):
        result["status_hint"] = "BLOCKED"
        result["skip_reason"] = skip_reason_for(samples)
    elif not foreign_exposed and not owner_ok:
        # Pre-D-04 this was a finding; an unusable session is not a vulnerability.
        result["status_hint"] = "BLOCKED" if any(is_blocking(x) or x.cls is ResponseClass.AUTH_EXPIRED for x in samples) else "INCONCLUSIVE"
        result["skip_reason"] = skip_reason_for(samples) if result["status_hint"] == "BLOCKED" else "owner_access_not_proven"
    return result


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    mode, auth = resolve_mode(client, kwargs)
    if mode == "engagement":
        return _run_with_session(client, base_url, auth, **kwargs)
    if mode == "skip":
        return skip_result(
            "BIZ",
            "authorization",
            SKIP_NO_AUTH_SESSION,
            "engagement login profile not ready; skipped lab account_a business-logic probes",
        )

    if not _login_ok(client, base_url, "account_a", "account-a-pass"):
        return {
            "test_id": "BIZ",
            "category": "authorization",
            "status_hint": "SKIPPED",
            "skip_reason": SKIP_LOGIN_FAILED,
            "observations": {"detail": "mock account_a login failed; engagement profiles not used for BIZ yet"},
            "finding_candidate": False,
            "evidence_hints": [],
        }

    own_status, own_body, _ = request_json(client, "GET", absolute(base_url, "/api/projects/proj-a"))
    owner_ok = own_status == 200 and isinstance(own_body, dict) and (
        own_body.get("id") == "proj-a" or own_body.get("projectId") == "proj-a"
    )

    # Safe order/replay: foreign object GET must not return the other owner's record.
    foreign_pair = request_pair(client, "GET", absolute(base_url, "/api/projects/proj-b"))
    foreign_status = int(foreign_pair.status or 0)
    foreign_body: Any = None
    try:
        import json

        foreign_body = json.loads(foreign_pair.response_body) if foreign_pair.response_body else None
    except Exception:
        foreign_body = None
    foreign_exposed = foreign_status == 200 and isinstance(foreign_body, dict) and (
        foreign_body.get("id") == "proj-b"
        or foreign_body.get("projectId") == "proj-b"
        or foreign_body.get("owner") == "account_b"
    )

    evidence = [foreign_pair] if foreign_exposed else []
    finding = (not owner_ok) or foreign_exposed
    return {
        "test_id": "BIZ",
        "category": "authorization",
        "observations": {
            "owner_access_ok": owner_ok,
            "owner_status": own_status,
            "foreign_status": foreign_status,
            "foreign_exposed": foreign_exposed,
        },
        "finding_candidate": finding,
        "evidence_pairs": evidence,
        "evidence_hints": [
            "GET /api/projects/proj-a as owner",
            "GET /api/projects/proj-b as owner (must deny)",
        ],
    }
