"""Passive OIDC / OAuth metadata review (D-03, case id ``OIDCMETA``).

Exactly one GET to ``/.well-known/openid-configuration`` on the target's own origin
(or an in-scope discovery URL the engagement supplied in
``ctx.extra["_oidc_discovery_url"]`` that is same-origin with the target or its API
base). No authentication attempt, no client registration, no token request.
Missing discovery is "not assessed", never PASSED.
"""

# @lat: [[run-validity-and-policy#OIDC metadata]]

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from attestra.automated_vapt.core.response_classifier import (
    ResponseClass,
    classify_pair,
    is_blocking,
    samples_to_json,
    skip_reason_for,
)

TEST_ID = "OIDCMETA"
CATEGORY = "authentication"
WELL_KNOWN = "/.well-known/openid-configuration"
SKIP_ABSENT = "oidc_discovery_absent"
SKIP_OUT_OF_SCOPE = "oidc_discovery_out_of_scope"

SEV_HIGH = "high"
SEV_MEDIUM = "medium"
SEV_LOW = "low"


def _origin(url: str) -> str:
    p = urlsplit(url or "")
    return f"{(p.scheme or '').lower()}://{(p.netloc or '').lower()}"


def discovery_url(base_url: str, ctx: Any | None = None) -> tuple[str | None, str]:
    """``(url, reason)``: the single URL to GET, or ``None`` when out of scope."""
    extra = (getattr(ctx, "extra", None) or {}) if ctx is not None else {}
    custom = str(extra.get("_oidc_discovery_url") or "").strip()
    allowed = {_origin(base_url)}
    api_root = str(extra.get("_api_base_url") or "").strip()
    if api_root:
        allowed.add(_origin(api_root))
    if custom:
        if _origin(custom) in allowed:
            return custom, "engagement_supplied"
        return None, SKIP_OUT_OF_SCOPE
    return _origin(base_url) + WELL_KNOWN, "target_origin"


def review_metadata(meta: dict[str, Any], *, target_origin: str = "") -> dict[str, Any]:
    """Pure review of a discovery document. Returns issues (codes + severities) only."""
    issues: list[dict[str, str]] = []

    def issue(code: str, sev: str, detail: str) -> None:
        issues.append({"code": code, "severity": sev, "detail": detail})

    rts = [str(x) for x in (meta.get("response_types_supported") or [])]
    implicit = [r for r in rts if r.split() and "code" not in r.split() and set(r.split()) <= {"token", "id_token"}]
    if implicit:
        issue("implicit_flow_advertised", SEV_MEDIUM, "response_types_supported includes token (implicit) flows")
    grants = [str(x) for x in (meta.get("grant_types_supported") or [])]
    if "implicit" in grants:
        issue("implicit_grant_advertised", SEV_MEDIUM, "grant_types_supported includes implicit")
    if "password" in grants:
        issue("ropc_grant_advertised", SEV_MEDIUM, "grant_types_supported includes password (ROPC)")
    pkce = [str(x) for x in (meta.get("code_challenge_methods_supported") or [])]
    if "S256" not in pkce:
        issue("pkce_s256_not_advertised", SEV_MEDIUM, "code_challenge_methods_supported lacks S256")
    if "plain" in pkce:
        issue("pkce_plain_allowed", SEV_LOW, "PKCE plain method advertised")
    for key in ("redirect_uris", "allowed_redirect_uris", "post_logout_redirect_uris"):
        vals = meta.get(key)
        if isinstance(vals, list) and any("*" in str(v) for v in vals):
            issue("wildcard_redirect_metadata", SEV_HIGH, f"{key} contains a wildcard")
    auth_methods = [str(x) for x in (meta.get("token_endpoint_auth_methods_supported") or [])]
    if "none" in auth_methods:
        issue("public_client_token_auth", SEV_LOW, "token endpoint accepts auth method none (public clients)")
    algs = [str(x) for x in (meta.get("id_token_signing_alg_values_supported") or [])]
    if any(a.lower() == "none" for a in algs):
        issue("id_token_alg_none", SEV_HIGH, "id_token_signing_alg_values_supported includes none")
    for key in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint"):
        v = str(meta.get(key) or "")
        if v.startswith("http://") and urlsplit(v).hostname not in ("localhost", "127.0.0.1"):
            issue("non_tls_endpoint", SEV_HIGH, f"{key} uses http://")
    issuer = str(meta.get("issuer") or "")
    if not issuer:
        issue("missing_issuer", SEV_LOW, "no issuer")
    if meta.get("request_uri_parameter_supported") is True and meta.get("require_request_uri_registration") is False:
        issue("request_uri_unregistered", SEV_LOW, "request_uri accepted without registration")
    sevs = [i["severity"] for i in issues]
    return {
        "issues": issues,
        "finding": SEV_HIGH in sevs or SEV_MEDIUM in sevs,
        "issuer_same_origin": bool(issuer) and bool(target_origin) and _origin(issuer) == target_origin,
        "response_types_supported": rts,
        "grant_types_supported": grants,
        "code_challenge_methods_supported": pkce,
        "implicit_like": sorted(set(implicit)),
    }


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    """OIDCMETA: one anonymous GET of the discovery document, then an offline review."""
    from attestra.automated_vapt.testing._session import request_plain

    ctx = kwargs.get("ctx")
    url, why = discovery_url(base_url, ctx)
    if url is None:
        return {
            "test_id": TEST_ID, "category": CATEGORY, "status_hint": "NOT_TESTED", "skip_reason": why,
            "observations": {"detail": "supplied discovery URL is not on the target/API origin"},
            "finding_candidate": False, "evidence_hints": [], "validity_samples": [],
        }
    try:
        pair = request_plain(client, "GET", url)
    except Exception as exc:  # noqa: BLE001
        return {
            "test_id": TEST_ID, "category": CATEGORY, "status_hint": "INCONCLUSIVE", "skip_reason": "network_failed",
            "observations": {"detail": f"discovery GET failed ({type(exc).__name__})"},
            "finding_candidate": False, "evidence_hints": [], "validity_samples": [{"cls": "network_failed", "reasons": ["network_error"], "confidence": 1.0}],
        }
    c = classify_pair(pair)
    samples = [c]
    base = {"test_id": TEST_ID, "category": CATEGORY, "validity_samples": samples_to_json(samples)}
    if is_blocking(c):
        return {**base, "status_hint": "BLOCKED", "skip_reason": skip_reason_for(samples),
                "observations": {"url": url, "status": pair.status, "response_class": c.cls.value},
                "finding_candidate": False, "evidence_hints": []}
    meta = None
    if c.cls is ResponseClass.APP_OK:
        try:
            meta = json.loads(pair.response_body or "")
        except ValueError:
            meta = None
    if not isinstance(meta, dict) or not (meta.get("issuer") or meta.get("authorization_endpoint")):
        return {**base, "status_hint": "NOT_TESTED", "skip_reason": SKIP_ABSENT,
                "observations": {"url": url, "status": pair.status, "response_class": c.cls.value,
                                 "detail": "no OIDC discovery document; OAuth/OIDC posture not assessed"},
                "finding_candidate": False, "evidence_hints": [f"GET {WELL_KNOWN}"]}
    review = review_metadata(meta, target_origin=_origin(base_url))
    return {
        **base,
        "observations": {"url": url, "source": why, "status": pair.status, **review},
        "finding_candidate": review["finding"],
        "detail": ", ".join(i["code"] for i in review["issues"]) or "OIDC metadata advertises code+PKCE S256 only",
        "evidence_pairs": [pair] if review["finding"] else [],
        "evidence_hints": [f"GET {WELL_KNOWN}"],
    }
