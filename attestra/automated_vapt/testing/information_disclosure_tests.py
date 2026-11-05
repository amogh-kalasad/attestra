"""Sensitive data exposure + light security-header / CORS observation.

Wraps [[attestra/automated_vapt/testing/api_security_tests.py#run]] for excessive
data exposure (``T07``). Also records security-header presence and CORS
``Access-Control-*`` values from a single base GET — **observation only**; missing
headers alone do not set ``finding_candidate``.

Catalogue: orchestrator wires ``T07`` to ``api_security_tests``; this module remains
a disclosure-oriented entry point (same ``finding_candidate`` as the API probe).
"""

from __future__ import annotations

from typing import Any

from attestra.automated_vapt.testing._http import absolute, request_pair
from attestra.automated_vapt.testing.api_security_tests import run as run_api

# @lat: [[architecture#Elite automated security testing#Authz test modules]]
# @lat: [[architecture#Elite automated security testing#Safe non-destructive probes]]

_SECURITY_HEADERS: tuple[str, ...] = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)


def observe_security_headers(headers: dict[str, Any] | None) -> dict[str, Any]:
    """Snapshot which common security headers are present (pure / observation)."""
    lower = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    present = {name: lower[name] for name in _SECURITY_HEADERS if name in lower}
    missing = [name for name in _SECURITY_HEADERS if name not in lower]
    return {"present": present, "missing": missing}


def observe_cors(headers: dict[str, Any] | None) -> dict[str, Any]:
    """Record CORS response headers without classifying a finding (pure helper)."""
    lower = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    acao = lower.get("access-control-allow-origin")
    acac = lower.get("access-control-allow-credentials")
    acah = lower.get("access-control-allow-headers")
    acam = lower.get("access-control-allow-methods")
    return {
        "access_control_allow_origin": acao,
        "access_control_allow_credentials": acac,
        "access_control_allow_headers": acah,
        "access_control_allow_methods": acam,
        "wildcard_origin": acao == "*",
        "credentials_with_wildcard": acao == "*" and (acac or "").lower() == "true",
    }


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    result = run_api(client, base_url, **kwargs)
    result["test_id"] = "T07"
    result["category"] = "disclosure"

    pair = request_pair(client, "GET", absolute(base_url, "/"), follow_redirects=False)
    hdr_obs = observe_security_headers(pair.response_headers)
    cors_obs = observe_cors(pair.response_headers)
    obs = dict(result.get("observations") or {})
    obs["security_headers"] = hdr_obs
    obs["cors"] = cors_obs
    obs["base_get_status"] = pair.status
    result["observations"] = obs
    hints = list(result.get("evidence_hints") or [])
    hints.append("GET / (security-header / CORS observation)")
    result["evidence_hints"] = hints
    # Header/CORS snapshot is observation-only; finding_candidate stays from API probe.
    return result
