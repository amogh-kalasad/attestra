"""SAFE reflected XSS canary probes (World-Class Phase 3).

Places a unique marker (quote-break shape, no stored writes, no alert()) in a query
param and flags ``finding_candidate`` only when the payload is reflected unencoded
in an HTML context. DOM/browser automation is optional and not required.

Catalogue mapping: not wired into the orchestrator — no deferred catalogue IDs for
XSS. Catalogue ``T21`` replays a script-tag payload via
[[attestra/automated_vapt/core/replay_checks.py]]; this module is a standalone safe
reflected-XSS canary. Call [[run]] directly or from a future catalogue handler.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

from attestra.automated_vapt.testing._http import absolute, request_pair
from attestra.automated_vapt.testing._reflection import (
    detect_unencoded_reflection,
    is_html_body,
    new_canary,
    reflected_unencoded_in_html,
    xss_canary_payload,
)

# @lat: [[architecture#Elite automated security testing#Safe non-destructive probes]]

_DEFAULT_PROBES: tuple[tuple[str, str], ...] = (
    ("/", "q"),
    ("/search", "q"),
    ("/q", "query"),
)
_MAX_PROBES = 3


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    """Reflected XSS canary on a few query endpoints (no stored XSS writes)."""
    probes = list(kwargs.get("probes") or _DEFAULT_PROBES)[:_MAX_PROBES]
    marker = new_canary(tag="XSS")
    payload = xss_canary_payload(marker)

    observations: list[dict[str, Any]] = []
    evidence = []
    finding = False
    finding_detail = ""

    for path, param in probes:
        qs = urlencode({param: payload})
        url = absolute(base_url, path)
        sep = "&" if "?" in url else "?"
        full = f"{url}{sep}{qs}"
        pair = request_pair(client, "GET", full, follow_redirects=False)
        ctype = ""
        for hk, hv in (pair.response_headers or {}).items():
            if hk.lower() == "content-type":
                ctype = hv
                break
        body = pair.response_body or ""
        # Prefer full payload reflection; marker alone is weaker but still noted.
        full_hit = reflected_unencoded_in_html(payload, body, content_type=ctype)
        marker_hit = reflected_unencoded_in_html(marker, body, content_type=ctype)
        unencoded_html = full_hit or marker_hit
        row = {
            "path": path,
            "param": param,
            "status": pair.status,
            "payload_reflected": detect_unencoded_reflection(payload, body),
            "marker_reflected": detect_unencoded_reflection(marker, body),
            "html_context": is_html_body(body, ctype),
            "unencoded_html": unencoded_html,
            "full_payload_unencoded": full_hit,
        }
        observations.append(row)
        if unencoded_html and not finding:
            finding = True
            finding_detail = f"XSS canary reflected unencoded in HTML at {path}?{param}="
            evidence.append(pair)

    return {
        "test_id": "XSS",
        "category": "xss",
        "observations": {
            "canary": marker,
            "payload": payload,
            "probes": observations,
            "probe_count": len(observations),
        },
        "finding_candidate": finding,
        "detail": finding_detail or "no unencoded HTML XSS canary reflection",
        "evidence_hints": [f"GET {p}?{param}=XSS-canary" for p, param in probes],
        "evidence_pairs": evidence,
    }
