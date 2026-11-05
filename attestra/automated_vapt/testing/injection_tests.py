"""SAFE reflected injection-surface probes (World-Class Phase 3).

Sends a few benign ``ATTSTRA_CANARY_*`` query values on common endpoints and flags
``finding_candidate`` only when the canary is clearly reflected **unencoded in an
HTML context**. No time-based SQLi, no destructive commands, no LDAP/OS execution.

Catalogue mapping: not wired into the orchestrator — no deferred catalogue IDs for
injection. Related API input checks live under catalogue ``T21``
([[attestra/automated_vapt/core/replay_checks.py]]). Call [[run]] directly or from a
future catalogue handler.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

from attestra.automated_vapt.testing._http import absolute, request_pair
from attestra.automated_vapt.testing._reflection import (
    detect_unencoded_reflection,
    injection_canary_payload,
    is_html_body,
    new_canary,
    reflected_unencoded_in_html,
    reflection_in_headers,
)

# @lat: [[architecture#Elite automated security testing#Safe non-destructive probes]]

# Few requests only — path + single query param each.
_DEFAULT_PROBES: tuple[tuple[str, str], ...] = (
    ("/", "q"),
    ("/search", "q"),
    ("/q", "query"),
    ("/api/search", "q"),
)
_MAX_PROBES = 4


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    """Probe common endpoints with a benign canary; max a few GETs."""
    probes = list(kwargs.get("probes") or _DEFAULT_PROBES)[:_MAX_PROBES]
    marker = new_canary(tag="INJ")
    payload = injection_canary_payload(marker)

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
        in_body = detect_unencoded_reflection(payload, body) or detect_unencoded_reflection(
            marker, body
        )
        header_hits = reflection_in_headers(payload, pair.response_headers) or reflection_in_headers(
            marker, pair.response_headers
        )
        html_ctx = is_html_body(body, ctype)
        unencoded_html = reflected_unencoded_in_html(payload, body, content_type=ctype) or (
            reflected_unencoded_in_html(marker, body, content_type=ctype)
        )
        row = {
            "path": path,
            "param": param,
            "status": pair.status,
            "reflected_body": in_body,
            "reflected_headers": header_hits,
            "html_context": html_ctx,
            "unencoded_html": unencoded_html,
        }
        observations.append(row)
        if unencoded_html and not finding:
            finding = True
            finding_detail = f"canary reflected unencoded in HTML at {path}?{param}="
            evidence.append(pair)

    return {
        "test_id": "INJ",
        "category": "injection",
        "observations": {
            "canary": marker,
            "payload": payload,
            "probes": observations,
            "probe_count": len(observations),
        },
        "finding_candidate": finding,
        "detail": finding_detail or "no unencoded HTML canary reflection",
        "evidence_hints": [f"GET {p}?{param}=ATTSTRA_CANARY_*" for p, param in probes],
        "evidence_pairs": evidence,
    }
