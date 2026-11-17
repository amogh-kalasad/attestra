"""SAFE reflected injection-surface probes (World-Class Phase 3).

Sends a few benign ``ATTSTRA_CANARY_*`` query values on common endpoints and flags
``finding_candidate`` only when the canary is clearly reflected **unencoded in an
HTML context**. No time-based SQLi, no destructive commands, no LDAP/OS execution.

Each probe row also carries its [[attestra/automated_vapt/testing/injection_catalog.py]]
check id, payload class, location and tier, plus an ``outcome`` from
[[attestra/automated_vapt/testing/injection_catalog.py#classify_outcome]] (reflected /
error_signature / filtered / not_reflected / blocked / inconclusive). Every response is
classified (FND-01) into ``validity_samples``; a run whose probes were all answered by a
WAF / challenge / 429 gets ``status_hint`` BLOCKED instead of a silent pass.

Catalogue mapping: not wired into the orchestrator — no deferred catalogue IDs for
injection. Related API input checks live under catalogue ``T21``
([[attestra/automated_vapt/core/replay_checks.py]]). Call [[run]] directly or from a
future catalogue handler.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlencode

from attestra.automated_vapt.testing import injection_catalog as _catalog
from attestra.automated_vapt.testing._http import absolute, request_pair
from attestra.automated_vapt.testing._probe_base import class_name, classify, status_from_samples
from attestra.automated_vapt.testing._reflection import (
    detect_unencoded_reflection,
    injection_canary_payload,
    is_html_body,
    new_canary,
    reflected_unencoded_in_html,
    reflection_in_headers,
)
from attestra.automated_vapt.testing._session import (
    SKIP_NO_AUTH_SESSION,
    probe_urls,
    request_auth,
    resolve_mode,
    skip_result,
)

# @lat: [[architecture#Elite automated security testing#Safe non-destructive probes]]
# @lat: [[web-api-probes#Injection catalogue]]

# Few requests only — path + single query param each.
_DEFAULT_PROBES: tuple[tuple[str, str], ...] = (
    ("/", "q"),
    ("/search", "q"),
    ("/q", "query"),
    ("/api/search", "q"),
)
_MAX_PROBES = 4

# Boolean-safe error signatures only — never time-based, never destructive SQL.
_ERROR_SIG_RE = re.compile(
    r"(?i)(SQLSTATE|ORA-\d{5}|syntax error at|pg_query|mysql_fetch|"
    r"Uncaught (?:PDO|mysqli)|SQLException|OLE DB|ODBC Driver|"
    r"quoted string not properly terminated)"
)
_BOOLEAN_PAYLOADS: tuple[str, ...] = (
    "'",
    "\"",
    "' OR '1'='1",
    "1' AND '1'='2",
)


def _target_url(base_url: str, path: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return absolute(base_url, path)


def _engagement_probes(base_url: str, kwargs: dict[str, Any]) -> list[tuple[str, str]]:
    urls = probe_urls(base_url, kwargs, api=False, limit=_MAX_PROBES)
    return [(u, "q") for u in urls] or list(_DEFAULT_PROBES)[:_MAX_PROBES]


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    """Probe common endpoints with a benign canary plus boolean-safe error checks."""
    mode, auth = resolve_mode(client, kwargs)
    if mode == "skip":
        return skip_result(
            "INJ",
            "injection",
            SKIP_NO_AUTH_SESSION,
            "engagement login profile not ready; skipped default /search lab probes",
        )
    if kwargs.get("probes"):
        probes = list(kwargs.get("probes") or _DEFAULT_PROBES)[:_MAX_PROBES]
    elif mode == "engagement":
        probes = _engagement_probes(base_url, kwargs)[:_MAX_PROBES]
    else:
        probes = list(_DEFAULT_PROBES)[:_MAX_PROBES]
    marker = new_canary(tag="INJ")
    payload = injection_canary_payload(marker)
    boolean_on = kwargs.get("boolean_canaries", True)

    observations: list[dict[str, Any]] = []
    evidence = []
    samples: list[Any] = []
    statuses: list[int | None] = []
    reflect_check = _catalog.get("INJ-REFLECT-QUERY")
    bool_check = _catalog.get("INJ-SQLBOOL-QUERY")

    def _classify(pair) -> str:
        c = classify(pair.status, pair.response_headers, pair.response_body or "", authed=auth is not None)
        samples.append(c)
        statuses.append(pair.status)
        return class_name(c)
    finding = False
    finding_detail = ""

    def _get(full: str):
        if auth is not None:
            return request_auth(client, "GET", full, auth, base_url, follow_redirects=False)
        return request_pair(client, "GET", full, follow_redirects=False)

    for path, param in probes:
        qs = urlencode({param: payload})
        url = _target_url(base_url, path)
        sep = "&" if "?" in url else "?"
        full = f"{url}{sep}{qs}"
        pair = _get(full)
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
        error_sig = bool(_ERROR_SIG_RE.search(body))
        rclass = _classify(pair)
        outcome = _catalog.classify_outcome(
            rclass,
            reflected_unencoded=bool(unencoded_html),
            error_signature=error_sig,
            marker_present_encoded=(marker in body) and not detect_unencoded_reflection(payload, body),
            reflected_non_html=detect_unencoded_reflection(payload, body) and not unencoded_html,
        )
        row = {
            "path": path,
            "param": param,
            "status": pair.status,
            "reflected_body": in_body,
            "reflected_headers": header_hits,
            "html_context": html_ctx,
            "unencoded_html": unencoded_html,
            "error_signature": error_sig,
            "check_id": reflect_check.check_id if reflect_check else "INJ-REFLECT-QUERY",
            "payload_class": reflect_check.payload_class if reflect_check else "reflection_canary",
            "location": "query",
            "tier": reflect_check.tier if reflect_check else "T1",
            "response_class": rclass,
            "outcome": outcome,
        }
        observations.append(row)
        if unencoded_html and not finding:
            finding = True
            finding_detail = f"canary reflected unencoded in HTML at {path}?{param}="
            evidence.append(pair)
        elif error_sig and not finding:
            finding = True
            finding_detail = f"boolean-safe injection error signature at {path}?{param}="
            evidence.append(pair)

    # One extra boolean-safe payload per first probe only (cap total requests).
    # Skip the boolean pair when the first probes were already blocked by the edge.
    edge_blocked = any(class_name(c) in ("waf_block", "challenge", "rate_limited") for c in samples)
    if boolean_on and probes and not finding and not edge_blocked:
        path, param = probes[0]
        for bp in _BOOLEAN_PAYLOADS[:2]:
            qs = urlencode({param: bp})
            url = _target_url(base_url, path)
            sep = "&" if "?" in url else "?"
            full = f"{url}{sep}{qs}"
            pair = _get(full)
            body = pair.response_body or ""
            bclass = _classify(pair)
            if bclass in ("waf_block", "challenge", "rate_limited"):
                break
            if _ERROR_SIG_RE.search(body):
                finding = True
                finding_detail = f"boolean-safe error signature for payload at {path}?{param}="
                evidence.append(pair)
                observations.append(
                    {
                        "path": path,
                        "param": param,
                        "status": pair.status,
                        "boolean_payload": bp,
                        "error_signature": True,
                        "check_id": bool_check.check_id if bool_check else "INJ-SQLBOOL-QUERY",
                        "payload_class": "sql_error_boolean",
                        "location": "query",
                        "tier": bool_check.tier if bool_check else "T1",
                        "response_class": bclass,
                        "outcome": "error_signature",
                    }
                )
                break

    hint = status_from_samples(samples, finding=finding, statuses=statuses)
    result: dict[str, Any] = {
        "test_id": "INJ",
        "category": "injection",
        "observations": {
            "canary": marker,
            "payload": payload,
            "probes": observations,
            "probe_count": len(observations),
            "boolean_canaries": boolean_on,
            "catalog_version": _catalog.CATALOG_VERSION,
            "outcomes": sorted({str(r.get("outcome")) for r in observations if r.get("outcome")}),
            "coverage": _catalog.coverage_rows(),
        },
        "finding_candidate": finding,
        "detail": finding_detail or "no unencoded HTML canary reflection",
        "evidence_hints": [f"GET {p}?{param}=ATTSTRA_CANARY_*" for p, param in probes],
        "evidence_pairs": evidence,
        "validity_samples": samples,
    }
    if hint in ("BLOCKED", "INCONCLUSIVE"):
        result["status_hint"] = hint
    return result
