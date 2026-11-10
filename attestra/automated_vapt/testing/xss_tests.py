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

import re
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
from attestra.automated_vapt.testing._session import (
    SKIP_NO_AUTH_SESSION,
    probe_urls,
    request_auth,
    resolve_mode,
    skip_result,
)

# @lat: [[architecture#Elite automated security testing#Safe non-destructive probes]]

_DEFAULT_PROBES: tuple[tuple[str, str], ...] = (
    ("/", "q"),
    ("/search", "q"),
    ("/q", "query"),
)
_MAX_PROBES = 3


def _target_url(base_url: str, path: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return absolute(base_url, path)


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    """Dispatch reflected / DOM / stored XSS modes (default: reflected)."""
    mode = str(kwargs.get("mode") or "reflected").strip().lower()
    if mode in {"dom", "xssdom"}:
        return run_dom(client, base_url, **kwargs)
    if mode in {"stored", "store", "xssstore", "xssstored"}:
        return run_stored(client, base_url, **kwargs)
    return run_reflected(client, base_url, **kwargs)


def run_reflected(client, base_url: str, **kwargs) -> dict[str, Any]:
    """Reflected XSS canary on a few query endpoints (no stored XSS writes)."""
    sess_mode, auth = resolve_mode(client, kwargs)
    if sess_mode == "skip":
        return skip_result(
            "XSS",
            "xss",
            SKIP_NO_AUTH_SESSION,
            "engagement login profile not ready; skipped default /search XSS probes",
        )
    if kwargs.get("probes"):
        probes = list(kwargs.get("probes") or _DEFAULT_PROBES)[:_MAX_PROBES]
    elif sess_mode == "engagement":
        probes = [(u, "q") for u in probe_urls(base_url, kwargs, api=False, limit=_MAX_PROBES)]
        probes = probes or list(_DEFAULT_PROBES)[:_MAX_PROBES]
    else:
        probes = list(_DEFAULT_PROBES)[:_MAX_PROBES]
    marker = new_canary(tag="XSS")
    payload = xss_canary_payload(marker)

    observations: list[dict[str, Any]] = []
    evidence = []
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
            "mode": "reflected",
        },
        "finding_candidate": finding,
        "detail": finding_detail or "no unencoded HTML XSS canary reflection",
        "evidence_hints": [f"GET {p}?{param}=XSS-canary" for p, param in probes],
        "evidence_pairs": evidence,
    }


_DOM_SINK_RE = re.compile(
    r"(?i)("
    r"innerHTML\s*=\s*[^;]*(location\.hash|location\.search|document\.URL|decodeURIComponent)|"
    r"document\.write\s*\(\s*(location|decodeURIComponent)|"
    r"location\.hash[\s\S]{0,120}?innerHTML"
    r")"
)


def run_dom(client, base_url: str, **kwargs) -> dict[str, Any]:
    """DOM XSS: detect dangerous sinks in page source; optional Playwright evaluate.

    Without Playwright, finding_candidate is True only when the page source shows a
    classic location→innerHTML/document.write sink (lab positive control). Secure
    pages that use textContent do not match.
    """
    sess_mode, auth = resolve_mode(client, kwargs)
    if sess_mode == "skip":
        return skip_result(
            "XSSDOM",
            "xss",
            SKIP_NO_AUTH_SESSION,
            "engagement login profile not ready; skipped lab /dom-sink probes",
        )
    path = str(kwargs.get("path") or "/dom-sink")
    if sess_mode == "engagement" and not kwargs.get("path"):
        urls = probe_urls(base_url, kwargs, api=False, limit=1)
        url = urls[0] if urls else _target_url(base_url, path)
        path = url
    else:
        url = _target_url(base_url, path)
    if auth is not None:
        pair = request_auth(client, "GET", url, auth, base_url, follow_redirects=False)
    else:
        pair = request_pair(client, "GET", url, follow_redirects=False)
    body = pair.response_body or ""
    sink = bool(_DOM_SINK_RE.search(body))
    ctx = kwargs.get("ctx")
    capture_fn = kwargs.get("capture_fn")
    if capture_fn is None and ctx is not None:
        capture_fn = (getattr(ctx, "extra", {}) or {}).get("capture_fn")
    browser_hit = False
    marker = new_canary(tag="DOM")
    if capture_fn is not None:
        # Injectable browser hook for tests: returns page content after navigation.
        try:
            content = capture_fn(f"{url}#{marker}")
            browser_hit = marker in (content or "") and ("<" + marker) in (content or "")
        except Exception:
            browser_hit = False
    finding = sink or browser_hit
    return {
        "test_id": "XSSDOM",
        "category": "xss",
        "observations": {
            "mode": "dom",
            "path": path,
            "sink_in_source": sink,
            "browser_marker_hit": browser_hit,
            "status": pair.status,
            "canary": marker,
        },
        "finding_candidate": finding,
        "detail": "DOM sink writes location into HTML" if finding else "no DOM sink / marker hit",
        "evidence_pairs": [pair] if finding else [],
        "evidence_hints": [f"GET {path} DOM sink inspection"],
    }


def run_stored(client, base_url: str, **kwargs) -> dict[str, Any]:
    """Stored XSS: post canary to lab guestbook, confirm HTML reflection, then delete.

    Gated to local/test/development unless force=True or ATTESTRA_AUTOMATED_VAPT_STORED_XSS=1.
    """
    import os

    from attestra.automated_vapt.testing._http import clear_cookies, login

    raw = (os.environ.get("ATTESTRA_AUTOMATED_VAPT_STORED_XSS") or "").strip().lower()
    if not kwargs.get("force") and raw not in ("1", "true", "yes", "on"):
        from attestra import config

        env = config.parse_app_env() if hasattr(config, "parse_app_env") else getattr(config, "APP_ENV", None)
        allow = getattr(config, "_APP_ENV_BYPASS_ALLOWLIST", frozenset({"local", "test", "development"}))
        if env not in allow:
            return {
                "test_id": "XSSSTORE",
                "category": "xss",
                "status_hint": "SKIPPED",
                "skip_reason": "stored_xss_disabled",
                "observations": {"detail": "stored XSS probe disabled outside local/test/development"},
                "finding_candidate": False,
                "evidence_hints": [],
            }

    sess_mode, auth = resolve_mode(client, kwargs)
    if sess_mode == "skip":
        return skip_result(
            "XSSSTORE",
            "xss",
            SKIP_NO_AUTH_SESSION,
            "engagement login profile not ready; skipped lab guestbook stored-XSS probes",
        )

    marker = new_canary(tag="STORED")
    payload = xss_canary_payload(marker)
    comment_url = absolute(base_url, "/api/comments")
    session_headers = {}
    if auth is not None and hasattr(auth, "headers_for"):
        session_headers = auth.headers_for(comment_url, base_url) or {}
    elif sess_mode == "lab":
        try:
            clear_cookies(client)
            login(client, base_url, "account_a", "account-a-pass")
        except Exception:
            pass
    post = client.post(comment_url, json={"text": payload}, headers=session_headers or None)
    post_status = int(getattr(post, "status_code", 0) or 0)
    cid = None
    try:
        cid = int((post.json() or {}).get("id") or 0) or None
    except Exception:
        cid = None
    guestbook = absolute(base_url, "/guestbook")
    if auth is not None:
        page = request_auth(client, "GET", guestbook, auth, base_url, follow_redirects=False)
    else:
        page = request_pair(client, "GET", guestbook, follow_redirects=False)
    ctype = ""
    for hk, hv in (page.response_headers or {}).items():
        if hk.lower() == "content-type":
            ctype = hv
            break
    body = page.response_body or ""
    # Require the quote-break / angle-bracket payload literally — marker alone can
    # appear inside a properly HTML-escaped guestbook and must not count as XSS.
    finding = reflected_unencoded_in_html(payload, body, content_type=ctype)
    if not finding and f"<{marker}>" in body:
        finding = True
    # Cleanup stored canary when delete API exists.
    if cid:
        try:
            client.request(
                "DELETE",
                absolute(base_url, f"/api/comments/{cid}"),
                headers=session_headers or None,
            )
        except Exception:
            pass
    return {
        "test_id": "XSSSTORE",
        "category": "xss",
        "observations": {
            "mode": "stored",
            "post_status": post_status,
            "comment_id": cid,
            "canary": marker,
            "reflected": finding,
        },
        "finding_candidate": finding,
        "detail": "stored XSS canary reflected unencoded in guestbook" if finding else "stored canary not reflected raw",
        "evidence_pairs": [page] if finding else [],
        "evidence_hints": ["POST /api/comments → GET /guestbook"],
    }
