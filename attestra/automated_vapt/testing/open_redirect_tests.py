"""B-03: Open redirect probe (catalogue id ``OREDIR``, WSTG-CLNT-04).

Safe-active read-only probe (tier T1, at most 12 GETs). Redirect-style query parameters
(``next``, ``url``, ``returnTo``, ...) seen in captured URLs, plus a few common login
paths, get a marker destination on the non-routable ``attestra-redirect-marker.invalid``
host. Requests never follow redirects; only the ``Location`` header (and a meta-refresh /
JS ``location`` in the body) is read. The marker host is **never contacted**.

The redirect chain is recorded: a same-origin ``Location`` is followed (GET, no auth
change) within the budget so a multi-hop open redirect is still seen. Any off-scope hop
stops the chain. A redirect that stays on the same site is allowlisted and suppressed.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from attestra.automated_vapt.testing._probe_base import (
    SKIP_DISABLED_BY_FLAG,
    ProbeMeta,
    ProbeSession,
    engagement_auth,
    finish,
    header,
    host_of,
    not_tested,
    probes_web_safe_enabled,
    scope_ok,
)
from attestra.automated_vapt.testing._session import ctx_extra

# @lat: [[web-api-probes#Open redirect probe]]

META = ProbeMeta(
    test_id="OREDIR",
    category="client_side",
    safety_tier="T1",
    request_budget=12,
    wstg_refs=("WSTG-CLNT-04",),
    cwe_refs=("CWE-601",),
)

MARKER_HOST = "attestra-redirect-marker.invalid"
MARKER_URL = f"https://{MARKER_HOST}/oredir"

# Encoded / parser-confusion variants (all point at the same non-routable marker).
PAYLOADS: tuple[tuple[str, str], ...] = (
    ("absolute", MARKER_URL),
    ("scheme_relative", f"//{MARKER_HOST}/oredir"),
    ("backslash", f"/\\{MARKER_HOST}/oredir"),
    ("encoded", "https%3A%2F%2F" + MARKER_HOST + "%2Foredir"),
)

REDIRECT_PARAM_RE = re.compile(
    r"(?i)^(next|url|redirect|redirect_?url|redirect_?uri|return|return_?to|returnurl|returnto|"
    r"continue|dest|destination|goto|go|target|r|u|callback|forward|out|view|to|ref|redir)$"
)
DEFAULT_CANDIDATES: tuple[tuple[str, str], ...] = (("/login", "next"), ("/", "redirect"), ("/", "returnTo"))
MAX_CANDIDATES = 3
MAX_HOPS = 2

_META_REFRESH_RE = re.compile(r"(?is)<meta[^>]+http-equiv=[\"']?refresh[^>]+url=([^\"'>]+)")
_JS_LOC_RE = re.compile(r"(?is)(?:window\.|document\.)?location(?:\.href)?\s*=\s*[\"']([^\"']+)")


def points_at_marker(location: str, from_url: str) -> bool:
    if not location:
        return False
    loc = location.strip().replace("\\", "/")
    target = urljoin(from_url, loc)
    return host_of(target) == MARKER_HOST


def body_redirect_targets(body: str) -> list[str]:
    text = (body or "")[:50_000]
    return [m.group(1).strip() for m in _META_REFRESH_RE.finditer(text)] + [
        m.group(1).strip() for m in _JS_LOC_RE.finditer(text)
    ]


def candidates(base_url: str, kwargs: dict[str, Any]) -> list[tuple[str, str]]:
    """(url-without-param, param) pairs: captured redirect-style params first, then defaults."""
    from attestra.automated_vapt.core.js_api_discovery import is_unsafe_path

    extra = ctx_extra(kwargs)
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    pool = list(extra.get("_capture_urls") or []) + list(extra.get("_capture_api_urls") or [])
    for u in pool:
        u = str(u or "")
        if not u or not scope_ok(u, base_url, kwargs) or is_unsafe_path(u):
            continue
        p = urlsplit(u)
        for k, _v in parse_qsl(p.query, keep_blank_values=True):
            if REDIRECT_PARAM_RE.match(k):
                bare = urlunsplit((p.scheme, p.netloc, p.path or "/", "", ""))
                key = (bare, k)
                if key not in seen:
                    seen.add(key)
                    out.append(key)
    root = base_url.rstrip("/")
    for path, param in DEFAULT_CANDIDATES:
        key = (root + path, param)
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out[:MAX_CANDIDATES]


def _with_param(url: str, param: str, value: str, *, raw: bool) -> str:
    p = urlsplit(url)
    pairs = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k != param]
    q = urlencode(pairs)
    enc = f"{param}={value}" if raw else urlencode({param: value})
    q = f"{q}&{enc}" if q else enc
    return urlunsplit((p.scheme, p.netloc, p.path or "/", q, ""))


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    if not probes_web_safe_enabled():
        return not_tested(META, SKIP_DISABLED_BY_FLAG, "ATTESTRA_PROBES_WEB_SAFE is off")
    auth = engagement_auth(kwargs)
    ps = ProbeSession(client, base_url, META, auth=auth, delay_s=kwargs.get("delay_s"))
    cands = list(kwargs.get("candidates") or candidates(base_url, kwargs))[:MAX_CANDIDATES]
    rows: list[dict[str, Any]] = []
    evidence: list[Any] = []
    confirmed: list[str] = []
    suspected: list[str] = []

    for cand_url, param in cands:
        if not ps.can_send() or confirmed:
            break
        for pname, payload in PAYLOADS:
            if not ps.can_send():
                break
            url = _with_param(cand_url, param, payload, raw=(pname == "encoded"))
            chain: list[dict[str, Any]] = []
            current = url
            hit = False
            for _hop in range(MAX_HOPS + 1):
                if not ps.can_send():
                    break
                pair = ps.send("GET", current)
                if pair is None:
                    break
                loc = header(pair.response_headers, "location")
                chain.append({"url": current.split("?", 1)[0], "status": pair.status, "location_host": host_of(urljoin(current, loc)) if loc else ""})
                if loc and points_at_marker(loc, current):
                    hit = True
                    evidence.append(ps.evidence(pair))
                    break
                if not loc and any(points_at_marker(t, current) for t in body_redirect_targets(pair.response_body or "")):
                    suspected.append(f"{param}:{pname}")
                    evidence.append(ps.evidence(pair))
                    break
                if not loc or not (300 <= int(pair.status or 0) < 400):
                    break
                nxt = urljoin(current, loc.replace("\\", "/"))
                if not scope_ok(nxt, base_url, kwargs):
                    chain[-1]["stopped"] = "off_scope_hop_not_followed"
                    break
                current = nxt  # same-site hop: allowlisted, follow within budget
            rows.append({"candidate": cand_url.split("?", 1)[0], "param": param, "payload": pname, "chain": chain, "marker_redirect": hit})
            if hit:
                confirmed.append(f"{param}:{pname}")
                break

    finding = bool(confirmed or suspected)
    if confirmed:
        detail = "open redirect to an external marker via " + ", ".join(confirmed)
    elif suspected:
        detail = "client-side redirect to an external marker via " + ", ".join(suspected)
    else:
        detail = "no redirect to an external destination"
    return finish(
        META,
        ps,
        observations={
            "marker_host": MARKER_HOST,
            "candidates": [{"url": u.split("?", 1)[0], "param": p} for u, p in cands],
            "attempts": rows,
            "confirmed": confirmed,
            "suspected": suspected,
        },
        finding=finding,
        confidence="confirmed" if confirmed else "suspected",
        severity="medium",
        detail=detail,
        evidence=evidence,
        hints=[f"GET {u.split('?', 1)[0]}?{p}=<marker>" for u, p in cands],
    )
