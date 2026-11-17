"""B-04: Authenticated-response cache posture (catalogue id ``CACHE``, WSTG-ATHN-06, CWE-524).

Passive-first probe (tier T1, at most 6 GETs) that needs the engagement login profile.
It GETs a few captured, non-static pages **with** the session and reads the caching
headers. No poisoning payload, no unkeyed-header tricks, no cache-buster abuse.

- ``ok``: ``Cache-Control`` contains ``no-store`` or ``private`` (or the response is
  not cacheable by a shared cache).
- ``suspicious``: a personalised (authenticated, dynamic) response is cacheable by a
  shared cache (``public`` / ``s-maxage`` / ``max-age`` without ``private``) or a CDN
  reports a cache ``HIT`` / ``Age`` on it.
- ``confirmed``: only for a suspicious URL that a CDN reports as a HIT, one GET **without**
  the session returns the same body hash. That is authenticated content served from a
  shared cache to an anonymous user.

Static assets (by extension or content type) are excluded. Bodies are never stored;
only a SHA-256 and redacted, size-capped evidence pairs are kept.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from attestra.automated_vapt.testing._probe_base import (
    SKIP_DISABLED_BY_FLAG,
    SKIP_NO_AUTH,
    ProbeMeta,
    ProbeSession,
    body_sha256,
    engagement_auth,
    finish,
    header,
    not_tested,
    probes_web_safe_enabled,
    scope_ok,
)
from attestra.automated_vapt.testing._session import probe_urls

# @lat: [[web-api-probes#Cache posture]]

META = ProbeMeta(
    test_id="CACHE",
    category="session",
    safety_tier="T1",
    request_budget=6,
    auth_required=True,
    wstg_refs=("WSTG-ATHN-06",),
    cwe_refs=("CWE-524", "CWE-525"),
)

MAX_PAGES = 4
_STATIC_EXT_RE = re.compile(r"(?i)\.(?:css|js|mjs|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|eot|map|txt|pdf|mp4|webm)$")
_STATIC_CT = ("image/", "font/", "text/css", "javascript", "video/", "audio/")
_HIT_RE = re.compile(r"(?i)\b(hit|stale|revalidated|updating)\b")


def is_static(url: str, content_type: str = "") -> bool:
    if _STATIC_EXT_RE.search(urlsplit(url).path or ""):
        return True
    ct = (content_type or "").lower()
    return any(s in ct for s in _STATIC_CT)


def parse_cache_control(value: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in (value or "").split(","):
        part = part.strip().lower()
        if not part:
            continue
        k, _, v = part.partition("=")
        out[k.strip()] = v.strip().strip('"')
    return out


def _int(v: str) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def assess_headers(headers: dict[str, Any] | None) -> dict[str, Any]:
    """Pure: shared-cacheability verdict for one authenticated response."""
    cc_raw = header(headers, "cache-control")
    cc = parse_cache_control(cc_raw)
    pragma = header(headers, "pragma").lower()
    expires = header(headers, "expires")
    cdn_status = (
        header(headers, "cf-cache-status")
        or header(headers, "x-cache")
        or header(headers, "x-cache-status")
        or header(headers, "akamai-cache-status")
    )
    age = _int(header(headers, "age"))
    no_store = "no-store" in cc
    private = "private" in cc
    shared_cacheable = False
    reasons: list[str] = []
    if not (no_store or private):
        if "public" in cc:
            shared_cacheable = True
            reasons.append("cache-control public")
        if _int(cc.get("s-maxage", "")) > 0:
            shared_cacheable = True
            reasons.append("s-maxage > 0")
        if _int(cc.get("max-age", "")) > 0 and "no-cache" not in cc:
            shared_cacheable = True
            reasons.append("max-age > 0 without private")
        if not cc_raw and expires and "no-cache" not in pragma:
            shared_cacheable = True
            reasons.append("Expires without Cache-Control")
    cdn_hit = bool(cdn_status and _HIT_RE.search(cdn_status)) or age > 0
    if cdn_hit and not no_store:
        reasons.append(f"cdn cache status {cdn_status or 'age>0'}")
    verdict = "ok"
    if (shared_cacheable or cdn_hit) and not no_store:
        verdict = "suspicious"
    return {
        "cache_control": cc_raw or None,
        "no_store": no_store,
        "private": private,
        "shared_cacheable": shared_cacheable,
        "cdn_cache_status": cdn_status or None,
        "age": age,
        "cdn_hit": cdn_hit,
        "verdict": verdict,
        "reasons": reasons,
    }


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    if not probes_web_safe_enabled():
        return not_tested(META, SKIP_DISABLED_BY_FLAG, "ATTESTRA_PROBES_WEB_SAFE is off")
    auth = engagement_auth(kwargs)
    if auth is None:
        # Never PASS without an authenticated identity: there is nothing personalised to test.
        return not_tested(META, SKIP_NO_AUTH, "engagement login profile not ready; authenticated cache posture not tested")
    ps = ProbeSession(client, base_url, META, auth=auth, delay_s=kwargs.get("delay_s"))
    urls = [u for u in probe_urls(base_url, kwargs, api=False, limit=12) if scope_ok(u, base_url, kwargs) and not is_static(u)]
    pages: list[dict[str, Any]] = []
    evidence: list[Any] = []
    suspicious: list[str] = []
    confirmed: list[str] = []
    for url in urls[:MAX_PAGES]:
        if not ps.can_send():
            break
        pair = ps.send("GET", url)
        if pair is None:
            continue
        ct = header(pair.response_headers, "content-type")
        row: dict[str, Any] = {"url": url.split("?", 1)[0], "status": pair.status, "class": ps.last_class()}
        if ps.last_class() != "app_ok" or is_static(url, ct):
            row["skipped"] = "not_app_content" if ps.last_class() != "app_ok" else "static"
            pages.append(row)
            continue
        verdict = assess_headers(pair.response_headers)
        row.update(verdict)
        authed_hash = body_sha256(pair.response_body or "")
        if verdict["verdict"] == "suspicious":
            suspicious.append(row["url"])
            evidence.append(ps.evidence(pair, body_cap=1_000))
            if verdict["cdn_hit"] and ps.can_send():
                anon = ps.send("GET", url, authed=False)
                if anon is not None:
                    same = ps.last_class() == "app_ok" and body_sha256(anon.response_body or "") == authed_hash
                    row["anonymous_same_body"] = same
                    if same:
                        confirmed.append(row["url"])
                        evidence.append(ps.evidence(anon, body_cap=1_000))
        pages.append(row)

    tested = [p for p in pages if "verdict" in p]
    finding = bool(suspicious)
    if confirmed:
        detail = "authenticated content served from a shared cache to an anonymous request: " + ", ".join(confirmed)
    elif suspicious:
        detail = "authenticated responses cacheable by shared caches: " + ", ".join(suspicious)
    elif tested:
        detail = "authenticated responses are private / no-store"
    else:
        detail = "no authenticated application page could be assessed"
    out = finish(
        META,
        ps,
        observations={"pages": pages, "suspicious": suspicious, "confirmed": confirmed, "assessed": len(tested)},
        finding=finding,
        confidence="confirmed" if confirmed else "suspected",
        severity="medium" if confirmed else "low",
        detail=detail,
        evidence=evidence,
        hints=[f"GET {p['url']} (authenticated) cache headers" for p in pages],
    )
    if not finding and not tested and out.get("status_hint") is None:
        out["status_hint"] = "INCONCLUSIVE"
    return out
