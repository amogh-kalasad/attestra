"""C-06: Passive API rate-limit headers and API version inventory (catalogue id ``APIPOST``).

Tier T0. Reads response headers from traffic the run **already** captured (T01
``_http_pairs``). Only when there is no captured traffic and ``ATTESTRA_PROBES_WEB_SAFE``
is on does it send up to 3 plain GETs to known API URLs. Never a burst, never a
rate-limit trigger attempt.

- Rate-limit headers: IETF ``RateLimit`` / ``RateLimit-Policy``, ``X-RateLimit-*``,
  ``Retry-After``. Missing headers are **informational only**.
- API version inventory: versions in paths (``/v1/``, ``/api/v2``), ``api-version``
  query values and version response headers, from captured URLs, JS-discovered
  endpoints and imported API specs. More than one live major version is an info note.

``finding_candidate`` is always False.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from attestra.automated_vapt.core.response_classifier import classify_pair
from attestra.automated_vapt.testing._probe_base import (
    ProbeMeta,
    ProbeSession,
    engagement_auth,
    finish,
    probes_web_safe_enabled,
    scope_ok,
)
from attestra.automated_vapt.testing._session import _is_api_probe_url, ctx_extra, probe_urls

# @lat: [[web-api-probes#API posture]]

META = ProbeMeta(
    test_id="APIPOST",
    category="api",
    safety_tier="T0",
    request_budget=3,
    wstg_refs=("WSTG-BUSL-05",),
    cwe_refs=("CWE-770", "CWE-1059"),
)

RATE_LIMIT_HEADERS = (
    "ratelimit",
    "ratelimit-policy",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-rate-limit-limit",
    "x-rate-limit-remaining",
    "x-rate-limit-reset",
    "retry-after",
)
VERSION_HEADERS = ("api-version", "x-api-version", "x-version", "api-supported-versions", "api-deprecated-versions", "deprecation", "sunset")
_PATH_VERSION_RE = re.compile(r"(?i)/(v\d{1,2}(?:\.\d{1,2})?)(?=/|$)")


def rate_limit_headers(headers: dict[str, Any] | None) -> dict[str, str]:
    lower = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    return {h: lower[h][:120] for h in RATE_LIMIT_HEADERS if h in lower}


def version_headers(headers: dict[str, Any] | None) -> dict[str, str]:
    lower = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    return {h: lower[h][:120] for h in VERSION_HEADERS if h in lower}


def versions_in_url(url: str) -> list[str]:
    p = urlsplit(url or "")
    out = [m.group(1).lower() for m in _PATH_VERSION_RE.finditer(p.path or "")]
    for k, v in parse_qsl(p.query, keep_blank_values=True):
        if k.lower() in ("api-version", "api_version", "version", "v") and v and len(v) <= 20:
            out.append(f"query:{v}")
    return out


def _major(v: str) -> str:
    m = re.match(r"(?i)v(\d+)", v)
    return f"v{m.group(1)}" if m else v



_AUTH_HEADER_NAMES = frozenset({"authorization", "cookie", "proxy-authorization"})
_INVALID_BEARER_MARK = "INVALID_TOKEN_attestra_replay_check"
_NEGATIVE_AUTH_STATUSES = frozenset({401, 403})


def _request_headers_lower(pair: Any) -> dict[str, str]:
    raw = getattr(pair, "request_headers", None) or {}
    return {str(k).lower(): str(v) for k, v in raw.items()}


def _is_invalid_bearer_request(pair: Any) -> bool:
    auth = _request_headers_lower(pair).get("authorization", "")
    return _INVALID_BEARER_MARK in auth


def _request_carried_session_auth(pair: Any) -> bool:
    """True when the captured request still looks like it carried a session.

    T19's invalid-token probe may keep an Authorization header (sometimes later
    redacted), so this cannot be the only filter: 401/403 pairs are excluded
    from APIPOST validity samples separately.
    """
    if _is_invalid_bearer_request(pair):
        return False
    hdrs = _request_headers_lower(pair)
    for name in _AUTH_HEADER_NAMES:
        if (hdrs.get(name) or "").strip():
            return True
    return False


def _is_api_relevant_pair(pair: Any, base_url: str, kwargs: dict[str, Any] | None) -> bool:
    """API inventory /api/ or GraphQL paths, or a distinct configured API host."""
    url = str(getattr(pair, "url", "") or "")
    extra = ctx_extra(kwargs)
    api_root = str(extra.get("_api_base_url") or "")
    api_set = {str(u).rstrip("/") for u in (extra.get("_capture_api_urls") or []) if u}
    if _is_api_probe_url(url, api_root, api_set):
        return True
    if not url or not api_root:
        return False
    u, r, t = urlsplit(url), urlsplit(api_root), urlsplit(base_url or "")
    if not u.netloc or not r.netloc:
        return False
    same_api_host = u.netloc.lower() == r.netloc.lower() and (u.scheme or "https").lower() == (r.scheme or "https").lower()
    if not same_api_host:
        return False
    # If the API base shares the SPA/target host, require /api/ or the inventory.
    if t.netloc and u.netloc.lower() == t.netloc.lower():
        return False
    return True


def captured_validity_samples(
    pairs: list[Any], base_url: str, kwargs: dict[str, Any] | None
) -> list[Any]:
    """Classify API-relevant captured pairs for run validity.

    Intentionally unauthenticated or bad-token 401/403 probes (T19) are
    excluded so they cannot be counted as ``auth_expired``. HTML app pages
    are not sampled.
    """
    samples: list[Any] = []
    for p in pairs:
        if not _is_api_relevant_pair(p, base_url, kwargs):
            continue
        try:
            status = int(getattr(p, "status", 0) or 0)
        except (TypeError, ValueError):
            status = 0
        if status in _NEGATIVE_AUTH_STATUSES:
            continue
        if _is_invalid_bearer_request(p):
            continue
        samples.append(classify_pair(p, authed=_request_carried_session_auth(p)))
        if len(samples) >= 40:
            break
    return samples


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    extra = ctx_extra(kwargs)
    pairs = [p for p in list(extra.get("_http_pairs") or []) if scope_ok(str(getattr(p, "url", "")), base_url, kwargs)]
    ps: ProbeSession | None = None
    source = "captured_traffic"
    if not pairs and probes_web_safe_enabled():
        source = "bounded_gets"
        ps = ProbeSession(client, base_url, META, auth=engagement_auth(kwargs), delay_s=kwargs.get("delay_s"))
        for u in probe_urls(base_url, kwargs, api=True, limit=META.request_budget):
            if not ps.can_send():
                break
            pr = ps.send("GET", u)
            if pr is not None:
                pairs.append(pr)
    elif not pairs:
        source = "none"

    rl_rows: list[dict[str, Any]] = []
    vh: dict[str, str] = {}
    for p in pairs[:40]:
        rl = rate_limit_headers(getattr(p, "response_headers", {}))
        rl_rows.append({"url": str(getattr(p, "url", "")).split("?", 1)[0], "status": getattr(p, "status", None), "rate_limit_headers": sorted(rl)})
        vh.update(version_headers(getattr(p, "response_headers", {})))

    urls: list[str] = [str(getattr(p, "url", "")) for p in pairs]
    urls += [str(u) for u in (extra.get("_capture_urls") or [])] + [str(u) for u in (extra.get("_capture_api_urls") or [])]
    js = extra.get("_js_api") or {}
    for ep in (js.get("endpoints_list") or []) if isinstance(js, dict) else []:
        urls.append(str(ep.get("path") if isinstance(ep, dict) else getattr(ep, "path", "")))
    for op in extra.get("_api_inventory_ops") or []:
        d = op.to_dict() if hasattr(op, "to_dict") else dict(op or {})
        urls.append(str(d.get("path") or ""))
    versions: dict[str, int] = {}
    for u in urls:
        for v in versions_in_url(u):
            versions[v] = versions.get(v, 0) + 1
    majors = sorted({_major(v) for v in versions if not v.startswith("query:")})

    with_rl = [r for r in rl_rows if r["rate_limit_headers"]]
    info: list[str] = []
    if pairs and not with_rl:
        info.append("no_rate_limit_headers_observed")
    if len(majors) > 1:
        info.append("multiple_api_major_versions_live")
    if vh.get("deprecation") or vh.get("sunset"):
        info.append("deprecated_api_version_advertised")
    detail = (
        f"{len(with_rl)}/{len(rl_rows)} responses advertise rate limits; API versions: {', '.join(majors) or 'none'}"
        if rl_rows
        else "no captured API traffic to observe"
    )
    captured_samples = []
    if ps is None and pairs:
        captured_samples = captured_validity_samples(pairs, base_url, kwargs)
    out = finish(
        META,
        ps,
        observations={
            "source": source,
            "rate_limit": {"responses": rl_rows, "with_headers": len(with_rl), "total": len(rl_rows)},
            "versions": {"seen": versions, "majors": majors, "headers": vh},
            "informational": info,
        },
        finding=False,
        detail=detail,
        hints=["passive header review of captured traffic"],
        status_hint=None if rl_rows else "NOT_TESTED",
        validity_samples=captured_samples or None,
    )
    if ps is None and rl_rows:
        out.pop("status_hint", None)
    if not rl_rows:
        out["skip_reason"] = "no_traffic"
    return out
