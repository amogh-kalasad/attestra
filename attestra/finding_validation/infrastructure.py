"""CDN / Cloudflare / challenge classifiers for general finding validation."""

from __future__ import annotations

import re
from urllib.parse import urlsplit, unquote

_CDN_CHALLENGE_MARKERS = (
    "/cdn-cgi/",
    "cdn-cgi/",
    "challenge-platform",
    "/cdn-cgi/challenge-platform",
    "cf-chl-",
    "challenges.cloudflare.com",
)

_CF_COOKIE_EXACT = frozenset(
    {
        "cf_clearance",
        "__cf_bm",
        "__cfruid",
        "_cfuvid",
    }
)

_COOKIE_TITLE_RE = re.compile(
    r"samesite|set-cookie|cookie\b|secure\s+flag|httponly",
    re.IGNORECASE,
)

# Next.js / bundler / common static asset paths (cache findings here are noise).
_STATIC_PATH_MARKERS = (
    "/_next/static",
    "/_next/",
    "/__nextjs",
    "/_vercel/",
    "/static/",
    "/assets/",
    "/webpack",
    "/chunks/",
)
_STATIC_EXT_RE = re.compile(
    r"(?i)\.(?:js|mjs|cjs|css|map|woff2?|ttf|otf|eot|ico|svg|png|jpe?g|gif|webp|avif)(?:$|[?#])"
)
_ROBOTS_RE = re.compile(r"(?i)(?:^|/)robots\.txt(?:$|[?#])")
_CACHE_RULE_RE = re.compile(
    r"(?:^|[\s,;/])(?:10015|10049(?:-\d+)?|10050(?:-\d+)?)(?:$|[\s,;:])"
)
_CACHE_TITLE_RE = re.compile(
    r"(?i)cache[-_\s]?control|non[-_\s]?storable|storable\s+and\s+cacheable|"
    r"storable\s+but\s+non[-_\s]?cacheable|retrieved\s+from\s+cache|"
    r"content\s+cacheability|re-examine\s+cache"
)


def is_cdn_challenge_url(url: str) -> bool:
    """True for Cloudflare/CDN challenge paths (case-insensitive)."""
    u = (url or "").lower()
    if not u:
        return False
    return any(m in u for m in _CDN_CHALLENGE_MARKERS)


def is_cloudflare_infrastructure_cookie(name: str) -> bool:
    """True for known Cloudflare infrastructure cookie names."""
    n = (name or "").strip().lower()
    if not n:
        return False
    if n in _CF_COOKIE_EXACT:
        return True
    return n.startswith(("cf_chl_", "__cf", "cf_"))


def _cookie_name_in_text(text: str) -> bool:
    blob = (text or "").lower()
    if not blob:
        return False
    for exact in _CF_COOKIE_EXACT:
        if exact in blob:
            return True
    if re.search(r"\bcf_chl_[a-z0-9_]+\b", blob):
        return True
    if re.search(r"\b__cf[a-z0-9_]*\b", blob) or re.search(r"\bcf_[a-z0-9_]+\b", blob):
        return True
    return False


def is_infrastructure_cookie_finding(
    title: str,
    param: str,
    location: str,
    evidence_text: str = "",
) -> bool:
    """SameSite/cookie findings naming a CF cookie or cookie-titled on cdn-cgi.

    Must not treat arbitrary evidence on challenge URLs (e.g. CORS ACAO) as
    cookie infrastructure noise — that would shadow CDN CORS classification.
    """
    title_l = title or ""
    cookie_titled = bool(_COOKIE_TITLE_RE.search(title_l))
    if is_cloudflare_infrastructure_cookie(param or ""):
        return True
    if _cookie_name_in_text(evidence_text) or _cookie_name_in_text(param or ""):
        return True
    # Cookie-titled alerts on challenge URLs are CDN noise even without a CF name.
    if cookie_titled and is_cdn_challenge_url(location or ""):
        return True
    return False


def is_cdn_cors_finding(title: str, location: str, evidence_text: str = "") -> bool:
    """CORS / cross-domain misconfig titles on cdn-cgi / challenge URLs."""
    if not is_cdn_challenge_url(location or ""):
        return False
    blob = f"{title or ''}\n{evidence_text or ''}".lower()
    # X-Permitted-Cross-Domain-Policies is Adobe policy-file gating, not CORS.
    if "x-permitted-cross-domain" in blob or "permitted-cross-domain-policies" in blob:
        return False
    markers = (
        "cors",
        "cross-origin",
        "cross origin",
        "cross-domain",
        "cross domain",
        "access-control-allow-origin",
        "access-control-allow",
        "acaorigin",
        "crossdomain",
    )
    return any(m in blob for m in markers)


def _url_path(location: str) -> str:
    loc = (location or "").strip()
    if not loc:
        return ""
    if "://" in loc:
        try:
            return unquote(urlsplit(loc).path or "")
        except ValueError:
            return loc
    return unquote(loc.split("?", 1)[0].split("#", 1)[0])


def is_static_asset_url(location: str) -> bool:
    """True for Next.js/static/bundler assets and robots.txt (cache noise targets)."""
    path = _url_path(location).lower()
    if not path:
        return False
    if _ROBOTS_RE.search(path):
        return True
    if any(m in path for m in _STATIC_PATH_MARKERS):
        return True
    if _STATIC_EXT_RE.search(path):
        return True
    return False


def is_cache_related_finding(
    title: str,
    rule_ids: list[str] | None = None,
    description: str = "",
) -> bool:
    """True for ZAP cache-control / storable / retrieved-from-cache family alerts."""
    rule_blob = " ".join(str(r) for r in (rule_ids or []))
    if _CACHE_RULE_RE.search(rule_blob):
        return True
    blob = f"{title or ''}\n{description or ''}"
    return bool(_CACHE_TITLE_RE.search(blob))
