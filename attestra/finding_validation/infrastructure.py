"""CDN / Cloudflare / challenge classifiers for general finding validation."""

from __future__ import annotations

import re

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
