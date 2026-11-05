"""Finding location/context normalization for cross-tool merge guards.

Security context keeps the same concept on one host from auto-merging when the
affected resource is infrastructure (CDN/challenge) vs application vs static.
Sibling CONCEPT_RULES expansions may add entries via ``EXTRA_CONCEPT_RULES``.
"""
# @lat: [[findings#Deduplication#Cross-tool merge]]

from __future__ import annotations

import re
from urllib.parse import urlsplit

from attestra.fingerprint import caa_host, normalize_location

# Optional sibling expansions (CORS / Permissions-Policy / SameSite / weak-cipher).
# crossmerge merges these with try/getattr so either side can land first.
EXTRA_CONCEPT_RULES: dict[str, dict[str, list[tuple[str, str]]]] = {}

_CDN_CGI_MARKERS = ("/cdn-cgi/", "cdn-cgi/")
_CHALLENGE_MARKERS = (
    "challenge-platform",
    "/cdn-cgi/challenge-platform",
    "challenges.cloudflare.com",
    "cf-chl-",
)
_STATIC_PREFIXES = ("/_next/", "/__nextjs", "/_vercel/", "/static/", "/assets/")
_HOSTPORT = re.compile(r"^[a-z0-9.-]+(:\d{1,5})?$", re.IGNORECASE)


def _bare_location(location: str) -> str:
    loc = (location or "").strip()
    if " [param:" in loc:
        loc = loc.split(" [param:", 1)[0].strip()
    return loc


def context_host(location: str) -> str:
    """Lowercase hostname for a URL or ``host[:port]``; "" for files/images."""
    loc = _bare_location(location)
    if not loc:
        return ""
    if "://" in loc:
        try:
            host = urlsplit(loc).hostname or ""
        except ValueError:
            return ""
        return host.lower().rstrip(".")
    if _HOSTPORT.match(loc) and "." in loc:
        return caa_host(loc).rstrip(".")
    return ""


def path_context_bucket(location: str, title: str = "") -> str:
    """Path security bucket: ``challenge``, ``cdn-cgi``, ``static``, or ``app``."""
    loc = _bare_location(location)
    blob = f"{loc}\n{title or ''}".lower()
    if any(m in blob for m in _CHALLENGE_MARKERS):
        return "challenge"
    if any(m in blob for m in _CDN_CGI_MARKERS):
        return "cdn-cgi"
    path = ""
    if "://" in loc:
        try:
            path = (urlsplit(loc).path or "").lower()
        except ValueError:
            path = ""
    else:
        path = loc.lower()
    if any(p in path for p in _STATIC_PREFIXES):
        return "static"
    return "app"


def security_context_key(location: str, title: str = "") -> str:
    """Host + path-context key so CDN/challenge findings do not merge with app ones.

    Format: ``{host}@{bucket}`` (e.g. ``shop.example.com@app``). When host is
    missing, uses normalized location (or empty) before ``@{bucket}``.
    """
    bucket = path_context_bucket(location, title)
    host = context_host(location)
    if host:
        return f"{host}@{bucket}"
    loc = normalize_location(_bare_location(location)).lower()
    return f"{loc}@{bucket}" if loc else f"@{bucket}"
