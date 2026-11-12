"""API base URL resolution for automated VAPT API requests (T19-T22, JS-discovered APIs).

Many SPAs serve pages from one host (``https://app.example.com``) and call their API on
another (``https://api.example.com``). JS discovery only yields *paths* (``/api/...``), so
gluing them onto the page host 404s. Resolution order for a relative API path:

1. the asset's ``api_base_url`` (set on the target's Crawl Settings),
2. else the origin of the login profile's ``refresh_url`` -- only when it is the same site
   as the target (so a third-party identity provider never receives API probes),
3. else the engagement target (today's behaviour).

Absolute URLs that already carry a host are never rewritten. Page URLs (T01 pages, T02
browser screenshots) are not routed through here and stay on the target.
"""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

SOURCE_ASSET = "asset"
SOURCE_REFRESH = "refresh_url"
SOURCE_TARGET = "target"

# Two-label public suffixes (co.uk, com.au, co.in ...) — enough for a same-site check.
_SECOND_LEVEL = frozenset({"co", "com", "net", "org", "gov", "ac", "edu", "or", "ne", "go"})


class ApiBaseError(ValueError):
    """Invalid API base URL (message is safe to show to the user)."""


def normalize_api_base(raw: str | None) -> str:
    """Return ``scheme://host[:port][/path]`` without trailing slash, or ``""`` when empty.

    Accepts a bare host (``api.example.com`` -> ``https://api.example.com``). Raises
    :class:`ApiBaseError` for non-http(s) schemes, missing host, embedded credentials,
    query strings or fragments.
    """
    text = (raw or "").strip()
    if not text:
        return ""
    if "://" not in text:
        text = "https://" + text
    try:
        p = urlsplit(text)
        port = p.port
    except ValueError as exc:
        raise ApiBaseError("API base URL is not a valid URL") from exc
    scheme = (p.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise ApiBaseError("API base URL must start with http:// or https://")
    host = (p.hostname or "").lower()
    if not host:
        raise ApiBaseError("API base URL must include a host, e.g. https://api.example.com")
    if p.username or p.password:
        raise ApiBaseError("API base URL must not contain a username or password")
    if p.query or p.fragment:
        raise ApiBaseError("API base URL must not contain a query string or fragment")
    netloc = f"[{host}]" if ":" in host else host
    if port and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        netloc = f"{netloc}:{port}"
    path = (p.path or "").rstrip("/")
    return urlunsplit((scheme, netloc, path, "", ""))


def safe_normalize(raw: str | None) -> str:
    """Like :func:`normalize_api_base` but returns ``""`` instead of raising."""
    try:
        return normalize_api_base(raw)
    except ApiBaseError:
        return ""


def origin_of(url: str | None) -> str:
    """``scheme://host[:port]`` of an absolute http(s) URL, else ``""``."""
    u = (url or "").strip()
    if not u:
        return ""
    try:
        p = urlsplit(u)
        port = p.port
    except ValueError:
        return ""
    scheme = (p.scheme or "").lower()
    host = (p.hostname or "").lower()
    if scheme not in ("http", "https") or not host:
        return ""
    netloc = f"[{host}]" if ":" in host else host
    if port and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        netloc = f"{netloc}:{port}"
    return f"{scheme}://{netloc}"


def _site(host: str) -> str:
    host = (host or "").lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = [x for x in host.split(".") if x]
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def same_site(url_a: str, url_b: str) -> bool:
    """True when both URLs share a registrable domain (``api.x.com`` ~ ``app.x.com``)."""
    ha = (urlsplit(url_a or "").hostname or "").lower()
    hb = (urlsplit(url_b or "").hostname or "").lower()
    if not ha or not hb:
        return False
    return ha == hb or _site(ha) == _site(hb)


def resolve_api_base(
    *,
    asset_api_base: str | None,
    refresh_url: str | None,
    target_base_url: str,
) -> tuple[str, str]:
    """Return ``(base, source)`` for relative API paths. ``source`` is asset|refresh_url|target."""
    base = safe_normalize(asset_api_base)
    if base:
        return base, SOURCE_ASSET
    ref = origin_of(refresh_url)
    if ref and same_site(ref, target_base_url):
        return ref, SOURCE_REFRESH
    return (target_base_url or "").strip(), SOURCE_TARGET


def is_absolute(url: str | None) -> bool:
    try:
        p = urlsplit((url or "").strip())
    except ValueError:
        return False
    return bool(p.scheme and p.netloc)


def join(base: str, path: str) -> str:
    """Join a relative path onto ``base`` (keeping any base path such as ``/v1``)."""
    root = (base or "").strip()
    root = root if root.endswith("/") else root + "/"
    return urljoin(root, (path or "").lstrip("/"))


def resolve_api_url(path_or_url: str, api_base: str, target_base_url: str = "") -> str:
    """Absolute URL for an API request. Absolute URLs (with a host) are returned unchanged."""
    raw = (path_or_url or "").strip()
    if is_absolute(raw):
        return raw
    return join(api_base or target_base_url, raw)


def rebase_to_api(url: str, target_base_url: str, api_base: str) -> str:
    """Move a target-origin URL (built from a relative API path) onto ``api_base``.

    URLs on any other origin, or when ``api_base`` is the target itself, are unchanged.
    """
    if not url or not api_base:
        return url
    t_origin = origin_of(target_base_url)
    if not t_origin or origin_of(url) != t_origin:
        return url
    if origin_of(api_base) == t_origin and not urlsplit(api_base).path.strip("/"):
        return url
    p = urlsplit(url)
    rel = (p.path or "/") + (f"?{p.query}" if p.query else "")
    return join(api_base, rel)


def api_root(ctx: Any) -> str:
    """Resolved API base for a run (``ctx.extra['_api_base_url']``), else the target."""
    extra = getattr(ctx, "extra", None) or {}
    return str(extra.get("_api_base_url") or getattr(ctx, "target_base_url", "") or "")


def api_root_from_extra(extra: dict[str, Any] | None, target_base_url: str) -> str:
    return str((extra or {}).get("_api_base_url") or target_base_url or "")


def apply_to_ctx(ctx: Any, *, asset: Any | None) -> dict[str, Any]:
    """Resolve the run's API base, rebase JS/API capture URLs, and allow session headers there.

    Pages in ``_capture_urls`` that are not API URLs are left on the target. Returns a
    value-free summary (also stored at ``ctx.extra['_api_base']``).
    """
    extra = ctx.extra
    target = str(getattr(ctx, "target_base_url", "") or "")
    auth = extra.get("_session_auth")
    refresh = getattr(auth, "refresh_origin", "") if auth is not None else ""
    base, source = resolve_api_base(
        asset_api_base=getattr(asset, "api_base_url", "") if asset is not None else "",
        refresh_url=refresh,
        target_base_url=target,
    )
    extra["_api_base_url"] = base
    info = {"url": base, "source": source}
    extra["_api_base"] = info
    if source == SOURCE_TARGET:
        return info

    api_urls = list(extra.get("_capture_api_urls") or [])
    if api_urls:
        mapping = {u: rebase_to_api(u, target, base) for u in api_urls}
        extra["_capture_api_urls"] = [mapping[u] for u in api_urls]
        caps = list(extra.get("_capture_urls") or [])
        if caps:
            api_keys = {u.rstrip("/"): mapping[u] for u in api_urls}
            extra["_capture_urls"] = [api_keys.get(u.rstrip("/"), u) for u in caps]
    api_origin = origin_of(base)
    for key in ("_session_auth", "_secondary_session_auth"):
        sess = extra.get(key)
        if sess is not None and api_origin and hasattr(sess, "allow_origin"):
            sess.allow_origin(api_origin)
    return info
