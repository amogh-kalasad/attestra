"""URL allowlist and SSRF guards for authenticated website crawl scope.

Reuses [[attestra/runner/authorization.py]] IP policy and optionally
[[attestra/runner/dns_pin.py#resolve_host]] for hostname resolution checks.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

from attestra.runner.authorization import (
    AuthorizationError,
    is_blocked_ip,
    is_private_ip,
    unwrap_ip,
    validate_resolved_ips,
)
from attestra.runner.dns_pin import resolve_host

SAFE_SCHEMES = frozenset({"http", "https"})


class ScopeError(AuthorizationError):
    """URL is outside crawl allowlist or fails SSRF policy."""


@dataclass(frozen=True)
class CrawlScope:
    """Same-origin / path-prefix allowlist derived from approved seed URLs."""

    allowed_origins: frozenset[str]
    allowed_path_prefixes: tuple[str, ...] = ("/",)
    allow_private: bool = False
    # Optional hostnames that may resolve to private IPs when allow_private is set.
    private_ok_hosts: frozenset[str] = frozenset()


def origin_of(url: str) -> str:
    """Return ``scheme://host[:port]`` (lowercase host) for an absolute URL."""
    parts = urlsplit((url or "").strip())
    if parts.scheme not in SAFE_SCHEMES or not parts.hostname:
        raise ScopeError(f"cannot derive origin from URL: {url!r}")
    host = parts.hostname.lower()
    port = parts.port
    default = 443 if parts.scheme == "https" else 80
    if port and port != default:
        return f"{parts.scheme}://{host}:{port}"
    return f"{parts.scheme}://{host}"


def scope_from_seeds(
    seeds: list[str] | tuple[str, ...],
    *,
    allow_private: bool = False,
) -> CrawlScope:
    """Build a crawl scope from approved seed URLs (same origin + path prefixes)."""
    origins: set[str] = set()
    prefixes: list[str] = []
    private_ok: set[str] = set()
    for raw in seeds:
        url = (raw or "").strip()
        if not url:
            continue
        parts = urlsplit(url)
        if parts.scheme not in SAFE_SCHEMES or not parts.hostname:
            raise ScopeError(f"seed URL must be absolute http(s): {url!r}")
        host = parts.hostname.lower()
        _assert_host_not_ssrf(host, allow_private=allow_private)
        origins.add(origin_of(url))
        path = parts.path or "/"
        if not path.endswith("/"):
            # Keep directory-ish prefixes; file-like seeds still allow the exact path parent.
            if "." in path.rsplit("/", 1)[-1]:
                path = path.rsplit("/", 1)[0] + "/" if "/" in path else "/"
            else:
                path = path + "/"
        if path not in prefixes:
            prefixes.append(path)
        if allow_private or host in ("127.0.0.1", "localhost", "::1"):
            private_ok.add(host)
    if not origins:
        raise ScopeError("at least one approved seed URL is required")
    return CrawlScope(
        allowed_origins=frozenset(origins),
        allowed_path_prefixes=tuple(prefixes) if prefixes else ("/",),
        allow_private=allow_private,
        private_ok_hosts=frozenset(private_ok),
    )


def is_same_origin(a: str, b: str) -> bool:
    try:
        return origin_of(a) == origin_of(b)
    except ScopeError:
        return False


def is_in_scope(url: str, scope: CrawlScope) -> bool:
    """Return True when URL matches an allowed origin and path prefix (no DNS)."""
    try:
        assert_url_shape(url)
        _assert_host_not_ssrf(urlsplit(url).hostname or "", allow_private=scope.allow_private)
        origin = origin_of(url)
        if origin not in scope.allowed_origins:
            return False
        path = urlsplit(url).path or "/"
        return any(path == p.rstrip("/") or path.startswith(p) or p == "/" for p in scope.allowed_path_prefixes)
    except ScopeError:
        return False


def assert_url_shape(url: str) -> None:
    parts = urlsplit((url or "").strip())
    if parts.scheme not in SAFE_SCHEMES:
        raise ScopeError(f"unsafe URL scheme: {parts.scheme!r}")
    if not parts.hostname:
        raise ScopeError("URL missing host")
    if parts.username or parts.password:
        raise ScopeError("credentials in URL are not allowed")


def _assert_host_not_ssrf(host: str, *, allow_private: bool) -> None:
    host = (host or "").lower().strip("[]")
    if not host:
        raise ScopeError("URL missing host")
    # Cloud metadata and internal DNS zones are always refused.
    if host in ("metadata", "metadata.google.internal") or host.endswith(
        (".local", ".internal", ".intranet", ".corp")
    ):
        raise ScopeError(f"blocked host: {host}")
    if host == "localhost" or host.endswith(".localhost"):
        if not allow_private:
            raise ScopeError(f"blocked host: {host}")
        return
    # Literal IP in the hostname.
    try:
        ip = unwrap_ip(ipaddress.ip_address(host))
    except ValueError:
        return
    if is_blocked_ip(ip):
        raise ScopeError(f"blocked IP: {ip}")
    if not allow_private and (is_private_ip(ip) or not ip.is_global):
        raise ScopeError(f"non-global IP not allowed: {ip}")


def assert_url_in_scope(
    url: str,
    scope: CrawlScope,
    *,
    resolver=resolve_host,
    check_dns: bool = True,
) -> None:
    """Raise ScopeError if the URL fails scheme/SSRF/allowlist checks."""
    assert_url_shape(url)
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower()
    _assert_host_not_ssrf(host, allow_private=scope.allow_private)

    origin = origin_of(url)
    if origin not in scope.allowed_origins:
        raise ScopeError(f"origin not in crawl scope: {origin}")

    path = parts.path or "/"
    path_ok = any(path == p.rstrip("/") or path.startswith(p) or p == "/" for p in scope.allowed_path_prefixes)
    if not path_ok:
        raise ScopeError(f"path outside allowed prefixes: {path}")

    if not check_dns:
        return

    allow_private = scope.allow_private and (
        not scope.private_ok_hosts or host in scope.private_ok_hosts or host in ("127.0.0.1", "localhost", "::1")
    )
    # Literal IPs already validated above; still run through validate for consistency.
    try:
        ipaddress.ip_address(host)
        validate_resolved_ips([host], allow_private=allow_private)
        return
    except ValueError:
        pass
    except AuthorizationError as exc:
        raise ScopeError(str(exc)) from exc

    try:
        ips = resolver(host)
        validate_resolved_ips(ips, allow_private=allow_private)
    except AuthorizationError as exc:
        raise ScopeError(str(exc)) from exc
    except OSError as exc:
        raise ScopeError(f"cannot resolve {host}: {exc}") from exc


def resolve_redirect_url(current: str, location: str) -> str:
    """Join a redirect Location against the current URL."""
    if not location:
        raise ScopeError("empty redirect location")
    return urljoin(current, location)


def assert_redirect_in_scope(
    current: str,
    location: str,
    scope: CrawlScope,
    *,
    resolver=resolve_host,
    check_dns: bool = True,
) -> str:
    """Validate a redirect target stays in crawl scope; return the absolute URL."""
    nxt = resolve_redirect_url(current, location)
    try:
        assert_url_in_scope(nxt, scope, resolver=resolver, check_dns=check_dns)
    except ScopeError as exc:
        raise ScopeError(f"out-of-scope redirect blocked: {exc}") from exc
    return nxt


def strip_userinfo(url: str) -> str:
    """Return URL without userinfo (never log credentials)."""
    parts = urlsplit(url)
    if not parts.username and not parts.password:
        return url
    netloc = parts.hostname or ""
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
