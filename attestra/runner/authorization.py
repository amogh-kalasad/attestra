"""Engagement-scoped target authorization for the runner plane.

Built from Attestra Authorization / Asset / Engagement records (no external scope files).
Deny ScopeRules are applied before allow-list checks.
"""
# @lat: [[authorization#Runner scope]]

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import date
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from attestra import services
from attestra.models import Asset, ScopeRule

# Shell / injection metacharacters never allowed in CLI args passed to scanners.
_UNSAFE_CLI = re.compile(r"[;|&`$]|\$\(|\n|\r")

# Always blocked even when allow_private is set (metadata / CGNAT / unspecified).
BLOCKED_CIDRS: tuple[ipaddress._BaseNetwork, ...] = tuple(
    ipaddress.ip_network(c)
    for c in (
        "0.0.0.0/8",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "fd00:ec2::254/128",
    )
)

# Home / office network ranges where a lead may confirm ownership by hand ("owner confirmed").
# These addresses have no DNS name, and the well-known file check refuses non-global IPs.
OWNER_CONFIRM_CIDRS: tuple[ipaddress._BaseNetwork, ...] = tuple(
    ipaddress.ip_network(c)
    for c in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "::1/128",
        "fc00::/7",
    )
)
OWNER_CONFIRMED = "owner_confirmed"


class AuthorizationError(Exception):
    """Target or engagement is outside the authorized scope."""


@dataclass(frozen=True)
class AuthorizedScope:
    name: str
    allowed_hosts: frozenset[str]
    allowed_urls: tuple[str, ...]
    allowed_paths: tuple[str, ...]
    allowed_images: tuple[str, ...]
    allow_private: bool = False
    deny_hosts: tuple[str, ...] = ()
    deny_urls: tuple[str, ...] = ()
    deny_paths: tuple[str, ...] = ()
    deny_images: tuple[str, ...] = ()
    deny_cidrs: tuple[str, ...] = ()
    # Asset identifiers that explicitly allow private/loopback (e.g. 127.0.0.1 fixtures).
    private_ok_hosts: frozenset[str] = field(default_factory=frozenset)


def scope_for_engagement(s: Session, engagement_id: int, on: date | None = None) -> AuthorizedScope:
    eng = services.get_engagement(s, engagement_id)
    envs = services.authorized_environments(eng, on)
    if not envs:
        raise AuthorizationError("no valid authorization")

    assets = [a for a in eng.assets if a.environment in envs]
    hosts: set[str] = set()
    urls: list[str] = []
    paths: list[str] = []
    images: list[str] = []
    private_ok: set[str] = set()

    confirmed = {
        aid for aid, method in services.ownership_methods(s, [a.id for a in assets]).items()
        if method == OWNER_CONFIRMED
    }
    for a in assets:
        _classify_asset(a, hosts, urls, paths, images, private_ok)
        # A private address the owner confirmed may be reached (BLOCKED_CIDRS stay refused at pin time).
        if a.id in confirmed and a.ownership_verified_at is not None:
            host = owner_confirm_host(a.kind, a.identifier)
            if host:
                private_ok.add(host)

    deny_hosts, deny_urls, deny_paths, deny_images, deny_cidrs = _load_deny_rules(s, engagement_id)

    return AuthorizedScope(
        name=eng.name,
        allowed_hosts=frozenset(hosts),
        allowed_urls=tuple(urls),
        allowed_paths=tuple(paths),
        allowed_images=tuple(images),
        allow_private=bool(private_ok),
        deny_hosts=deny_hosts,
        deny_urls=deny_urls,
        deny_paths=deny_paths,
        deny_images=deny_images,
        deny_cidrs=deny_cidrs,
        private_ok_hosts=frozenset(private_ok),
    )


def owner_confirm_host(kind: str, identifier: str) -> str:
    """Host of a target whose owner may confirm control by hand, or '' when that is not allowed.

    Only a literal private or loopback IP address (OWNER_CONFIRM_CIDRS) or ``localhost`` qualifies.
    Public IPs, domain names and BLOCKED_CIDRS never do; they must prove control with DNS or the file.
    """
    ident = (identifier or "").strip()
    if kind in ("web_app", "api"):
        parts = urlsplit(ident)
        if parts.scheme not in ("http", "https"):
            return ""
        host = (parts.hostname or "").lower()
    elif kind == "host":
        if "/" in ident:
            return ""  # a range, not one address
        host = ident.lower().strip("[]")
    else:
        return ""
    if host == "localhost":
        return host
    try:
        ip = unwrap_ip(ipaddress.ip_address(host))
    except ValueError:
        return ""
    if any(ip in net for net in BLOCKED_CIDRS):
        return ""
    return host if any(ip in net for net in OWNER_CONFIRM_CIDRS) else ""


def _classify_asset(
    a: Asset,
    hosts: set[str],
    urls: list[str],
    paths: list[str],
    images: list[str],
    private_ok: set[str],
) -> None:
    kind = a.kind
    ident = a.identifier.strip()
    notes = (a.notes or "").lower()
    allow_priv = "allow_private" in notes or ident.startswith("http://127.0.0.1") or ident.startswith("https://127.0.0.1")

    if kind in ("web_app", "api", "url"):
        parts = urlsplit(ident)
        if parts.scheme and parts.netloc:
            host = parts.hostname or parts.netloc.split("@")[-1].split(":")[0]
            hosts.add(host.lower())
            urls.append(ident.rstrip("/"))
            if allow_priv or host in ("127.0.0.1", "localhost", "::1"):
                private_ok.add(host.lower())
    elif kind in ("repo",):
        paths.append(ident.replace("\\", "/").rstrip("/"))
    elif kind == "image":
        images.append(ident)
    elif kind == "host":
        host = ident.split("/")[0].lower()
        hosts.add(host)
        if allow_priv or host in ("127.0.0.1", "localhost", "::1"):
            private_ok.add(host)


def _load_deny_rules(
    s: Session, engagement_id: int
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    from sqlalchemy import select

    rules = list(
        s.scalars(select(ScopeRule).where(ScopeRule.engagement_id == engagement_id, ScopeRule.action == "deny"))
    )
    hosts: list[str] = []
    urls: list[str] = []
    paths: list[str] = []
    images: list[str] = []
    cidrs: list[str] = []
    for r in rules:
        bucket = {"host": hosts, "url": urls, "path": paths, "image": images, "cidr": cidrs}.get(r.kind)
        if bucket is not None:
            bucket.append(r.pattern)
    return tuple(hosts), tuple(urls), tuple(paths), tuple(images), tuple(cidrs)


def authorize_target(scope: AuthorizedScope, target: str, kind: str) -> None:
    """Raise AuthorizationError if target is not in scope. Deny rules win over allow."""
    kind = kind.lower()
    if kind in ("url", "web_app", "api", "http"):
        validate_url_target(scope, target)
    elif kind in ("path", "repo", "fs"):
        validate_path_target(scope, target)
    elif kind in ("image", "container"):
        validate_image_target(scope, target)
    elif kind == "host":
        host = target.strip().lower()
        _check_deny_host(scope, host)
        if host not in scope.allowed_hosts:
            raise AuthorizationError(f"host not in scope: {host}")
    else:
        raise AuthorizationError(f"unknown target kind: {kind}")


def validate_url_target(scope: AuthorizedScope, url: str) -> None:
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https"):
        raise AuthorizationError(f"unsupported URL scheme: {parts.scheme!r}")
    if not parts.hostname:
        raise AuthorizationError("URL missing host")
    host = parts.hostname.lower()

    _check_deny_host(scope, host)
    for pattern in scope.deny_urls:
        if fnmatch.fnmatch(url, pattern) or fnmatch.fnmatch(parts.path or "/", pattern):
            raise AuthorizationError(f"URL denied by scope rule: {pattern}")

    if host not in scope.allowed_hosts:
        raise AuthorizationError(f"host not in scope: {host}")

    # If an allowed URL for this host specifies a port, the target must match it.
    host_urls = [u for u in scope.allowed_urls if (urlsplit(u).hostname or "").lower() == host]
    if host_urls:
        allowed_ports = {urlsplit(u).port for u in host_urls}
        if None not in allowed_ports and parts.port not in allowed_ports and parts.port is not None:
            raise AuthorizationError(f"port {parts.port} not authorized for {host}")
        # Path prefix: target path must be under at least one allowed URL path prefix
        target_path = parts.path or "/"
        path_ok = False
        for u in host_urls:
            prefix = urlsplit(u).path or "/"
            if target_path == prefix or target_path.startswith(prefix.rstrip("/") + "/") or prefix in ("", "/"):
                path_ok = True
                break
        if not path_ok:
            raise AuthorizationError(f"path outside allowed URL prefixes: {url}")


def validate_path_target(scope: AuthorizedScope, path: str) -> None:
    norm = path.replace("\\", "/").strip()
    for pattern in scope.deny_paths:
        if fnmatch.fnmatch(norm, pattern) or norm.startswith(pattern.rstrip("*")):
            raise AuthorizationError(f"path denied by scope rule: {pattern}")
    if not scope.allowed_paths:
        raise AuthorizationError("no paths in scope")
    if not any(norm == p or norm.startswith(p.rstrip("/") + "/") or p.endswith("*") and fnmatch.fnmatch(norm, p) for p in scope.allowed_paths):
        raise AuthorizationError(f"path outside allowed prefixes: {path}")


def validate_image_target(scope: AuthorizedScope, image: str) -> None:
    image = image.strip()
    for pattern in scope.deny_images:
        if _image_allowed(image, pattern) or fnmatch.fnmatch(image, pattern):
            raise AuthorizationError(f"image denied by scope rule: {pattern}")
    if not any(_image_allowed(image, allowed) for allowed in scope.allowed_images):
        raise AuthorizationError(f"image not in scope: {image}")


def _image_allowed(image: str, allowed: str) -> bool:
    """Exact match unless allowed ends with *; avoids nginx allowing nginx-evil."""
    if allowed.endswith("*"):
        return image.startswith(allowed[:-1])
    return image == allowed


def _check_deny_host(scope: AuthorizedScope, host: str) -> None:
    for pattern in scope.deny_hosts:
        if fnmatch.fnmatch(host, pattern) or host == pattern:
            raise AuthorizationError(f"host denied by scope rule: {pattern}")


def unwrap_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    ip = unwrap_ip(ip)
    # Mapped/unwrapped loopback is a classic SSRF pivot; treat like an explicit block.
    if ip.is_loopback:
        return True
    return any(ip in net for net in BLOCKED_CIDRS)


def is_private_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    ip = unwrap_ip(ip)
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or not ip.is_global


def validate_resolved_ips(
    ips: list[str] | list[ipaddress.IPv4Address | ipaddress.IPv6Address],
    *,
    allow_private: bool = False,
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Validate resolved addresses. Raises AuthorizationError if any are blocked."""
    out: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for raw in ips:
        ip = unwrap_ip(ipaddress.ip_address(raw) if not isinstance(raw, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else raw)
        if is_blocked_ip(ip):
            raise AuthorizationError(f"blocked IP: {ip}")
        if not allow_private and (not ip.is_global or is_private_ip(ip)):
            raise AuthorizationError(f"non-global IP not allowed: {ip}")
        if allow_private and is_blocked_ip(ip):
            raise AuthorizationError(f"blocked IP: {ip}")
        # Even with allow_private, keep BLOCKED_CIDRS denied (already checked).
        out.append(ip)
    if not out:
        raise AuthorizationError("no resolved IPs")
    return out


def assert_safe_cli_arg(arg: str) -> str:
    if _UNSAFE_CLI.search(arg):
        raise AuthorizationError(f"unsafe characters in CLI argument: {arg!r}")
    return arg
