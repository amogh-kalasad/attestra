"""Resolve a host once, validate IPs, and pin a single connect address."""
# @lat: [[authorization#Runner scope]]

from __future__ import annotations

import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

from attestra.runner.authorization import AuthorizationError, AuthorizedScope, validate_resolved_ips


@dataclass(frozen=True)
class PinnedTarget:
    host: str
    ip: str
    port: int
    scheme: str

    @property
    def connect_url(self) -> str:
        return f"{self.scheme}://{self.ip}:{self.port}"

    @property
    def host_header(self) -> str:
        default = 443 if self.scheme == "https" else 80
        if self.port == default:
            return self.host
        return f"{self.host}:{self.port}"

    @property
    def sni_hostname(self) -> str:
        return self.host


def resolve_host(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    ips: list[str] = []
    seen: set[str] = set()
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)
    return ips


def pin_url(url: str, scope: AuthorizedScope, *, resolver=resolve_host) -> PinnedTarget:
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise AuthorizationError(f"cannot pin URL: {url}")
    host = parts.hostname.lower()
    port = parts.port or (443 if parts.scheme == "https" else 80)
    allow_private = scope.allow_private and (
        not scope.private_ok_hosts or host in scope.private_ok_hosts or host in ("127.0.0.1", "localhost", "::1")
    )
    ips = resolver(host)
    validated = validate_resolved_ips(ips, allow_private=allow_private or host in ("127.0.0.1", "localhost"))
    # Prefer IPv4 for stable connect; pick first validated.
    chosen = str(validated[0])
    return PinnedTarget(host=host, ip=chosen, port=port, scheme=parts.scheme)
