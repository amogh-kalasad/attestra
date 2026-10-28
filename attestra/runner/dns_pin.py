"""Resolve a host once, validate IPs, and pin a single connect address."""
# @lat: [[authorization#Runner scope]]

from __future__ import annotations

import ipaddress
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


# RFC 6052 well-known NAT64 prefix. DNS64 resolvers synthesize these from a host's
# real A record, so 64:ff9b::a.b.c.d is just a.b.c.d reached through a translator.
_NAT64_WKP = ipaddress.ip_network("64:ff9b::/96")


def drop_nat64_duplicates(ips: list[str]) -> list[str]:
    """Remove DNS64-synthesized IPv6 addresses whose embedded IPv4 was also returned.

    Only drops an address when the same IPv4 is present in the answer, so every
    remaining address is still validated as strictly as before. A lone NAT64
    address (no matching A record) is kept and validation refuses it as usual.
    """
    v4 = {ip for ip in ips if ":" not in ip}
    out: list[str] = []
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            out.append(ip)
            continue
        if addr.version == 6 and addr in _NAT64_WKP:
            embedded = str(ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF))
            if embedded in v4:
                continue
        out.append(ip)
    return out


def pin_url(url: str, scope: AuthorizedScope, *, resolver=resolve_host) -> PinnedTarget:
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise AuthorizationError(f"cannot pin URL: {url}")
    host = parts.hostname.lower()
    port = parts.port or (443 if parts.scheme == "https" else 80)
    allow_private = scope.allow_private and (
        not scope.private_ok_hosts or host in scope.private_ok_hosts or host in ("127.0.0.1", "localhost", "::1")
    )
    ips = drop_nat64_duplicates(resolver(host))
    validated = validate_resolved_ips(ips, allow_private=allow_private or host in ("127.0.0.1", "localhost"))
    # Prefer IPv4 for stable connect; fall back to the first validated address.
    v4 = [ip for ip in validated if ip.version == 4]
    chosen = str(v4[0] if v4 else validated[0])
    return PinnedTarget(host=host, ip=chosen, port=port, scheme=parts.scheme)
