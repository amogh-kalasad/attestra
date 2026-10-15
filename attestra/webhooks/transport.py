"""Minimal HTTP client that connects to an already-validated IP (no DNS at send time).

Used by webhook delivery and proof replay so DNS rebinding cannot move the
connection after the SSRF / scope checks ran. Redirects are never followed.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from http.client import HTTPConnection, HTTPSConnection

from attestra.runner.dns_pin import PinnedTarget

MAX_BODY = 1_000_000


@dataclass
class RawResponse:
    status: int
    headers: dict[str, str]
    body: bytes


class _PinnedHTTPS(HTTPSConnection):
    """Connect to ``pin.ip`` but verify the certificate for ``pin.host`` (SNI)."""

    def __init__(self, pin: PinnedTarget, timeout: float):
        super().__init__(pin.ip, pin.port, timeout=timeout, context=ssl.create_default_context())
        self._pin = pin

    def connect(self) -> None:
        sock = socket.create_connection((self._pin.ip, self._pin.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._pin.sni_hostname)


def pinned_request(
    pin: PinnedTarget,
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = 10.0,
    max_body: int = MAX_BODY,
) -> RawResponse:
    conn = _PinnedHTTPS(pin, timeout) if pin.scheme == "https" else HTTPConnection(pin.ip, pin.port, timeout=timeout)
    try:
        hdrs = {k: v for k, v in (headers or {}).items() if k.lower() not in ("host", "content-length")}
        hdrs["Host"] = pin.host_header
        conn.request(method, path or "/", body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read(max_body + 1)[:max_body]
        return RawResponse(status=resp.status, headers={k.lower(): v for k, v in resp.getheaders()}, body=data)
    finally:
        conn.close()
