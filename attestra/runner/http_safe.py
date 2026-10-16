"""HTTP client that connects only to a pinned IP and re-authorizes every redirect."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from http.client import HTTPConnection, HTTPSConnection
from urllib.parse import urljoin, urlsplit

from sqlalchemy.orm import Session

from attestra import audit
from attestra.runner.authorization import AuthorizationError, AuthorizedScope, authorize_target
from attestra.runner.dns_pin import PinnedTarget, pin_url

MAX_REDIRECTS = 5
MAX_BODY = 2_000_000


@dataclass
class SafeResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    final_url: str


def resolve_redirect_url(current: str, location: str) -> str:
    return urljoin(current, location)


def safe_request(
    method: str,
    url: str,
    *,
    scope: AuthorizedScope,
    session: Session | None = None,
    actor: str = "runner",
    pin: PinnedTarget | None = None,
    max_redirects: int = MAX_REDIRECTS,
    max_body: int = MAX_BODY,
    resolver=None,
    follow_redirects: bool = True,
) -> SafeResponse:
    current = url
    pin_fn = (lambda u, sc: pin_url(u, sc, resolver=resolver)) if resolver else pin_url
    for _ in range(max_redirects + 1):
        try:
            authorize_target(scope, current, "url")
        except AuthorizationError as exc:
            _refuse(session, actor, current, str(exc))
            raise
        target = pin or pin_fn(current, scope)
        pin = None  # only first hop may reuse an explicit pin
        conn = _connect(target)
        try:
            path = urlsplit(current).path or "/"
            query = urlsplit(current).query
            if query:
                path = f"{path}?{query}"
            conn.request(method, path, headers={"Host": target.host_header, "User-Agent": "attestra-safe/0.1"})
            resp = conn.getresponse()
            body = resp.read(max_body + 1)
            if len(body) > max_body:
                raise AuthorizationError("response body exceeds size limit")
            # Preserve every Set-Cookie line (dict would keep only the last one).
            headers: dict[str, str] = {}
            for k, v in resp.getheaders():
                key = k.lower()
                if key == "set-cookie" and key in headers:
                    headers[key] = f"{headers[key]}\n{v}"
                else:
                    headers[key] = v
            if resp.status in (301, 302, 303, 307, 308) and "location" in headers:
                if not follow_redirects:
                    return SafeResponse(status=resp.status, headers=headers, body=body, final_url=current)
                nxt = resolve_redirect_url(current, headers["location"])
                try:
                    authorize_target(scope, nxt, "url")
                except AuthorizationError as exc:
                    _refuse(session, actor, nxt, str(exc))
                    raise
                current = nxt
                continue
            return SafeResponse(status=resp.status, headers=headers, body=body, final_url=current)
        finally:
            conn.close()
    raise AuthorizationError("too many redirects")


def safe_get(url: str, **kwargs) -> SafeResponse:
    return safe_request("GET", url, **kwargs)


class _PinnedHTTPSConnection(HTTPSConnection):
    """Connect to ``pin.ip`` but present SNI and verify the cert for ``pin.host``."""

    def __init__(self, pin: PinnedTarget, timeout: float = 30):
        ctx = ssl.create_default_context()
        super().__init__(pin.ip, pin.port, context=ctx, timeout=timeout)
        self._pin = pin

    def connect(self) -> None:
        sock = socket.create_connection((self._pin.ip, self._pin.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._pin.sni_hostname)


def _connect(pin: PinnedTarget):
    if pin.scheme == "https":
        return _PinnedHTTPSConnection(pin, timeout=30)
    return HTTPConnection(pin.ip, pin.port, timeout=30)


def _refuse(session: Session | None, actor: str, url: str, reason: str) -> None:
    if session is None:
        return
    audit.record(session, actor, "http.refused", "url", None, url=url, reason=reason)
