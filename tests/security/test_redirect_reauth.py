"""Tests for redirect re-authorization — safe_get must refuse SSRF via 302."""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from attestra.runner.authorization import AuthorizationError, AuthorizedScope
from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.http_safe import safe_get


def _scope_allowing_loopback(host: str = "127.0.0.1") -> AuthorizedScope:
    """Scope that allows only the loopback test server."""
    return AuthorizedScope(
        name="test",
        allowed_hosts=frozenset([host]),
        allowed_urls=(f"http://{host}",),
        allowed_paths=(),
        allowed_images=(),
        allow_private=True,
        private_ok_hosts=frozenset([host]),
    )


class _RedirectHandler(BaseHTTPRequestHandler):
    """Always 302 to evil.example.com."""

    redirect_to = "https://evil.example.com/sensitive"

    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", self.redirect_to)
        self.end_headers()

    def log_message(self, *args):
        pass  # silence test output


@pytest.fixture
def redirect_server():
    server = HTTPServer(("127.0.0.1", 0), _RedirectHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield ("127.0.0.1", port)
    server.shutdown()


# ---------------------------------------------------------------- redirect to out-of-scope host raises


def test_safe_get_refuses_redirect_to_out_of_scope(redirect_server):
    host, port = redirect_server
    scope = _scope_allowing_loopback(host)

    # Provide a pre-built PinnedTarget so we skip DNS for the loopback server.
    pin = PinnedTarget(host=host, ip=host, port=port, scheme="http")

    with pytest.raises(AuthorizationError):
        safe_get(
            f"http://{host}:{port}/start",
            scope=scope,
            pin=pin,
        )


# ---------------------------------------------------------------- scope that allows follow is fine (sanity)


class _OkHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


@pytest.fixture
def ok_server():
    server = HTTPServer(("127.0.0.1", 0), _OkHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield ("127.0.0.1", port)
    server.shutdown()


def test_safe_get_direct_200(ok_server):
    host, port = ok_server
    scope = _scope_allowing_loopback(host)
    pin = PinnedTarget(host=host, ip=host, port=port, scheme="http")

    resp = safe_get(f"http://{host}:{port}/", scope=scope, pin=pin)
    assert resp.status == 200
    assert resp.body == b"ok"
