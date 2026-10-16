"""Offline tests for webcheck adapter, checks, importer, and follow_redirects."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from attestra.importers import webcheck as webcheck_importer
from attestra.runner.authorization import AuthorizedScope
from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.http_safe import safe_get
from attestra.runner.scanners import webcheck as wc
from attestra.runner.scanners.webcheck import WebcheckAdapter


def _scope(host: str = "127.0.0.1", *url_prefixes: str) -> AuthorizedScope:
    urls = url_prefixes or (f"http://{host}",)
    return AuthorizedScope(
        name="test",
        allowed_hosts=frozenset([host]),
        allowed_urls=tuple(urls),
        allowed_paths=(),
        allowed_images=(),
        allow_private=True,
        private_ok_hosts=frozenset([host]),
    )


def _run_server(handler_cls):
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, "127.0.0.1", port


# ---------------------------------------------------------------- check unit tests


def test_csp_base_uri_missing():
    f = wc.check_csp_base_uri({"content-security-policy": "default-src 'self'"}, "https://ex/")
    assert f and f["id"] == "csp-base-uri"


def test_csp_base_uri_present():
    assert wc.check_csp_base_uri({"content-security-policy": "default-src 'self'; base-uri 'self'"}, "u") is None


def test_server_disclosure_version_is_low():
    f = wc.check_server_disclosure({"server": "nginx/1.24.0"}, "u")
    assert f and f["severity"] == "low"


def test_referrer_policy_strict_origin_when_cross_origin_is_finding():
    f = wc.check_referrer_policy({"referrer-policy": "strict-origin-when-cross-origin"}, "u")
    assert f and f["id"] == "referrer-policy"


def test_referrer_policy_no_referrer_ok():
    assert wc.check_referrer_policy({"referrer-policy": "no-referrer"}, "u") is None


def test_http_no_redirect_ok_on_301_https():
    resp = wc.SafeResponse(301, {"location": "https://ex/"}, b"", "http://ex/")
    assert wc.check_http_no_redirect(resp, "http://ex/") is None


def test_waf_seen_via_cf_ray():
    assert wc.check_waf_none_seen({"cf-ray": "abc"}, "u") is None


def test_parent_domain():
    assert wc.parent_domain("www.example.com") == "example.com"
    assert wc.parent_domain("example.com") is None


# ---------------------------------------------------------------- follow_redirects


class _RedirectOnce(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "http://127.0.0.1/next")
        self.end_headers()

    def log_message(self, *args):
        pass


def test_follow_redirects_false_returns_redirect(tmp_path: Path):
    server, host, port = _run_server(_RedirectOnce)
    try:
        scope = _scope(host, f"http://{host}")
        # Location host is in scope but we must not follow when disabled.
        pin = PinnedTarget(host=host, ip=host, port=port, scheme="http")
        resp = safe_get(f"http://{host}:{port}/", scope=scope, pin=pin, follow_redirects=False)
        assert resp.status == 302
        assert resp.headers["location"].startswith("http://")
    finally:
        server.shutdown()


# ---------------------------------------------------------------- bad / good servers


class _BadHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/.well-known/security.txt"):
            body = b"<html>not security txt</html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = b"bad"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("Server", "nginx")
        self.send_header("X-XSS-Protection", "1; mode=block")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class _GoodHandler(BaseHTTPRequestHandler):
    # Suppress BaseHTTP's default Server header so good fixtures stay clean.
    server_version = ""
    sys_version = ""

    def version_string(self):
        return ""

    def do_GET(self):
        if self.path.startswith("/.well-known/security.txt"):
            body = b"Contact: mailto:security@example.com\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", "default-src 'self'; base-uri 'self'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("CF-Ray", "test-ray-id")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def bad_server():
    server, host, port = _run_server(_BadHandler)
    yield host, port
    server.shutdown()


@pytest.fixture
def good_server():
    server, host, port = _run_server(_GoodHandler)
    yield host, port
    server.shutdown()


def test_adapter_bad_server_findings(bad_server, tmp_path: Path):
    host, port = bad_server
    scope = _scope(host, f"http://{host}")
    pin = PinnedTarget(host=host, ip=host, port=port, scheme="http")
    result = WebcheckAdapter().scan(pin, out_dir=tmp_path, scope=scope)
    assert not result.error
    assert result.raw_path and result.raw_path.exists()
    doc = json.loads(result.raw_path.read_text(encoding="utf-8"))
    ids = {f["id"] for f in doc["findings"]}
    assert "csp-base-uri" in ids
    assert "server-disclosure" in ids
    assert "x-xss-protection" in ids
    assert "referrer-policy" in ids
    assert "security-txt" in ids
    assert "expect-ct" in ids


def test_adapter_good_server_only_expect_ct(good_server, tmp_path: Path):
    host, port = good_server
    scope = _scope(host, f"http://{host}")
    pin = PinnedTarget(host=host, ip=host, port=port, scheme="http")
    result = WebcheckAdapter().scan(pin, out_dir=tmp_path, scope=scope)
    assert not result.error
    doc = json.loads(result.raw_path.read_text(encoding="utf-8"))
    ids = {f["id"] for f in doc["findings"]}
    # http-only loopback: upgrade/parent/preload checks skipped or N/A.
    assert ids == {"expect-ct"}


def test_adapter_requires_scope(tmp_path: Path):
    pin = PinnedTarget(host="127.0.0.1", ip="127.0.0.1", port=80, scheme="http")
    result = WebcheckAdapter().scan(pin, out_dir=tmp_path, scope=None)
    assert result.error and "scope" in result.error.lower()


def test_importer_parse_variant():
    raw = json.dumps(
        {
            "requests": [],
            "findings": [
                {
                    "id": "csp-base-uri",
                    "title": "CSP: base-uri directive missing",
                    "severity": "low",
                    "cwe": 693,
                    "description": "missing",
                    "location": "https://ex/",
                }
            ],
            "notes": [],
        }
    ).encode()
    findings = webcheck_importer.parse(raw)
    assert len(findings) == 1
    nf = findings[0]
    assert nf.tool == "webcheck"
    assert nf.rule_id == "webcheck/csp-base-uri"
    assert nf.variant == "csp-base-uri"
    assert nf.cwe == 693
    assert nf.severity == "low"
