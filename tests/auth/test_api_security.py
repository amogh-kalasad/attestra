"""Security headers and rate limiting."""
# @lat: [[tests#Phase 2 auth tests#tests/auth/test_api_security.py]]

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from attestra.api_security import RateLimiter, RateLimitMiddleware, SecurityHeadersMiddleware


def test_security_headers_present(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert r.headers.get("Referrer-Policy") == "no-referrer"
    assert "default-src" in (r.headers.get("Content-Security-Policy") or "")


def test_rate_limiter_blocks_after_limit():
    limiter = RateLimiter(limit=3, window_s=60.0)
    assert limiter.allow("k")
    assert limiter.allow("k")
    assert limiter.allow("k")
    assert not limiter.allow("k")


def test_rate_limit_middleware_returns_429():
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, limiter=RateLimiter(limit=2, window_s=60.0))

    @app.get("/api/ping")
    def ping():
        return {"ok": True}

    with TestClient(app) as c:
        assert c.get("/api/ping").status_code == 200
        assert c.get("/api/ping").status_code == 200
        assert c.get("/api/ping").status_code == 429


def test_security_headers_middleware_alone():
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/x")
    def x():
        return {"ok": True}

    with TestClient(app) as c:
        r = c.get("/x")
        assert r.headers["X-Frame-Options"] == "DENY"
