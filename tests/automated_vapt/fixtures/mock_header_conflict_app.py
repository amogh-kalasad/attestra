"""Header-conflict mock: the same origin answers with different security headers per path.

Local-only fixture. Do not deploy. It reproduces the real-world shape where a scanner
flags "HSTS missing" on one URL while another response on the same host proves HSTS is
set, and where Permissions-Policy is present on the document but absent on a script asset.

Paths:

- ``/with-hsts``      HTML with ``Strict-Transport-Security: max-age=31536000; includeSubDomains``
- ``/without-hsts``   HTML with no HSTS header
- ``/``               HTML document with ``Permissions-Policy`` and ``X-Frame-Options: SAMEORIGIN``
- ``/static/app.js``  JS asset with long cache and *no* Permissions-Policy / XFO
- ``/api/ping``       JSON with ``Content-Security-Policy: frame-ancestors 'none'`` but no XFO
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse, JSONResponse

MODE = "header_conflict"
HSTS_VALUE = "max-age=31536000; includeSubDomains"
PERMISSIONS_POLICY_VALUE = "camera=(), microphone=(), geolocation=()"


def _doc(title: str) -> str:
    return (
        f"<!doctype html><html><head><title>{title}</title>"
        "<script src='/static/app.js'></script></head>"
        f"<body><h1>{title}</h1>"
        "<a href='/with-hsts'>with</a> <a href='/without-hsts'>without</a> "
        "<a href='/api/ping'>ping</a></body></html>"
    )


def create_header_conflict_app() -> FastAPI:
    app = FastAPI(title="Attestra header-conflict mock", docs_url=None, redoc_url=None)

    @app.get("/__attestra_mock__")
    def mock_meta() -> dict[str, Any]:
        return {"mode": MODE, "local_only": True, "purpose": "elite_automated_security_testing_fixtures"}

    @app.get("/", response_class=HTMLResponse)
    def home() -> Response:
        resp = HTMLResponse(_doc("Home"))
        resp.headers["permissions-policy"] = PERMISSIONS_POLICY_VALUE
        resp.headers["x-frame-options"] = "SAMEORIGIN"
        resp.headers["strict-transport-security"] = HSTS_VALUE
        return resp

    @app.get("/with-hsts", response_class=HTMLResponse)
    def with_hsts() -> Response:
        resp = HTMLResponse(_doc("With HSTS"))
        resp.headers["strict-transport-security"] = HSTS_VALUE
        resp.headers["permissions-policy"] = PERMISSIONS_POLICY_VALUE
        return resp

    @app.get("/without-hsts", response_class=HTMLResponse)
    def without_hsts() -> Response:
        # Intentionally no HSTS and no Permissions-Policy on this document.
        return HTMLResponse(_doc("Without HSTS"))

    @app.get("/static/app.js")
    def script_asset() -> Response:
        resp = Response(content="console.log('synthetic asset');", media_type="application/javascript")
        resp.headers["cache-control"] = "public, max-age=31536000, immutable"
        # No Permissions-Policy / XFO on an asset is expected, not a finding.
        return resp

    @app.get("/api/ping")
    def ping() -> Response:
        resp = JSONResponse({"ok": True})
        resp.headers["content-security-policy"] = "frame-ancestors 'none'"
        return resp

    return app
