"""Cloudflare-style WAF / JS-challenge mock for noise-classification and crawler tests.

Local-only fixture. Do not deploy. Behaviour:

- ``/`` and any unknown path answer with a 403 "Just a moment..." challenge page that
  references ``/cdn-cgi/challenge-platform/...`` and sets ``cf_clearance`` / ``__cf_bm``
  cookies without ``SameSite`` (the exact shape that produces scanner noise).
- ``/cdn-cgi/challenge-platform/h/b/orchestrate/jsch/v1`` serves a cacheable JS blob
  with ``Access-Control-Allow-Origin: *`` (CDN CORS noise).
- ``/cdn-cgi/trace`` returns the usual plain-text trace block.
- Requests carrying a ``cf_clearance`` cookie equal to ``CLEARANCE_TOKEN`` pass the
  challenge and reach a tiny origin page under ``/`` and ``/app``.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse

MODE = "waf_challenge"
CLEARANCE_TOKEN = "mock-clearance-synthetic"
CHALLENGE_SCRIPT_PATH = "/cdn-cgi/challenge-platform/h/b/orchestrate/jsch/v1"
CHALLENGE_JS = "window._cf_chl_opt={cRay:'8d5c4a2b1f0e9d3a'};/* synthetic challenge */"

CHALLENGE_HTML = (
    "<!DOCTYPE html><html lang=\"en-US\"><head><title>Just a moment...</title>"
    "<meta http-equiv=\"refresh\" content=\"390\">"
    "</head><body class=\"no-js\"><div class=\"main-wrapper\">"
    "<h1>Verifying you are human. This may take a few seconds.</h1>"
    "<p>app.example.test needs to review the security of your connection before proceeding.</p>"
    f"<script src=\"{CHALLENGE_SCRIPT_PATH}\"></script>"
    "<a href=\"/cdn-cgi/challenge-platform/h/b/scripts/jsd/abc/main.js\">challenge</a>"
    "</div></body></html>"
)


def _challenge_cookies(resp: Response) -> None:
    # Infrastructure cookies, intentionally without SameSite (classification noise).
    resp.headers.append("set-cookie", f"cf_clearance={CLEARANCE_TOKEN}; Path=/; Secure; HttpOnly")
    resp.headers.append("set-cookie", "__cf_bm=synthetic-bot-mgmt; Path=/; Secure; HttpOnly")
    resp.headers["server"] = "cloudflare"
    resp.headers["cf-ray"] = "8d5c4a2b1f0e9d3a-BOM"
    resp.headers["cf-mitigated"] = "challenge"
    resp.headers["cache-control"] = "private, max-age=0, no-store, no-cache, must-revalidate"


def _cleared(request: Request) -> bool:
    return request.cookies.get("cf_clearance") == CLEARANCE_TOKEN


def create_waf_challenge_app() -> FastAPI:
    """Build the challenge mock; every non-cdn-cgi path is gated until cleared."""
    app = FastAPI(title="Attestra WAF challenge mock", docs_url=None, redoc_url=None)

    @app.get("/__attestra_mock__")
    def mock_meta() -> dict[str, Any]:
        return {"mode": MODE, "local_only": True, "purpose": "elite_automated_security_testing_fixtures"}

    @app.get(CHALLENGE_SCRIPT_PATH)
    def challenge_script() -> Response:
        resp = Response(content=CHALLENGE_JS, media_type="application/javascript")
        resp.headers["cache-control"] = "public, max-age=14400"
        resp.headers["access-control-allow-origin"] = "*"
        resp.headers["server"] = "cloudflare"
        return resp

    @app.get("/cdn-cgi/challenge-platform/h/b/scripts/jsd/{rest:path}")
    def challenge_jsd(rest: str) -> Response:
        resp = Response(content=CHALLENGE_JS, media_type="application/javascript")
        resp.headers["cache-control"] = "public, max-age=14400"
        resp.headers["access-control-allow-origin"] = "*"
        return resp

    @app.get("/cdn-cgi/trace", response_class=PlainTextResponse)
    def trace() -> str:
        return "fl=1f23\nh=app.example.test\nip=203.0.113.10\nts=1700000000.000\nvisit_scheme=https\nsni=plaintext\n"

    @app.get("/{rest:path}")
    def gated(rest: str, request: Request) -> Response:
        if not _cleared(request):
            resp = HTMLResponse(CHALLENGE_HTML, status_code=403)
            _challenge_cookies(resp)
            return resp
        path = "/" + rest
        if path == "/app":
            body = "<!doctype html><html><body><h1>Origin app</h1><a href='/'>Home</a></body></html>"
        else:
            body = "<!doctype html><html><body><h1>Origin home</h1><a href='/app'>App</a></body></html>"
        resp = HTMLResponse(body)
        resp.headers["server"] = "cloudflare"
        resp.headers["cf-cache-status"] = "DYNAMIC"
        return resp

    return app
