"""Configurable probe target. ``vulnerable=True`` turns every weakness on; False is safe.

Local-only fixture (FastAPI TestClient). It records every request it receives in
``app.state.seen`` so tests can assert request budgets, methods and headers.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

_MUTATION_RE = re.compile(r"(?i)\bmutation\b")

SESSION_TOKEN = "Bearer probe-secret-token-value"
SECOND_TOKEN = "Bearer probe-second-token-value"

SCHEMA = {
    "queryType": {"name": "Query"},
    "mutationType": {"name": "Mutation"},
    "types": [
        {
            "name": "Query",
            "kind": "OBJECT",
            "fields": [
                {"name": "adminUsers", "args": [], "type": {"kind": "OBJECT", "name": "UserPage", "ofType": None}},
                {"name": "me", "args": [], "type": {"kind": "OBJECT", "name": "User", "ofType": None}},
                {"name": "user", "args": [{"name": "id", "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "ID"}}}], "type": {"kind": "OBJECT", "name": "User", "ofType": None}},
            ],
        },
        {"name": "UserPage", "kind": "OBJECT", "fields": [{"name": "total", "args": [], "type": {"kind": "SCALAR", "name": "Int", "ofType": None}}]},
        {"name": "User", "kind": "OBJECT", "fields": [{"name": "email", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}}]},
        {"name": "Mutation", "kind": "OBJECT", "fields": [{"name": "deleteUser", "args": [], "type": {"kind": "SCALAR", "name": "Boolean", "ofType": None}}]},
    ],
}


def create_probe_app(*, vulnerable: bool = True, graphql_introspection: bool = True, field_authz_broken: bool = True) -> FastAPI:
    app = FastAPI(title="Attestra probe mock", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.seen = []

    @app.middleware("http")
    async def record(request: Request, call_next):
        app.state.seen.append(
            {
                "method": request.method,
                "path": request.url.path,
                "query": str(request.url.query),
                "headers": {k.lower(): v for k, v in request.headers.items()},
            }
        )
        return await call_next(request)

    def _authed(request: Request) -> str:
        auth = request.headers.get("authorization", "")
        if auth == SESSION_TOKEN:
            return "primary"
        if auth == SECOND_TOKEN:
            return "secondary"
        return ""

    def _cors(request: Request, resp: Response) -> Response:
        origin = request.headers.get("origin")
        if not origin:
            return resp
        if vulnerable:
            resp.headers["access-control-allow-origin"] = origin
            resp.headers["access-control-allow-credentials"] = "true"
        elif origin == "https://app.example.test":
            resp.headers["access-control-allow-origin"] = origin
            resp.headers["access-control-allow-credentials"] = "true"
        return resp

    def _host_for_links(request: Request) -> str:
        if vulnerable:
            return request.headers.get("x-forwarded-host") or request.headers.get("host") or "testserver"
        return "testserver"

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request) -> Response:
        host = _host_for_links(request)
        body = f"<!doctype html><html><body><h1>Probe home</h1><a href='https://{host}/reset?t=1'>reset</a></body></html>"
        resp = HTMLResponse(body)
        resp.headers["x-ratelimit-limit"] = "100"
        resp.headers["x-ratelimit-remaining"] = "99"
        return _cors(request, resp)

    @app.options("/{rest:path}")
    def preflight(rest: str, request: Request) -> Response:
        resp = Response(status_code=204)
        origin = request.headers.get("origin")
        if origin:
            resp.headers["access-control-allow-origin"] = origin if vulnerable else "https://app.example.test"
            resp.headers["access-control-allow-methods"] = "GET, POST"
        return resp

    @app.get("/api/v1/profile")
    def profile(request: Request) -> Response:
        who = _authed(request)
        if not who:
            return _cors(request, JSONResponse({"error": "unauthorized"}, status_code=401))
        resp = JSONResponse({"user": who, "email": f"{who}@example.test", "plan": "pro"})
        if vulnerable:
            resp.headers["cache-control"] = "public, max-age=600"
            resp.headers["cf-cache-status"] = "HIT"
        else:
            resp.headers["cache-control"] = "private, no-store"
        resp.headers["ratelimit-policy"] = "100;w=60"
        return _cors(request, resp)

    @app.get("/dashboard")
    def dashboard(request: Request) -> Response:
        who = _authed(request)
        if vulnerable and not who:
            # The CDN served the cached authenticated page to an anonymous user.
            resp = HTMLResponse("<html><body>Welcome primary — balance 42</body></html>")
            resp.headers["cache-control"] = "public, max-age=600"
            resp.headers["cf-cache-status"] = "HIT"
            return resp
        if not who:
            return RedirectResponse("/login", status_code=302)
        resp = HTMLResponse(f"<html><body>Welcome {who} — balance 42</body></html>")
        if vulnerable:
            resp.headers["cache-control"] = "public, max-age=600"
            resp.headers["cf-cache-status"] = "HIT"
        else:
            resp.headers["cache-control"] = "private, no-store"
        return resp

    @app.get("/static/app.css")
    def css() -> Response:
        resp = Response("body{}", media_type="text/css")
        resp.headers["cache-control"] = "public, max-age=86400"
        return resp

    @app.get("/login")
    def login(request: Request, next: str = "") -> Response:
        if next:
            if vulnerable:
                return RedirectResponse(next, status_code=302)
            p = urlsplit(next)
            if not p.netloc and next.startswith("/") and not next.startswith("//") and "\\" not in next:
                return RedirectResponse(next, status_code=302)
            return RedirectResponse("/", status_code=302)
        return HTMLResponse("<form>login</form>")

    @app.get("/go")
    def go(request: Request, url: str = "") -> Response:
        # Same-site hop first, then (vulnerable only) the external destination.
        if url and vulnerable:
            return RedirectResponse(f"/login?next={url}", status_code=302)
        return RedirectResponse("/", status_code=302)

    @app.get("/graphql")
    def graphql_get(request: Request, query: str = "") -> Response:
        if _MUTATION_RE.search(query):
            return JSONResponse({"errors": [{"message": "mutation sent (should never happen)"}]}, status_code=400)
        if "__typename" in query:
            return JSONResponse({"data": {"__typename": "Query"}})
        if "__schema" in query:
            if not graphql_introspection:
                return JSONResponse({"errors": [{"message": "introspection disabled"}]})
            return JSONResponse({"data": {"__schema": SCHEMA}})
        who = _authed(request)
        if "adminUsers" in query:
            if who == "primary" or (who == "secondary" and field_authz_broken):
                return JSONResponse({"data": {"adminUsers": {"total": 7}}})
            return JSONResponse({"data": {"adminUsers": None}, "errors": [{"message": "forbidden"}]})
        if "me" in query:
            return JSONResponse({"data": {"me": {"email": f"{who or 'anon'}@example.test"}}})
        return JSONResponse({"errors": [{"message": "unknown"}]}, status_code=400)

    @app.post("/graphql")
    async def graphql_post(request: Request) -> Response:
        body: Any = await request.body()
        try:
            q = json.loads(body or b"{}").get("query", "")
        except Exception:  # noqa: BLE001
            q = ""
        if _MUTATION_RE.search(str(q)):
            return JSONResponse({"errors": [{"message": "mutation sent (should never happen)"}]}, status_code=400)
        return JSONResponse({"data": {"__typename": "Query"}})

    @app.get("/huge-graphql")
    def huge(request: Request, query: str = "") -> Response:
        if "__typename" in query:
            return JSONResponse({"data": {"__typename": "Query"}})
        return Response("{" + '"x":"' + ("A" * (700 * 1024)) + '"}', media_type="application/json")

    @app.get("/search")
    def search(request: Request, q: str = "") -> Response:
        if vulnerable:
            return HTMLResponse(f"<html><body>Results for {q}</body></html>")
        import html

        return HTMLResponse(f"<html><body>Results for {html.escape(q)}</body></html>")

    @app.get("/echo-encoded")
    def echo_encoded(q: str = "") -> Response:
        import html

        return Response(f"you searched {html.escape(q)}", media_type="text/plain")

    @app.get("/tpl")
    def tpl() -> Response:
        return HTMLResponse("<pre>jinja2.exceptions.TemplateSyntaxError: unexpected '}'</pre>", status_code=500)

    @app.get("/feed.xml")
    def feed() -> Response:
        return Response("<rss/>", media_type="application/rss+xml")

    return app
