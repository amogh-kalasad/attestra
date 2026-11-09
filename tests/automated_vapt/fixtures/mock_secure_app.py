"""Secure local mock application for Elite automated security-testing fixtures.

Expected behavior: authentication required where claimed, admin-only admin routes,
owner-scoped project access, tenant isolation, and no secret leakage in list APIs.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse

from tests.automated_vapt.fixtures._common import (
    PROJECTS,
    USERS,
    register_common_routes,
    require_auth_json,
    require_auth_redirect,
    session_role,
    session_tenant,
    session_user,
)

MODE = "secure"
# Only this host may be fetched server-side (SSRF negative control).
_FETCH_ALLOWLIST = frozenset({"cdn.example.test"})


def create_secure_app() -> FastAPI:
    """Build the secure mock used as the negative-control target."""
    app = FastAPI(title="Attestra Elite secure mock", docs_url=None, redoc_url=None)
    register_common_routes(app, mode=MODE)

    @app.get("/api/projects")
    def list_projects(request: Request) -> Response:
        denied = require_auth_json(request)
        if denied is not None:
            return denied
        user, tenant = session_user(request), session_tenant(request)
        items = [
            {"projectId": pid, "name": p["name"]}
            for pid, p in PROJECTS.items()
            if p["owner"] == user and p["tenant"] == tenant
        ]
        return JSONResponse({"items": items, "total": len(items)})

    @app.post("/api/projects", status_code=201)
    async def create_project(request: Request) -> Response:
        denied = require_auth_json(request)
        if denied is not None:
            return denied
        try:
            body = await request.json()
        except ValueError:
            return JSONResponse({"detail": "json body required"}, status_code=400)
        name = str((body or {}).get("name") or "").strip() if isinstance(body, dict) else ""
        if not name:
            return JSONResponse({"detail": "name required"}, status_code=422)
        # Server assigns ids and ownership; client-supplied ids are ignored.
        return JSONResponse({"id": "proj-new", "projectId": "proj-new", "name": name[:80]}, status_code=201)

    @app.put("/api/projects/{project_id}")
    async def update_project(project_id: str, request: Request) -> Response:
        denied = require_auth_json(request)
        if denied is not None:
            return denied
        project = PROJECTS.get(project_id)
        if project is None or project["owner"] != session_user(request) or project["tenant"] != session_tenant(request):
            return JSONResponse({"detail": "not found"}, status_code=404)
        try:
            body = await request.json()
        except ValueError:
            return JSONResponse({"detail": "json body required"}, status_code=400)
        name = str((body or {}).get("name") or project["name"])[:80] if isinstance(body, dict) else project["name"]
        return JSONResponse({"id": project_id, "projectId": project_id, "name": name})

    @app.post("/api/upload")
    def upload(request: Request) -> Response:
        denied = require_auth_json(request)
        if denied is not None:
            return denied
        if session_role(request) != "admin":
            return JSONResponse({"detail": "forbidden"}, status_code=403)
        return JSONResponse({"detail": "upload disabled in this environment"}, status_code=403)

    @app.get("/api/fetch")
    def fetch_url(request: Request) -> Response:
        denied = require_auth_json(request)
        if denied is not None:
            return denied
        from urllib.parse import urlsplit

        host = (urlsplit(request.query_params.get("url") or "").hostname or "").lower()
        if host not in _FETCH_ALLOWLIST:
            return JSONResponse({"detail": "url not allowed"}, status_code=400)
        return JSONResponse({"fetched": True, "host": host})

    @app.get("/app/settings", response_class=HTMLResponse)
    def app_settings(request: Request) -> Response:
        denied = require_auth_redirect(request)
        if denied is not None:
            return denied
        return HTMLResponse("<!doctype html><html><body><h1>Settings</h1></body></html>")

    @app.get("/admin", response_class=HTMLResponse)
    def admin(request: Request) -> Response:
        denied = require_auth_redirect(request)
        if denied is not None:
            return denied
        if session_role(request) != "admin":
            return HTMLResponse(
                "<!doctype html><html><body><h1>Forbidden</h1></body></html>",
                status_code=403,
            )
        return HTMLResponse("<!doctype html><html><body><h1>Admin</h1></body></html>")

    @app.get("/api/projects/{project_id}")
    def get_project(project_id: str, request: Request) -> Response:
        denied = require_auth_json(request)
        if denied is not None:
            return denied
        project = PROJECTS.get(project_id)
        if project is None:
            return JSONResponse({"detail": "not found"}, status_code=404)
        user = session_user(request)
        tenant = session_tenant(request)
        if project["owner"] != user or project["tenant"] != tenant:
            # Do not confirm existence to other principals.
            return JSONResponse({"detail": "not found"}, status_code=404)
        return JSONResponse(_public_project(project))

    @app.get("/api/users")
    def list_users(request: Request) -> Response:
        denied = require_auth_json(request)
        if denied is not None:
            return denied
        if session_role(request) != "admin":
            return JSONResponse({"detail": "forbidden"}, status_code=403)
        # Admin directory without secrets.
        rows = [
            {"username": name, "role": meta["role"], "tenant": meta["tenant"]}
            for name, meta in USERS.items()
        ]
        return JSONResponse({"users": rows})

    return app


def _public_project(project: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": project["id"],
        "name": project["name"],
        "owner": project["owner"],
        "tenant": project["tenant"],
    }
