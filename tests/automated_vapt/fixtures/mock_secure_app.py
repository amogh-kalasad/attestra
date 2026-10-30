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


def create_secure_app() -> FastAPI:
    """Build the secure mock used as the negative-control target."""
    app = FastAPI(title="Attestra Elite secure mock", docs_url=None, redoc_url=None)
    register_common_routes(app, mode=MODE)

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
