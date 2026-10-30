"""Intentionally vulnerable local mock for Elite automated security-testing fixtures.

Controlled weaknesses for offline tests only:
- BOLA/IDOR on project fetch
- Broken admin role enforcement
- Settings reachable without authentication
- Excessive user directory exposure (passwords / tokens)

Do not deploy outside an isolated local test environment.
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
    session_user,
)

MODE = "vulnerable"


def create_vulnerable_app() -> FastAPI:
    """Build the intentional-vulnerable mock used as the positive-control target."""
    app = FastAPI(title="Attestra Elite vulnerable mock", docs_url=None, redoc_url=None)
    register_common_routes(app, mode=MODE)

    @app.get("/app/settings", response_class=HTMLResponse)
    def app_settings(_request: Request) -> Response:
        # Weakness: authentication not enforced.
        return HTMLResponse(
            "<!doctype html><html><body><h1>Settings</h1>"
            "<p>unauthenticated access allowed (intentional)</p></body></html>"
        )

    @app.get("/admin", response_class=HTMLResponse)
    def admin(request: Request) -> Response:
        denied = require_auth_redirect(request)
        if denied is not None:
            return denied
        # Weakness: any authenticated role reaches admin.
        return HTMLResponse("<!doctype html><html><body><h1>Admin</h1></body></html>")

    @app.get("/api/projects/{project_id}")
    def get_project(project_id: str, request: Request) -> Response:
        denied = require_auth_json(request)
        if denied is not None:
            return denied
        project = PROJECTS.get(project_id)
        if project is None:
            return JSONResponse({"detail": "not found"}, status_code=404)
        # Weakness: no owner/tenant check; returns sensitive fields (BOLA + exposure).
        _ = session_user(request)
        return JSONResponse(_leaky_project(project))

    @app.get("/api/users")
    def list_users(request: Request) -> Response:
        denied = require_auth_json(request)
        if denied is not None:
            return denied
        # Weakness: any authenticated user sees passwords and project tokens.
        rows = [
            {
                "username": name,
                "role": meta["role"],
                "tenant": meta["tenant"],
                "password": meta["password"],
            }
            for name, meta in USERS.items()
        ]
        tokens = {pid: p["api_token"] for pid, p in PROJECTS.items()}
        return JSONResponse({"users": rows, "project_tokens": tokens})

    return app


def _leaky_project(project: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": project["id"],
        "name": project["name"],
        "owner": project["owner"],
        "tenant": project["tenant"],
        "secret_note": project["secret_note"],
        "api_token": project["api_token"],
    }
