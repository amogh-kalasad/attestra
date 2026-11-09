"""Intentionally vulnerable local mock for Elite automated security-testing fixtures.

Controlled weaknesses for offline tests only:
- BOLA/IDOR on project fetch
- Broken admin role enforcement
- Settings reachable without authentication
- Excessive user directory exposure (passwords / tokens)
- Phase 4 lab additions: JSON list for id harvest (``GET /api/projects``), JSON write
  bodies without owner checks (``POST /api/projects``, ``PUT /api/projects/{id}``),
  unauthenticated upload that serves files back verbatim (``POST /api/upload`` →
  ``GET /uploads/{name}``), and a URL-fetcher with no destination allowlist
  (``GET /api/fetch?url=``) that "reaches" loopback / link-local hosts.

Do not deploy outside an isolated local test environment.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urlsplit

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.datastructures import UploadFile

from tests.automated_vapt.fixtures._common import (
    PROJECTS,
    USERS,
    register_common_routes,
    require_auth_json,
    require_auth_redirect,
    session_user,
)

MODE = "vulnerable"

# Hosts the fake fetcher pretends to reach (SSRF positive control, no real sockets).
_INTERNAL_HOSTS = frozenset({"127.0.0.1", "localhost", "0.0.0.0", "169.254.169.254", "metadata", "metadata.google.internal", "[::1]"})
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")


def create_vulnerable_app() -> FastAPI:
    """Build the intentional-vulnerable mock used as the positive-control target."""
    app = FastAPI(title="Attestra Elite vulnerable mock", docs_url=None, redoc_url=None)
    register_common_routes(app, mode=MODE)
    # Mutable lab state (per app instance): created projects and uploaded files.
    projects: dict[str, dict[str, Any]] = {pid: dict(p) for pid, p in PROJECTS.items()}
    uploads: dict[str, tuple[bytes, str]] = {}
    app.state.lab_projects = projects
    app.state.lab_uploads = uploads
    app.state.fetch_log = []

    @app.get("/api/projects")
    def list_projects(request: Request) -> Response:
        denied = require_auth_json(request)
        if denied is not None:
            return denied
        # Weakness: lists every tenant's projects (harvest surface for T20).
        items = [{"projectId": pid, "name": p["name"], "owner": p["owner"]} for pid, p in projects.items()]
        return JSONResponse({"items": items, "data": {"items": [{"id": pid} for pid in projects]}, "total": len(items)})

    @app.post("/api/projects", status_code=201)
    async def create_project(request: Request) -> Response:
        denied = require_auth_json(request)
        if denied is not None:
            return denied
        try:
            body = await request.json()
        except ValueError:
            return JSONResponse({"detail": "json body required"}, status_code=400)
        if not isinstance(body, dict) or not str(body.get("name") or "").strip():
            return JSONResponse({"detail": "name required"}, status_code=422)
        pid = str(body.get("projectId") or body.get("id") or f"proj-{len(projects) + 1}")
        owner = session_user(request) or ""
        projects[pid] = {
            "id": pid,
            "name": str(body["name"])[:80],
            "owner": owner,
            "tenant": USERS.get(owner, {}).get("tenant", ""),
            "secret_note": "",
            "api_token": f"tok_{pid}_synthetic",
        }
        return JSONResponse({"id": pid, "projectId": pid, "name": projects[pid]["name"]}, status_code=201)

    @app.put("/api/projects/{project_id}")
    async def update_project(project_id: str, request: Request) -> Response:
        denied = require_auth_json(request)
        if denied is not None:
            return denied
        project = projects.get(project_id)
        if project is None:
            return JSONResponse({"detail": "not found"}, status_code=404)
        try:
            body = await request.json()
        except ValueError:
            return JSONResponse({"detail": "json body required"}, status_code=400)
        # Weakness: no owner/tenant check on write (T22 object-id swap positive control).
        if isinstance(body, dict) and body.get("name"):
            project["name"] = str(body["name"])[:80]
        return JSONResponse({"id": project_id, "projectId": project_id, "name": project["name"], "owner": project["owner"]})

    @app.post("/api/upload", status_code=201)
    async def upload(request: Request) -> Response:
        # Weakness: no authentication, no type allowlist, served back verbatim.
        form = await request.form()
        file = form.get("file")
        if not isinstance(file, UploadFile):
            return JSONResponse({"detail": "file field required"}, status_code=422)
        name = (file.filename or "upload.bin").rsplit("/", 1)[-1]
        if not _SAFE_NAME_RE.match(name):
            name = "upload.bin"
        data = await file.read()
        uploads[name] = (data[:65536], file.content_type or "application/octet-stream")
        return JSONResponse({"stored": True, "url": f"/uploads/{name}", "content_type": uploads[name][1]}, status_code=201)

    @app.get("/uploads/{name}")
    def serve_upload(name: str) -> Response:
        item = uploads.get(name)
        if item is None:
            return JSONResponse({"detail": "not found"}, status_code=404)
        data, ctype = item
        # Weakness: echoes the uploader-supplied content type (text/html executes in browser).
        return Response(content=data, media_type=ctype)

    @app.get("/api/fetch")
    def fetch_url(request: Request) -> Response:
        # Weakness: server-side fetch with no destination allowlist. Never opens a socket:
        # loopback / metadata hosts are answered from a canned banner so tests stay offline.
        url = request.query_params.get("url") or ""
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        app.state.fetch_log.append(url)
        if not host:
            return JSONResponse({"detail": "url required"}, status_code=400)
        token = (parse_qs(parts.query).get("token") or parse_qs(parts.query).get("canary") or [""])[0]
        if host in _INTERNAL_HOSTS or host.startswith(("10.", "192.168.", "172.16.")):
            banner = f"internal-service-banner host={host} path={parts.path or '/'}"
            if token:
                banner += f" canary={token}"
            return JSONResponse({"fetched": url, "status": 200, "body": banner})
        # External hosts are "fetched" too, with the canary reflected (callback-style proof).
        body = f"<html><title>fetched {host}</title>" + (f"canary={token}" if token else "") + "</html>"
        return JSONResponse({"fetched": url, "status": 200, "body": body})

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

    # Phase 3c lab: stored XSS guestbook + DOM sink page (offline only).
    comments: list[str] = []
    app.state.lab_comments = comments

    @app.post("/api/comments")
    async def add_comment(request: Request) -> Response:
        try:
            body = await request.json()
        except Exception:
            body = {}
        text = str((body or {}).get("text") or "")[:500]
        comments.append(text)
        return JSONResponse({"id": len(comments), "stored": True}, status_code=201)

    @app.get("/api/comments")
    def list_comments() -> Response:
        # Weakness: comments rendered without encoding on /guestbook.
        return JSONResponse({"items": [{"id": i + 1, "text": t} for i, t in enumerate(comments)]})

    @app.delete("/api/comments/{cid}")
    def delete_comment(cid: int) -> Response:
        idx = int(cid) - 1
        if 0 <= idx < len(comments):
            comments.pop(idx)
            return JSONResponse({"deleted": True})
        return JSONResponse({"detail": "not found"}, status_code=404)

    @app.get("/guestbook", response_class=HTMLResponse)
    def guestbook() -> Response:
        # Weakness: stored comments concatenated raw into HTML.
        body = "".join(f"<div class='c'>{t}</div>" for t in comments)
        return HTMLResponse(f"<!doctype html><html><body><h1>Guestbook</h1>{body}</body></html>")

    @app.get("/dom-sink", response_class=HTMLResponse)
    def dom_sink() -> Response:
        # Weakness: client-side sink writes location.hash into HTML without encoding.
        return HTMLResponse(
            "<!doctype html><html><body><h1>DOM sink</h1>"
            "<div id='out'></div>"
            "<script>"
            "var h=(location.hash||'').slice(1);"
            "document.getElementById('out').innerHTML=decodeURIComponent(h);"
            "</script></body></html>"
        )

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
