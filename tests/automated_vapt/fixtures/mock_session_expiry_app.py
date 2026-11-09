"""Session-expiry mock: sessions die after N authenticated requests (mid-scan auth loss).

Local-only fixture. Do not deploy. Used by Phase 1 session-guard tests.

Behaviour:

- ``POST /login`` with a ``tests.automated_vapt.fixtures._common.USERS`` account sets a
  ``mock_session`` cookie whose value is ``<user>.<serial>``; each login issues a new serial.
- Every authenticated request increments a per-session counter. Once it exceeds
  ``max_requests`` (constructor arg, default 3) the session is expired:
  JSON routes answer ``401 {"error": "SESSION_EXPIRED"}``, HTML routes ``302 -> /login``.
- ``POST /api/session/refresh`` (opt-in refresh endpoint) re-arms the counter when the
  current cookie is still known, answering ``{"refreshed": true}``; unknown cookies get 401.
- ``/api/me`` reports the current user and remaining budget.
- ``app.state.expiry.force_expire_all()`` lets a test kill every session on demand, and
  ``app.state.expiry.relogin_count`` counts successful logins for assertions.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, Form, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from tests.automated_vapt.fixtures._common import USERS, login_form_html

MODE = "session_expiry"
SESSION_COOKIE = "mock_session"


@dataclass
class ExpiryState:
    max_requests: int = 3
    sessions: dict[str, dict[str, Any]] = field(default_factory=dict)
    serial: itertools.count = field(default_factory=itertools.count, repr=False)
    relogin_count: int = 0
    refresh_count: int = 0

    def issue(self, username: str) -> str:
        token = f"{username}.{next(self.serial)}"
        self.sessions[token] = {"user": username, "used": 0, "alive": True}
        self.relogin_count += 1
        return token

    def touch(self, token: str | None) -> dict[str, Any] | None:
        """Consume one request from the session budget; None when not authenticated."""
        sess = self.sessions.get(token or "")
        if sess is None or not sess["alive"]:
            return None
        sess["used"] += 1
        if sess["used"] > self.max_requests:
            sess["alive"] = False
            return None
        return sess

    def refresh(self, token: str | None) -> bool:
        sess = self.sessions.get(token or "")
        if sess is None:
            return False
        sess["used"] = 0
        sess["alive"] = True
        self.refresh_count += 1
        return True

    def force_expire_all(self) -> None:
        for sess in self.sessions.values():
            sess["alive"] = False


def create_session_expiry_app(max_requests: int = 3) -> FastAPI:
    app = FastAPI(title="Attestra session-expiry mock", docs_url=None, redoc_url=None)
    state = ExpiryState(max_requests=max_requests)
    app.state.expiry = state

    def _token(request: Request) -> str | None:
        return request.cookies.get(SESSION_COOKIE)

    @app.get("/__attestra_mock__")
    def mock_meta() -> dict[str, Any]:
        return {"mode": MODE, "local_only": True, "purpose": "elite_automated_security_testing_fixtures"}

    @app.get("/", response_class=HTMLResponse)
    def home() -> str:
        return "<!doctype html><html><body><h1>Public home (expiry)</h1><a href='/login'>Login</a></body></html>"

    @app.get("/login", response_class=HTMLResponse)
    def login_get() -> str:
        return login_form_html()

    @app.post("/login")
    def login_post(username: str = Form(...), password: str = Form(...)) -> Response:
        account = USERS.get(username)
        if not account or account["password"] != password:
            return HTMLResponse(login_form_html("Invalid credentials"), status_code=401)
        resp = RedirectResponse(url="/app", status_code=303)
        resp.set_cookie(SESSION_COOKIE, state.issue(username), httponly=True, samesite="lax")
        return resp

    @app.get("/logout")
    def logout(request: Request) -> Response:
        sess = state.sessions.get(_token(request) or "")
        if sess:
            sess["alive"] = False
        resp = RedirectResponse(url="/", status_code=303)
        resp.delete_cookie(SESSION_COOKIE)
        return resp

    @app.get("/app", response_class=HTMLResponse)
    def app_home(request: Request) -> Response:
        sess = state.touch(_token(request))
        if sess is None:
            return RedirectResponse(url="/login?expired=1", status_code=302)
        return HTMLResponse(
            f"<!doctype html><html><body><h1>App</h1><p>user={sess['user']}</p>"
            "<a href='/app/projects'>Projects</a> <a href='/logout'>Logout</a></body></html>"
        )

    @app.get("/app/projects", response_class=HTMLResponse)
    def app_projects(request: Request) -> Response:
        sess = state.touch(_token(request))
        if sess is None:
            return RedirectResponse(url="/login?expired=1", status_code=302)
        return HTMLResponse("<!doctype html><html><body><h1>Projects</h1><a href='/app'>Back</a></body></html>")

    @app.get("/api/me")
    def api_me(request: Request) -> Response:
        sess = state.touch(_token(request))
        if sess is None:
            return JSONResponse({"error": "SESSION_EXPIRED", "detail": "session expired, please log in again"}, 401)
        return JSONResponse({"user": sess["user"], "remaining": state.max_requests - sess["used"]})

    @app.get("/api/projects")
    def api_projects(request: Request) -> Response:
        sess = state.touch(_token(request))
        if sess is None:
            return JSONResponse({"error": "SESSION_EXPIRED"}, 401)
        return JSONResponse({"items": [{"projectId": "proj-a", "owner": sess["user"]}]})

    @app.post("/api/session/refresh")
    def api_refresh(request: Request) -> Response:
        if not state.refresh(_token(request)):
            return JSONResponse({"error": "SESSION_EXPIRED"}, 401)
        return JSONResponse({"refreshed": True})

    return app
