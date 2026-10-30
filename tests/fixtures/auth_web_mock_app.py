"""Local mock website for authenticated security-testing smoke tests.

Synthetic form-login app only — no external network. Use with FastAPI TestClient
or mount behind a loopback server. Credentials are test doubles, not real secrets.
"""

from __future__ import annotations

from urllib.parse import quote

from fastapi import FastAPI, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

USERS: dict[str, dict[str, str]] = {
    "viewer": {"password": "viewer-pass", "role": "viewer"},
    "admin": {"password": "admin-pass", "role": "admin"},
}

SESSION_COOKIE = "mock_session"
ROLE_COOKIE = "mock_role"


def _login_form_html(error: str = "") -> str:
    err = f"<p style='color:red'>{error}</p>" if error else ""
    return (
        "<!doctype html>\n<html><head><title>Mock Login</title></head>\n<body>\n"
        f"<h1>Login</h1>\n{err}\n"
        '<form method="post" action="/login">\n'
        '  <label>Username <input name="username" autocomplete="username"></label>\n'
        '  <label>Password <input name="password" type="password" '
        'autocomplete="current-password"></label>\n'
        '  <button type="submit">Sign in</button>\n'
        "</form>\n</body></html>"
    )


def _session_user(request: Request) -> str | None:
    user = request.cookies.get(SESSION_COOKIE)
    return user if user in USERS else None


def _session_role(request: Request) -> str | None:
    return request.cookies.get(ROLE_COOKIE)


def create_app() -> FastAPI:
    """Build a small FastAPI app with public, authed, and admin routes."""
    app = FastAPI(title="Attestra auth-web mock", docs_url=None, redoc_url=None)

    @app.get("/", response_class=HTMLResponse)
    def home() -> str:
        return (
            "<!doctype html><html><body><h1>Public home</h1>"
            "<a href='/login'>Login</a></body></html>"
        )

    @app.get("/login", response_class=HTMLResponse)
    def login_get() -> str:
        return _login_form_html()

    @app.post("/login")
    def login_post(username: str = Form(...), password: str = Form(...)) -> Response:
        account = USERS.get(username)
        if not account or account["password"] != password:
            return HTMLResponse(_login_form_html("Invalid credentials"), status_code=401)
        resp = RedirectResponse(url="/app", status_code=303)
        resp.set_cookie(SESSION_COOKIE, username, httponly=True, samesite="lax")
        resp.set_cookie(ROLE_COOKIE, account["role"], httponly=True, samesite="lax")
        return resp

    @app.get("/logout")
    def logout() -> Response:
        resp = RedirectResponse(url="/", status_code=303)
        resp.delete_cookie(SESSION_COOKIE)
        resp.delete_cookie(ROLE_COOKIE)
        return resp

    def _require_auth(request: Request) -> Response | None:
        user = _session_user(request)
        if not user or user not in USERS:
            return RedirectResponse(url="/login", status_code=302)
        return None

    @app.get("/app", response_class=HTMLResponse)
    def app_home(request: Request) -> Response:
        denied = _require_auth(request)
        if denied is not None:
            return denied
        user = _session_user(request) or ""
        role = _session_role(request) or ""
        return HTMLResponse(
            "<!doctype html><html><body><h1>App</h1><p>user="
            + quote(user, safe="")
            + " role="
            + quote(role, safe="")
            + "</p><a href='/app/settings'>Settings</a> "
            "<a href='/logout'>Logout</a></body></html>"
        )

    @app.get("/app/settings", response_class=HTMLResponse)
    def app_settings(request: Request) -> Response:
        denied = _require_auth(request)
        if denied is not None:
            return denied
        return HTMLResponse("<!doctype html><html><body><h1>Settings</h1></body></html>")

    @app.get("/admin", response_class=HTMLResponse)
    def admin(request: Request) -> Response:
        denied = _require_auth(request)
        if denied is not None:
            return denied
        if _session_role(request) != "admin":
            return HTMLResponse(
                "<!doctype html><html><body><h1>Forbidden</h1></body></html>",
                status_code=403,
            )
        return HTMLResponse("<!doctype html><html><body><h1>Admin</h1></body></html>")

    return app
