"""Shared synthetic users and projects for Elite local mock apps.

Local test doubles only — never real credentials or production data.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from fastapi import Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

# Account A / Account B for controlled two-account authorization tests.
USERS: dict[str, dict[str, str]] = {
    "viewer": {"password": "viewer-pass", "role": "viewer", "tenant": "tenant-a"},
    "admin": {"password": "admin-pass", "role": "admin", "tenant": "tenant-a"},
    "account_a": {"password": "account-a-pass", "role": "member", "tenant": "tenant-a"},
    "account_b": {"password": "account-b-pass", "role": "member", "tenant": "tenant-b"},
}

PROJECTS: dict[str, dict[str, Any]] = {
    "proj-a": {
        "id": "proj-a",
        "name": "Project A",
        "owner": "account_a",
        "tenant": "tenant-a",
        "secret_note": "SENSITIVE: payroll for account_a only",
        "api_token": "tok_account_a_proj_a_synthetic",
    },
    "proj-b": {
        "id": "proj-b",
        "name": "Project B",
        "owner": "account_b",
        "tenant": "tenant-b",
        "secret_note": "SENSITIVE: payroll for account_b only",
        "api_token": "tok_account_b_proj_b_synthetic",
    },
}

SESSION_COOKIE = "mock_session"
ROLE_COOKIE = "mock_role"
TENANT_COOKIE = "mock_tenant"


def login_form_html(error: str = "") -> str:
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


def session_user(request: Request) -> str | None:
    user = request.cookies.get(SESSION_COOKIE)
    return user if user in USERS else None


def session_role(request: Request) -> str | None:
    return request.cookies.get(ROLE_COOKIE)


def session_tenant(request: Request) -> str | None:
    return request.cookies.get(TENANT_COOKIE)


def require_auth_redirect(request: Request) -> Response | None:
    user = session_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    return None


def require_auth_json(request: Request) -> Response | None:
    user = session_user(request)
    if not user:
        return Response(
            content='{"detail":"authentication required"}',
            status_code=401,
            media_type="application/json",
        )
    return None


def set_session_cookies(resp: Response, username: str) -> None:
    account = USERS[username]
    resp.set_cookie(SESSION_COOKIE, username, httponly=True, samesite="lax")
    resp.set_cookie(ROLE_COOKIE, account["role"], httponly=True, samesite="lax")
    resp.set_cookie(TENANT_COOKIE, account["tenant"], httponly=True, samesite="lax")


def clear_session_cookies(resp: Response) -> None:
    resp.delete_cookie(SESSION_COOKIE)
    resp.delete_cookie(ROLE_COOKIE)
    resp.delete_cookie(TENANT_COOKIE)


def register_common_routes(app, *, mode: str) -> None:
    """Public home, login/logout, and mock identity marker shared by both apps."""

    @app.get("/__attestra_mock__")
    def mock_meta() -> dict[str, Any]:
        return {
            "mode": mode,
            "local_only": True,
            "purpose": "elite_automated_security_testing_fixtures",
        }

    @app.get("/", response_class=HTMLResponse)
    def home() -> str:
        return (
            f"<!doctype html><html><body><h1>Public home ({mode})</h1>"
            "<a href='/login'>Login</a></body></html>"
        )

    @app.get("/login", response_class=HTMLResponse)
    def login_get() -> str:
        return login_form_html()

    @app.post("/login")
    def login_post(username: str = Form(...), password: str = Form(...)) -> Response:
        account = USERS.get(username)
        if not account or account["password"] != password:
            return HTMLResponse(login_form_html("Invalid credentials"), status_code=401)
        resp = RedirectResponse(url="/app", status_code=303)
        set_session_cookies(resp, username)
        return resp

    @app.get("/logout")
    def logout() -> Response:
        resp = RedirectResponse(url="/", status_code=303)
        clear_session_cookies(resp)
        return resp

    @app.get("/app", response_class=HTMLResponse)
    def app_home(request: Request) -> Response:
        denied = require_auth_redirect(request)
        if denied is not None:
            return denied
        user = session_user(request) or ""
        role = session_role(request) or ""
        return HTMLResponse(
            "<!doctype html><html><body><h1>App</h1><p>user="
            + quote(user, safe="")
            + " role="
            + quote(role, safe="")
            + f" mode={mode}</p>"
            "<a href='/app/settings'>Settings</a> "
            "<a href='/logout'>Logout</a></body></html>"
        )
