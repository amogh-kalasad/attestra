"""Phase 6 offline smoke tests against the restored auth-web mock app."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.fixtures.auth_web_mock_app import create_app


# @lat: [[tests#Phase 6 auth web#Mock login succeeds]]
def test_mock_login_succeeds():
    client = TestClient(create_app())
    r = client.post(
        "/login",
        data={"username": "viewer", "password": "viewer-pass"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers.get("location") == "/app"
    app = client.get("/app")
    assert app.status_code == 200
    assert "user=viewer" in app.text


# @lat: [[tests#Phase 6 auth web#Unauthenticated app gate]]
def test_unauthenticated_app_gate():
    client = TestClient(create_app())
    r = client.get("/app", follow_redirects=False)
    assert r.status_code in (302, 401)
    if r.status_code == 302:
        assert "/login" in (r.headers.get("location") or "")


# @lat: [[tests#Phase 6 auth web#Admin role gate]]
def test_admin_role_gate():
    client = TestClient(create_app())
    client.post("/login", data={"username": "viewer", "password": "viewer-pass"})
    forbidden = client.get("/admin")
    assert forbidden.status_code == 403

    client.post("/login", data={"username": "admin", "password": "admin-pass"})
    ok = client.get("/admin")
    assert ok.status_code == 200
    assert "Admin" in ok.text


# @lat: [[tests#Phase 6 auth web#Public home and settings]]
def test_public_home_and_settings():
    client = TestClient(create_app())
    home = client.get("/")
    assert home.status_code == 200
    assert "Public home" in home.text

    denied = client.get("/app/settings", follow_redirects=False)
    assert denied.status_code == 302

    client.post("/login", data={"username": "viewer", "password": "viewer-pass"})
    settings = client.get("/app/settings")
    assert settings.status_code == 200
    assert "Settings" in settings.text
