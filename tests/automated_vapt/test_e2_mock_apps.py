"""Elite Phase E2: secure vs intentionally vulnerable local mock applications."""

from __future__ import annotations

from tests.automated_vapt.conftest import login


# @lat: [[tests#Elite Phase E2 mock apps#Mock modes distinguishable]]
def test_mock_modes_distinguishable(secure_client, vulnerable_client):
    s = secure_client.get("/__attestra_mock__")
    v = vulnerable_client.get("/__attestra_mock__")
    assert s.status_code == 200 and s.json()["mode"] == "secure"
    assert v.status_code == 200 and v.json()["mode"] == "vulnerable"
    assert s.json()["local_only"] is True
    assert v.json()["local_only"] is True


# @lat: [[tests#Elite Phase E2 mock apps#Secure blocks cross-owner project]]
def test_secure_blocks_cross_owner_project(secure_client):
    login(secure_client, "account_a", "account-a-pass")
    own = secure_client.get("/api/projects/proj-a")
    assert own.status_code == 200
    body = own.json()
    assert body["id"] == "proj-a"
    assert "secret_note" not in body
    assert "api_token" not in body

    other = secure_client.get("/api/projects/proj-b")
    assert other.status_code == 404


# @lat: [[tests#Elite Phase E2 mock apps#Vulnerable exposes cross-owner project]]
def test_vulnerable_exposes_cross_owner_project(vulnerable_client):
    login(vulnerable_client, "account_a", "account-a-pass")
    other = vulnerable_client.get("/api/projects/proj-b")
    assert other.status_code == 200
    body = other.json()
    assert body["id"] == "proj-b"
    assert "SENSITIVE" in body.get("secret_note", "")
    assert body.get("api_token", "").startswith("tok_")


# @lat: [[tests#Elite Phase E2 mock apps#Secure enforces admin role]]
def test_secure_enforces_admin_role(secure_client):
    login(secure_client, "account_a", "account-a-pass")
    assert secure_client.get("/admin").status_code == 403
    login(secure_client, "admin", "admin-pass")
    assert secure_client.get("/admin").status_code == 200


# @lat: [[tests#Elite Phase E2 mock apps#Vulnerable admin role failure]]
def test_vulnerable_admin_role_failure(vulnerable_client):
    login(vulnerable_client, "account_a", "account-a-pass")
    r = vulnerable_client.get("/admin")
    assert r.status_code == 200
    assert "Admin" in r.text


# @lat: [[tests#Elite Phase E2 mock apps#Secure settings require auth]]
def test_secure_settings_require_auth(secure_client):
    denied = secure_client.get("/app/settings", follow_redirects=False)
    assert denied.status_code == 302
    login(secure_client, "viewer", "viewer-pass")
    assert secure_client.get("/app/settings").status_code == 200


# @lat: [[tests#Elite Phase E2 mock apps#Vulnerable settings auth failure]]
def test_vulnerable_settings_auth_failure(vulnerable_client):
    r = vulnerable_client.get("/app/settings", follow_redirects=False)
    assert r.status_code == 200
    assert "Settings" in r.text


# @lat: [[tests#Elite Phase E2 mock apps#Secure user directory limited]]
def test_secure_user_directory_limited(secure_client):
    login(secure_client, "account_a", "account-a-pass")
    assert secure_client.get("/api/users").status_code == 403
    login(secure_client, "admin", "admin-pass")
    data = secure_client.get("/api/users").json()
    assert "users" in data
    assert all("password" not in u for u in data["users"])


# @lat: [[tests#Elite Phase E2 mock apps#Vulnerable excessive data exposure]]
def test_vulnerable_excessive_data_exposure(vulnerable_client):
    login(vulnerable_client, "account_a", "account-a-pass")
    data = vulnerable_client.get("/api/users").json()
    assert any("password" in u for u in data["users"])
    assert "project_tokens" in data


# @lat: [[tests#Elite Phase E2 mock apps#Account B can access own project]]
def test_account_b_can_access_own_project(secure_client, vulnerable_client):
    for client in (secure_client, vulnerable_client):
        login(client, "account_b", "account-b-pass")
        r = client.get("/api/projects/proj-b")
        assert r.status_code == 200
        assert r.json()["id"] == "proj-b"
