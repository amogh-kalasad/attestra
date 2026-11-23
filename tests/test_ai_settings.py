"""Per-tenant AI settings UI/API: encrypt pasted keys, role gates, live Mongo resolve."""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

pytest.importorskip("pymongo")
pytestmark = pytest.mark.mongo

from attestra import ai_narratives as ai
from attestra.ai_providers import AnthropicProvider
from attestra.ai_settings import service as ai_settings


class _Principal:
    def __init__(self, role="admin", actor="admin1", tenant_id=1):
        self.role = role
        self.actor = actor
        self.tenant_id = tenant_id


@pytest.fixture()
def fernet_env(monkeypatch):
    key = Fernet.generate_key().decode("ascii")
    monkeypatch.setenv("ATTESTRA_CREDENTIAL_FERNET_KEY", key)
    return key


@pytest.fixture()
def ai_mongo(mongo_test_db, fernet_env, monkeypatch):
    from attestra.web import data_access

    monkeypatch.setattr(data_access, "mongo_db", lambda: mongo_test_db)
    monkeypatch.setattr(ai_settings, "_mdb", lambda: mongo_test_db)
    mongo_test_db["tenants"].update_one({"_id": 1}, {"$set": {"name": "Acme"}}, upsert=True)
    return mongo_test_db


def test_paste_key_encrypted_in_mongo_and_settings_dict_hides_it(ai_mongo):
    # @lat: [[tests#AI settings#Paste key encrypted]]
    p = _Principal()
    row = ai_settings.update_settings(
        None,
        p,
        1,
        enabled=True,
        provider="anthropic",
        model="claude-sonnet-4-5",
        api_key="sk-ant-PASTE-ME-SECRET",
    )
    assert row.api_key_enc and str(row.api_key_enc).startswith("fernet:v1:")
    assert "PASTE-ME" not in str(row.api_key_enc)
    public = ai_settings.settings_dict(row, 1)
    blob = str(public)
    assert public["has_api_key"] is True
    assert "api_key" not in public
    assert "api_key_enc" not in public
    assert "PASTE-ME" not in blob
    assert public["provider"] == "anthropic"
    assert any(x["id"] == "anthropic" for x in public["providers"])


def test_empty_key_preserves_existing(ai_mongo):
    # @lat: [[tests#AI settings#Empty key preserves]]
    p = _Principal()
    ai_settings.update_settings(None, p, 1, api_key="sk-keep-this")
    before = ai_settings.get_raw(1)["api_key_enc"]
    ai_settings.update_settings(None, p, 1, model="gpt-4o-mini", api_key="")
    assert ai_settings.get_raw(1)["api_key_enc"] == before
    ai_settings.update_settings(None, p, 1, clear_api_key=True)
    assert not ai_settings.get_raw(1).get("api_key_enc")


def test_tester_cannot_update(ai_mongo):
    # @lat: [[tests#AI settings#Tester denied]]
    with pytest.raises(ai_settings.AiSettingsError, match="not allowed"):
        ai_settings.update_settings(None, _Principal(role="tester"), 1, enabled=True)


def test_get_provider_uses_mongo_without_env_narratives(ai_mongo, monkeypatch):
    # @lat: [[tests#AI settings#Live Mongo resolve]]
    monkeypatch.delenv("ATTESTRA_AI_NARRATIVES", raising=False)
    ai_settings.update_settings(
        None,
        _Principal(),
        1,
        enabled=True,
        provider="anthropic",
        api_key="sk-ant-live",
        model="claude-sonnet-4-5",
    )
    assert ai.is_enabled(tenant_id=1) is True

    sent = []

    def post(url, headers, body):
        sent.append((url, headers))
        return {"content": [{"type": "text", "text": "ok"}]}

    monkeypatch.setattr("attestra.ai_providers._http_post", post)
    ai.set_provider(None)
    p = ai.get_provider(tenant_id=1)
    assert isinstance(p, AnthropicProvider)
    assert p.complete("s", "u") == "ok"
    assert sent[-1][0].endswith("/v1/messages")
    assert sent[-1][1]["x-api-key"] == "sk-ant-live"
    assert "sk-ant-live" not in repr(p)

    ai_settings.update_settings(None, _Principal(), 1, enabled=False)
    assert ai.is_enabled(tenant_id=1) is False
    assert ai.get_provider(tenant_id=1) is None


PASSWORD = "Correct-Horse-9"


@pytest.fixture()
def ai_web(fresh_db, mongo_test_db, fernet_env, monkeypatch):
    import attestra.config as cfg

    monkeypatch.setattr(cfg, "PERSISTENCE_BACKEND", "mongo")
    monkeypatch.setenv("ATTESTRA_PERSISTENCE", "mongo")
    return mongo_test_db


def _bearer(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


def _login(c, username: str, password: str = PASSWORD) -> None:
    r = c.post("/login", data={"username": username, "password": password}, follow_redirects=False)
    assert r.status_code in (302, 303), r.text


def test_ai_settings_routes_admin_lead_and_tester_denied(ai_web, api_credentials, engagement, monkeypatch):
    # @lat: [[tests#AI settings#Routes role gate]]
    from cryptography.fernet import Fernet
    from fastapi.testclient import TestClient

    from attestra import db, services
    from attestra.api import app
    from attestra.auth.keys import create_api_key, create_user
    from attestra.persistence.mongo import collections as C

    monkeypatch.setenv("ATTESTRA_CREDENTIAL_FERNET_KEY", Fernet.generate_key().decode())
    with db.session() as s:
        tid = services.get_engagement(s, engagement).tenant_id
        tester = create_user(s, username="tester-ai", role="tester", password=PASSWORD, display_name="T")
        _, tester_key = create_api_key(s, tester)

    h = _bearer(api_credentials["lead_key"])
    with TestClient(app) as c:
        got = c.get(f"/api/ai/settings?tenant_id={tid}", headers=h)
        assert got.status_code == 200, got.text
        assert got.json()["has_api_key"] is False
        assert any(p["id"] == "anthropic" for p in got.json()["providers"])

        put = c.put(
            f"/api/ai/settings?tenant_id={tid}",
            headers=h,
            json={
                "enabled": True,
                "provider": "anthropic",
                "model": "claude-sonnet-4-5",
                "api_key": "sk-ant-FROM-UI",
            },
        )
        assert put.status_code == 200, put.text
        body = put.json()
        assert body["enabled"] is True and body["provider"] == "anthropic" and body["has_api_key"] is True
        assert "api_key" not in body and "api_key_enc" not in body
        assert "FROM-UI" not in str(body)

        doc = ai_web[C.AI_SETTINGS].find_one({"tenant_id": tid})
        assert doc and doc.get("api_key_enc", "").startswith("fernet:v1:")
        assert "FROM-UI" not in str(doc)

        deny = c.get(f"/api/ai/settings?tenant_id={tid}", headers=_bearer(tester_key))
        assert deny.status_code == 403

        deny_put = c.put(
            f"/api/ai/settings?tenant_id={tid}",
            headers=_bearer(tester_key),
            json={"enabled": False},
        )
        assert deny_put.status_code == 403

    with TestClient(app) as c:
        _login(c, "lead", "test-pass-lead")
        page = c.get(f"/settings/ai?tenant_id={tid}")
        assert page.status_code == 200
        assert "AI provider" in page.text
        assert "Paste API key" in page.text
        assert "FROM-UI" not in page.text
        assert "fernet:" not in page.text

        _login(c, "tester-ai", PASSWORD)
        blocked = c.get(f"/settings/ai?tenant_id={tid}", follow_redirects=False)
        assert blocked.status_code in (302, 303)

    assert ai_web[C.AUDIT_EVENTS].find_one({"action": "ai.settings.update"}) is not None
