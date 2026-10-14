import json
import socket
from types import SimpleNamespace

import pytest

from attestra import ai_narratives as ai


class FakeProvider:
    name = "fake"

    def __init__(self):
        self.calls = []

    def complete(self, system, prompt):
        self.calls.append(prompt)
        return "Drafted narrative."


def _finding(**kw):
    base = dict(
        id=1,
        title="SQL injection at https://app.acme.example/login (10.0.0.5)",
        severity="high",
        cwe=89,
        cves=["CVE-2024-12345", "junk"],
        kev=True,
        epss=0.4,
        cvss_score=8.1,
        status="new",
        description="EVIDENCE password=hunter2",
        location="https://app.acme.example/login?id=1",
        recommendation="secret stuff",
        owasp_top10="A03",
        asvs_ref="",
    )
    base.update(kw)
    return SimpleNamespace(**base)


def test_off_by_default_no_provider_no_network(monkeypatch, tmp_path):
    monkeypatch.delenv("ATTESTRA_AI_NARRATIVES", raising=False)

    def boom(*a, **k):
        raise AssertionError("network call while feature is off")

    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(ai.urllib.request, "urlopen", boom)
    assert ai.is_enabled() is False
    assert ai.provider_from_env() is None
    store = ai.DraftStore(tmp_path)
    assert ai.draft_finding_narrative(None, store, 1, _finding()) is None
    assert ai.draft_executive_summary(None, store, 1, [_finding()]) is None
    assert store.list(1) == []


def test_metadata_is_redacted_and_evidence_free():
    meta = ai.finding_metadata(
        _finding(title="Leak of api_key=" + "sk_" + "live_" + "FAKE0TEST0VALUE0NOT0REAL0000" + " on db01.corp.example by a@b.com")
    )
    blob = json.dumps(meta)
    for bad in ("hunter2", "EVIDENCE", "acme", "10.0.0.5", "sk_live", "corp.example", "a@b.com", "secret stuff"):
        assert bad not in blob
    assert "description" not in meta and "location" not in meta and "recommendation" not in meta
    assert meta["cves"] == ["CVE-2024-12345"]
    assert meta["severity"] == "high" and meta["cwe"] == 89


def test_drafts_require_tester_approval(tmp_path, monkeypatch):
    monkeypatch.setenv("ATTESTRA_AI_NARRATIVES", "on")
    store = ai.DraftStore(tmp_path)
    fake = FakeProvider()
    d = ai.draft_finding_narrative(fake, store, 7, _finding())
    s = ai.draft_executive_summary(fake, store, 7, [_finding(), _finding(id=2, severity="low")])
    assert d.label == "AI draft" and d.status == "draft"
    assert "acme" not in "".join(fake.calls) and "hunter2" not in "".join(fake.calls)
    assert ai.approved_text(store, 7, "finding", 1) is None
    assert ai.approved_text(store, 7, "executive_summary") is None
    with pytest.raises(PermissionError):
        store.approve(7, d.id, user="c", role="client_viewer")
    store.approve(7, d.id, user="t1", role="tester", edited_text="Reviewed text.")
    assert ai.approved_text(store, 7, "finding", 1) == "Reviewed text."
    store.reject(7, s.id, user="t1")
    assert ai.approved_text(store, 7, "executive_summary") is None


def test_per_tenant_off_switch(tmp_path, monkeypatch):
    monkeypatch.setenv("ATTESTRA_AI_NARRATIVES", "on")
    monkeypatch.setenv("ATTESTRA_AI_TENANTS_OFF", "3")
    fake = FakeProvider()
    assert ai.draft_finding_narrative(fake, ai.DraftStore(tmp_path), 1, _finding(), tenant_id=3) is None
    assert fake.calls == []


def test_providers_use_injected_transport_and_secret_store(monkeypatch):
    from attestra import secret_store

    sent = []

    def post(url, headers, body):
        sent.append((url, headers, body))
        if url.endswith("/api/chat"):
            return {"message": {"content": "ollama text"}}
        return {"choices": [{"message": {"content": "openai text"}}]}

    env = {"ATTESTRA_AI_NARRATIVES": "on", "ATTESTRA_AI_PROVIDER": "ollama"}
    p = ai.provider_from_env(env, http_post=post)
    assert p.complete("s", "u") == "ollama text"

    class S:
        def get(self, key, default=""):
            return "k-from-store" if key == "ai_api_key" else default

    secret_store.set_provider(S())
    try:
        env = {
            "ATTESTRA_AI_NARRATIVES": "on",
            "ATTESTRA_AI_PROVIDER": "openai",
            "ATTESTRA_AI_BASE_URL": "https://llm.internal/v1",
            "ATTESTRA_AI_MODEL": "m",
        }
        p = ai.provider_from_env(env, http_post=post)
        assert p.complete("s", "u") == "openai text"
        assert sent[-1][0] == "https://llm.internal/v1/chat/completions"
        assert sent[-1][1]["Authorization"] == "Bearer k-from-store"
        assert "k-from-store" not in repr(p)
    finally:
        secret_store.set_provider(None)


def test_bad_config_rejected():
    with pytest.raises(ai.AINarrativesError):
        ai.provider_from_env({"ATTESTRA_AI_NARRATIVES": "on", "ATTESTRA_AI_PROVIDER": "nope"})
    with pytest.raises(ai.AINarrativesError):
        ai.OllamaProvider("file:///etc/passwd")
