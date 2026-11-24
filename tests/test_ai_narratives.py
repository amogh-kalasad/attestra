import json
import socket
from types import SimpleNamespace

import pytest

from attestra import ai_narratives as ai


class FakeProvider:
    name = "fake"

    def __init__(self):
        self.calls = []

    def complete(self, system, prompt, *, max_tokens=None, timeout=None):
        self.calls.append({"prompt": prompt, "max_tokens": max_tokens, "timeout": timeout})
        return (
            "## Description\nDrafted description.\n\n"
            "## Impact\nDrafted impact.\n\n"
            "## Likelihood\nDrafted likelihood.\n\n"
            "## Recommendation\nDrafted recommendation."
        )


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
    assert "## Description" in d.text and "## Recommendation" in d.text
    prompts = "\n".join(c["prompt"] for c in fake.calls)
    assert "acme" not in prompts and "hunter2" not in prompts
    assert "Description" in fake.calls[0]["prompt"] and "Impact" in fake.calls[0]["prompt"]
    assert fake.calls[0]["timeout"] == 120.0 and fake.calls[0]["max_tokens"] == 2048
    assert ai.approved_text(store, 7, "finding", 1) is None
    assert ai.approved_text(store, 7, "executive_summary") is None
    with pytest.raises(PermissionError):
        store.approve(7, d.id, user="c", role="client_viewer")
    store.approve(7, d.id, user="t1", role="tester", edited_text="Reviewed text.")
    assert ai.approved_text(store, 7, "finding", 1) == "Reviewed text."
    store.reject(7, s.id, user="t1")
    assert ai.approved_text(store, 7, "executive_summary") is None


def test_multi_finding_per_and_combined(tmp_path, monkeypatch):
    monkeypatch.setenv("ATTESTRA_AI_NARRATIVES", "on")
    store = ai.DraftStore(tmp_path)
    fake = FakeProvider()
    findings = [_finding(id=1), _finding(id=2, severity="low"), _finding(id=3, severity="medium")]
    batch = ai.draft_finding_narratives(fake, store, 9, findings)
    assert len(batch) == 3
    assert all(d.kind == "finding" and d.finding_id in (1, 2, 3) for d in batch)
    combined = ai.draft_combined_finding_writeup(fake, store, 9, findings)
    assert combined is not None and combined.kind == "finding_combined" and combined.finding_id is None
    last = fake.calls[-1]
    assert "F-1" in last["prompt"] and "F-3" in last["prompt"]
    expect_tokens, expect_timeout = ai.draft_generation_budget(3, mode="combined")
    assert last["max_tokens"] == expect_tokens and last["timeout"] == expect_timeout
    secs = ai.writeup_sections(batch[0].text)
    assert [h for h, _ in secs] == list(ai.FINDING_WRITEUP_SECTIONS)
    sample = (
        "# F-1 · SQL injection\n\n## Description\nA\n\n## Impact\nB\n\n## Likelihood\nC\n\n## Recommendation\nD\n\n"
        "# F-2 · XSS\n\n## Description\nE\n\n## Impact\nF\n\n## Likelihood\nG\n\n## Recommendation\nH"
    )
    blocks = ai.combined_writeup_blocks(sample)
    assert len(blocks) == 2
    assert blocks[0][0].startswith("F-1") and [h for h, _ in blocks[0][1]] == list(ai.FINDING_WRITEUP_SECTIONS)
    assert blocks[1][0].startswith("F-2") and blocks[1][1][0][1] == "E"


def test_draft_generation_budget_scales_with_finding_count():
    t1, w1 = ai.draft_generation_budget(1, mode="combined")
    t45, w45 = ai.draft_generation_budget(45, mode="combined")
    assert t45 > t1 and w45 > w1
    assert t45 == ai.MAX_OUTPUT_TOKENS
    assert w45 == ai.MAX_HTTP_TIMEOUT_S
    assert ai.draft_generation_budget(1, mode="finding") == (2048, 120.0)


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
    from attestra.ai_providers import AIProviderError

    with pytest.raises(ai.AINarrativesError):
        ai.provider_from_env({"ATTESTRA_AI_NARRATIVES": "on", "ATTESTRA_AI_PROVIDER": "nope"})
    with pytest.raises(AIProviderError):
        ai.OllamaProvider("file:///etc/passwd")


def test_http_post_includes_error_body(monkeypatch):
    """Provider HTTP failures must surface the upstream body, not only the status line."""
    import io

    import urllib.error

    from attestra.ai_providers import AIProviderError, _http_post

    class FakeHTTPError(urllib.error.HTTPError):
        def __init__(self):
            super().__init__("https://api.example/v1/messages", 400, "Bad Request", {}, None)
            self._buf = io.BytesIO(b'{"type":"error","error":{"message":"invalid model"}}')

        def read(self, n=-1):
            return self._buf.read(n)

    def boom(req, timeout=60.0):
        raise FakeHTTPError()

    import attestra.ai_providers as providers

    monkeypatch.setattr(providers.urllib.request, "urlopen", boom)
    with pytest.raises(AIProviderError) as exc:
        _http_post("https://api.example/v1/messages", {"Content-Type": "application/json"}, {"model": "x"})
    msg = str(exc.value)
    assert "400" in msg
    assert "invalid model" in msg


def test_anthropic_and_catalog_providers(monkeypatch):
    from attestra.ai_providers import AnthropicProvider, build_provider

    sent = []

    def post(url, headers, body):
        sent.append((url, dict(headers), body))
        if "messages" in url and "chat" not in url:
            return {"content": [{"type": "text", "text": "claude text"}]}
        return {"choices": [{"message": {"content": "compat text"}}]}

    env = {
        "ATTESTRA_AI_NARRATIVES": "on",
        "ATTESTRA_AI_PROVIDER": "anthropic",
        "ATTESTRA_AI_MODEL": "claude-sonnet-4-5",
        "ATTESTRA_AI_API_KEY": "sk-ant-test-key",
    }
    p = ai.provider_from_env(env, http_post=post)
    assert isinstance(p, AnthropicProvider)
    assert p.complete("sys", "user") == "claude text"
    assert sent[-1][0] == "https://api.anthropic.com/v1/messages"
    assert sent[-1][1]["x-api-key"] == "sk-ant-test-key"
    assert "anthropic-version" in sent[-1][1]
    assert "sk-ant-test-key" not in repr(p)

    # Operators often set ATTESTRA_AI_BASE_URL=.../v1; do not produce /v1/v1/messages.
    sent.clear()
    p_v1 = AnthropicProvider("https://api.anthropic.com/v1", "claude-sonnet-4-5", "sk-ant-test-key", http_post=post)
    assert p_v1.complete("sys", "user") == "claude text"
    assert sent[-1][0] == "https://api.anthropic.com/v1/messages"

    x = build_provider(provider="xai", model="grok-2-latest", api_key="xk", http_post=post)
    assert x.complete("s", "u") == "compat text"
    assert sent[-1][0] == "https://api.x.ai/v1/chat/completions"
    assert sent[-1][1]["Authorization"] == "Bearer xk"
