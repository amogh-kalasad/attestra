"""Phase 5 workflow: AI draft provider keys stay out of drafts, logs, and errors."""

from __future__ import annotations

import json
import logging

import pytest

from attestra import ai_narratives as ai


class FakeProvider:
    name = "fake"

    def __init__(self, text: str = "Drafted narrative."):
        self.calls = []
        self.text = text

    def complete(self, system, prompt):
        self.calls.append(prompt)
        return self.text


def _finding(**kw):
    from types import SimpleNamespace

    base = dict(
        id=1,
        title="SQL injection at https://app.acme.example/login",
        severity="high",
        cwe=89,
        cves=["CVE-2024-12345"],
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


# @lat: [[tests#Phase 5 workflow#AI key never in drafts or errors]]
def test_openai_key_never_in_drafts_logs_or_errors(tmp_path, monkeypatch, caplog):
    secret = "sk-test-NEVER-LEAK-THIS-KEY-VALUE-9f3a"
    monkeypatch.setenv("ATTESTRA_AI_NARRATIVES", "on")
    monkeypatch.setenv("ATTESTRA_AI_PROVIDER", "openai")
    monkeypatch.setenv("ATTESTRA_AI_BASE_URL", "https://llm.internal/v1")
    monkeypatch.setenv("ATTESTRA_AI_MODEL", "m")
    monkeypatch.setenv("ATTESTRA_AI_API_KEY", secret)

    sent = []

    def post(url, headers, body):
        sent.append((url, headers, body))
        auth = headers.get("Authorization", "")
        assert auth == f"Bearer {secret}"
        # Transport must not echo the Authorization header into the response body.
        assert secret not in json.dumps(body)
        return {"choices": [{"message": {"content": "Safe draft text."}}]}

    store = ai.DraftStore(tmp_path)
    with caplog.at_level(logging.DEBUG):
        p = ai.provider_from_env(http_post=post)
        assert p is not None and p.name == "openai"
        assert secret not in repr(p)
        d = ai.draft_finding_narrative(p, store, 9, _finding())
    assert d is not None and d.text == "Safe draft text."
    blob = json.dumps([d.__dict__], default=str)
    assert secret not in blob
    assert "Authorization" not in blob
    assert secret not in caplog.text
    assert secret not in "".join(str(r.getMessage()) for r in caplog.records)

    def boom(url, headers, body):
        raise RuntimeError(f"upstream 401 Authorization: Bearer {secret}")

    p2 = ai.provider_from_env(http_post=boom)
    with pytest.raises(ai.AINarrativesError) as exc:
        p2.complete("s", "u")
    assert secret not in str(exc.value)
    assert "Bearer [redacted]" in str(exc.value) or "[redacted]" in str(exc.value)


# @lat: [[tests#Phase 5 workflow#AI defaults to ollama when unset]]
def test_default_provider_is_ollama_feature_still_off(monkeypatch):
    monkeypatch.delenv("ATTESTRA_AI_NARRATIVES", raising=False)
    monkeypatch.delenv("ATTESTRA_AI_PROVIDER", raising=False)
    assert ai.is_enabled() is False
    assert ai.provider_from_env() is None

    monkeypatch.setenv("ATTESTRA_AI_NARRATIVES", "on")
    monkeypatch.delenv("ATTESTRA_AI_PROVIDER", raising=False)

    def post(url, headers, body):
        assert url.endswith("/api/chat")
        return {"message": {"content": "local"}}

    p = ai.provider_from_env({"ATTESTRA_AI_NARRATIVES": "on"}, http_post=post)
    assert p is not None and p.name == "ollama"
    assert p.complete("s", "u") == "local"
