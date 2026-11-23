"""AASI Phase 3 provider wrapper — mocks only, no live LLM."""

from __future__ import annotations

import json

import pytest

from attestra import config
from attestra.aasi.provider import (
    AasiProvider,
    AasiProviderDisabled,
    AasiProviderError,
    build_provider,
)


class FakeProvider:
    name = "fake"

    def __init__(self, responses: list[str] | None = None, *, error: Exception | None = None):
        self.calls: list[tuple[str, str]] = []
        self._responses = list(responses or ['{"ok": true}'])
        self._error = error

    def complete(self, system: str, prompt: str) -> str:
        self.calls.append((system, prompt))
        if self._error is not None:
            raise self._error
        if not self._responses:
            return '{"ok": true}'
        return self._responses.pop(0)


@pytest.fixture
def aasi_ai_on(monkeypatch):
    monkeypatch.setattr(config, "AASI_ENABLED", True)
    monkeypatch.setenv("ATTESTRA_AI_NARRATIVES", "on")
    monkeypatch.delenv("ATTESTRA_AI_TENANTS_OFF", raising=False)


# @lat: [[tests#AASI Phase 3 provider#Tenant off disables provider]]
def test_tenant_off_disables_provider(monkeypatch, aasi_ai_on):
    monkeypatch.setenv("ATTESTRA_AI_TENANTS_OFF", "9")
    fake = FakeProvider()
    with pytest.raises(AasiProviderDisabled, match="tenant"):
        build_provider(tenant_id=9, provider=fake)
    assert fake.calls == []


# @lat: [[tests#AASI Phase 3 provider#Narratives off disables provider]]
def test_narratives_off_disables_provider(monkeypatch):
    monkeypatch.setattr(config, "AASI_ENABLED", True)
    monkeypatch.setenv("ATTESTRA_AI_NARRATIVES", "off")
    fake = FakeProvider()
    with pytest.raises(AasiProviderDisabled):
        build_provider(provider=fake)
    assert fake.calls == []


# @lat: [[tests#AASI Phase 3 provider#AASI flag off disables provider]]
def test_aasi_flag_off_disables_provider(monkeypatch):
    monkeypatch.setattr(config, "AASI_ENABLED", False)
    monkeypatch.setenv("ATTESTRA_AI_NARRATIVES", "on")
    fake = FakeProvider()
    with pytest.raises(AasiProviderDisabled, match="AASI"):
        build_provider(provider=fake)
    assert fake.calls == []


# @lat: [[tests#AASI Phase 3 provider#Redaction strips URLs and hosts]]
def test_redaction_strips_urls_and_hosts(aasi_ai_on):
    fake = FakeProvider(responses=['{"objectives": ["probe"]}'])
    usage_events = []
    wrapper = AasiProvider(fake, on_usage=usage_events.append, tenant_id=1)
    out = wrapper.complete_json(
        "system",
        "Assess https://llm.acme.example/v1/chat for host db01.corp.example",
        schema_hint={"required": ["objectives"]},
    )
    assert out == {"objectives": ["probe"]}
    assert len(fake.calls) == 1
    system, prompt = fake.calls[0]
    blob = system + prompt
    assert "https://llm.acme.example" not in blob
    assert "llm.acme.example" not in blob
    assert "db01.corp.example" not in blob
    assert "[url]" in blob or "[host]" in blob
    assert usage_events and usage_events[0].calls == 1


# @lat: [[tests#AASI Phase 3 provider#Schema validation and retries]]
def test_schema_validation_and_retries(aasi_ai_on, monkeypatch):
    monkeypatch.setattr(config, "AASI_RETRY_LIMIT", 2)
    fake = FakeProvider(
        responses=[
            "not-json",
            '{"partial": 1}',
            '{"objectives": ["a"], "extra": true}',
        ]
    )
    wrapper = AasiProvider(fake, retry_limit=2)
    out = wrapper.complete_json("s", "p", schema_hint=["objectives"])
    assert out["objectives"] == ["a"]
    assert len(fake.calls) == 3
    assert wrapper.usage.retries == 2
    assert wrapper.usage.calls == 3


# @lat: [[tests#AASI Phase 3 provider#Schema failure exhausts retries]]
def test_schema_failure_exhausts_retries(aasi_ai_on):
    fake = FakeProvider(responses=['{"nope": 1}', '{"nope": 2}'])
    wrapper = AasiProvider(fake, retry_limit=1)
    with pytest.raises(AasiProviderError, match="required keys"):
        wrapper.complete_json("s", "p", schema_hint={"required": ["objectives"]})
    assert len(fake.calls) == 2


# @lat: [[tests#AASI Phase 3 provider#Fence JSON accepted]]
def test_fenced_json_accepted(aasi_ai_on):
    fake = FakeProvider(responses=['Here you go:\n```json\n{"objectives": ["x"]}\n```'])
    wrapper = AasiProvider(fake)
    assert wrapper.complete_json("s", "p", ["objectives"])["objectives"] == ["x"]


def test_usage_to_dict(aasi_ai_on):
    fake = FakeProvider()
    wrapper = build_provider(provider=fake, tenant_id=1)
    wrapper.complete_json("s", "p", schema_hint=["ok"])
    d = wrapper.usage.to_dict()
    assert d["calls"] == 1 and d["provider"] == "fake"
    assert "tokens_in" in d
