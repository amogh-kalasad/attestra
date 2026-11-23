"""AASI Phase 3 context packet — bounded, redacted, trust-labelled."""

from __future__ import annotations

import json
from types import SimpleNamespace

from attestra.aasi.context import TRUSTED, UNTRUSTED, build_context_packet


# @lat: [[tests#AASI Phase 3 context#Packet serializes and prefers ai_app]]
def test_packet_serializes_and_prefers_ai_app():
    packet = build_context_packet(
        engagement_id=42,
        tenant_id=7,
        objective="Assess chatbot at https://chat.vendor.example/",
        assets=[
            SimpleNamespace(
                id=2,
                kind="web_app",
                name="Portal",
                identifier="https://portal.example/",
                environment="staging",
                test_types=["web_dast"],
                intrusive_allowed=False,
                criticality=2,
                exposure="internet",
                notes="",
                owner="sec",
            ),
            SimpleNamespace(
                id=1,
                kind="ai_app",
                name="LLM gateway",
                identifier="https://llm.acme.example/v1",
                environment="staging",
                test_types=["ai_llm", "ai_agent"],
                intrusive_allowed=False,
                criticality=4,
                exposure="internet",
                notes="api_key=should-not-leak-into-prompt-body",
                owner="ml-team",
            ),
        ],
        findings=[
            SimpleNamespace(
                id=99,
                title="Prompt injection at https://llm.acme.example/ask",
                severity="high",
                status="new",
                description="RAW EVIDENCE body must never appear",
            )
        ],
        coverage_ledger=[
            {
                "test_id": "garak",
                "category": "ai_llm",
                "execution_status": "SKIPPED",
                "limitation": "rate limited",
                "target_endpoint": "https://llm.acme.example/v1",
                "asset_id": 1,
                "origin": "catalogue",
            },
            {
                "test_id": "T01",
                "category": "capture",
                "execution_status": "PASSED",
            },
        ],
        previous_summaries=["Prior run found injection near chat.vendor.example"],
        observations=[SimpleNamespace(id=501), 502, "503"],
        available_test_ids=["T01", "garak", "promptfoo"],
    )

    data = packet.to_dict()
    blob = json.dumps(data)
    assert data["engagement_id"] == 42
    assert data["objective"]["trust"] == UNTRUSTED
    assert "chat.vendor.example" not in data["objective"]["value"]
    assert "[url]" in data["objective"]["value"] or "[host]" in data["objective"]["value"]

    kinds = [row["value"]["kind"] for row in data["assets"]]
    assert kinds[0] == "ai_app"
    assert data["assets"][0]["value"]["identifier"]["trust"] == UNTRUSTED
    assert "llm.acme.example" not in blob
    assert "should-not-leak" not in blob or "[secret]" in blob

    finding = data["findings"][0]["value"]
    assert finding["id"] == 99
    assert "RAW EVIDENCE" not in blob
    assert "description" not in finding
    assert data["findings"][0]["trust"] == TRUSTED

    assert len(data["coverage_gaps"]) == 1
    gap = data["coverage_gaps"][0]["value"]
    assert gap["test_id"] == "garak" and gap["status"] == "SKIPPED"
    assert gap["target_endpoint"]["trust"] == UNTRUSTED

    assert data["observation_ids"] == ["501", "502", "503"]
    assert data["available_test_ids"] == ["T01", "garak", "promptfoo"]
    assert "password" not in blob.lower() or "[secret]" in blob


# @lat: [[tests#AASI Phase 3 context#Omits evidence credentials and code]]
def test_omits_evidence_credentials_and_code():
    packet = build_context_packet(
        engagement_id=1,
        objective="ok",
        assets=[
            {
                "id": 1,
                "kind": "ai_app",
                "name": "bot",
                "identifier": "https://x.example/",
                "ownership_token": "tokensecret",
                "crawl_seed_urls": "https://x.example/admin",
                "api_base_url": "https://api.x.example",
                "notes": "Bearer supersecret-token-value-here-abcdefgh",
            }
        ],
        findings=[
            {
                "id": 1,
                "title": "issue",
                "description": "evidence body",
                "recommendation": "fix me",
                "location": "https://x.example/a",
            }
        ],
        include_test_registry=False,
        include_adapters=False,
        available_test_ids=[],
    )
    data = packet.to_dict()
    asset_meta = data["assets"][0]["value"]
    for banned in ("ownership_token", "crawl_seed_urls", "api_base_url"):
        assert banned not in asset_meta
    finding = data["findings"][0]["value"]
    for banned in ("description", "recommendation", "location", "evidence"):
        assert banned not in finding
    blob = json.dumps(data)
    assert "supersecret" not in blob
    assert "tokensecret" not in blob


# @lat: [[tests#AASI Phase 3 context#Registry and AI adapters listed]]
def test_registry_and_ai_adapters_listed():
    packet = build_context_packet(
        engagement_id=1,
        objective="obj",
        include_test_registry=True,
        include_adapters=True,
    )
    ids = set(packet.available_test_ids)
    assert "T01" in ids
    assert "garak" in ids
    assert "promptfoo" in ids
    assert "safelabs" in ids
