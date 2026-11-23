"""PyRIT attack-result export importer tests (fixture-driven contract)."""
# @lat: [[tests#AASI Phase 1 PyRIT importer]]

from __future__ import annotations

from pathlib import Path

import pytest

from attestra.importers.pyrit import parse

FIXTURES = Path(__file__).parent / "fixtures" / "ai" / "pyrit"


# @lat: [[tests#AASI Phase 1 PyRIT importer#Successful attack becomes finding]]
def test_pyrit_success_only_no_false_findings():
    findings = parse((FIXTURES / "attack_results.json").read_bytes())
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "pyrit"
    assert f.original_id == "ar-success-1"
    assert f.variant == "success"
    assert "b7896526-f44d-4d11-a210-4f33b934f629" in f.description
    assert "crescendo-jailbreak-01" in f.description


def test_pyrit_preserves_conversation_scenario_score_success():
    findings = parse((FIXTURES / "attack_results.json").read_bytes())
    f = findings[0]
    assert "conversation_id:b7896526-f44d-4d11-a210-4f33b934f629" in f.evidence_refs
    assert "scenario_id:crescendo-jailbreak-01" in f.evidence_refs
    assert "score:True" in f.evidence_refs or "score:true" in {e.lower() for e in f.evidence_refs}
    assert "outcome:success" in f.evidence_refs
    assert f.tool_version == "1.2.1"
    assert f.location == "https://llm.example.com/v1/chat"
    assert "CrescendoAttack" in f.title
    assert "validation=potential" in f.confidence
    assert f.param == "CrescendoAttack"


def test_pyrit_jsonl_success_and_skip_failure():
    findings = parse((FIXTURES / "attack_results.jsonl").read_bytes())
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "pyrit"
    assert "jsonl-success-1" in f.description
    assert "PAIRAttack" in f.title


# @lat: [[tests#AASI Phase 1 PyRIT importer#Failed empty yield nothing]]
def test_pyrit_empty_and_all_failed_yield_nothing():
    assert parse(b"") == []
    assert parse(b"[]") == []
    assert parse(b'{"attack_results":[]}') == []
    failed_only = b"""{
      "attack_results": [
        {"conversation_id": "x", "outcome": "failure", "success": false},
        {"conversation_id": "y", "outcome": "error"},
        {"conversation_id": "z", "outcome": "undetermined"}
      ]
    }"""
    assert parse(failed_only) == []


def test_pyrit_success_flag_without_outcome():
    raw = b"""{
      "results": [
        {
          "conversation_id": "flag-1",
          "scenario_id": "sc-1",
          "objective": "exfiltrate",
          "attack_type": "TreeOfAttacks",
          "success": true,
          "score": {"value": 0.95, "score_type": "float_scale", "category": ["exfil"]}
        }
      ]
    }"""
    findings = parse(raw)
    assert len(findings) == 1
    assert findings[0].param == "TreeOfAttacks"
    assert "scenario_id:sc-1" in findings[0].evidence_refs


# @lat: [[tests#AASI Phase 1 PyRIT importer#Malformed raises ValueError]]
def test_pyrit_malformed_raises():
    with pytest.raises(ValueError, match="malformed"):
        parse(b"{not-json")
    with pytest.raises(ValueError, match="malformed"):
        parse(b"null")
    with pytest.raises(ValueError, match="malformed"):
        parse(b"42")
