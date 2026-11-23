"""AASI Phase 1: promptfoo results.json → NormalizedFinding."""
# @lat: [[tests#AASI Phase 1 promptfoo importer]]

from __future__ import annotations

from pathlib import Path

import pytest

from attestra.importers import promptfoo

FIX = Path(__file__).parent / "fixtures" / "ai" / "promptfoo"


def _load(name: str) -> bytes:
    return (FIX / name).read_bytes()


# @lat: [[tests#AASI Phase 1 promptfoo importer#Failed assertion becomes finding]]
def test_failed_assertion_becomes_finding():
    out = promptfoo.parse(_load("results_failed.json"))
    assert len(out) == 2
    by_plugin = {f.rule_id: f for f in out}
    assert set(by_plugin) == {"promptExtraction", "sqlInjection"}

    inj = by_plugin["promptExtraction"]
    assert inj.tool == "promptfoo"
    assert inj.severity == "high"
    assert inj.variant == "crescendo"
    assert "crescendo" in inj.original_id
    assert "promptExtraction" in inj.original_id
    assert inj.location.startswith("vulnerable-chat")
    assert inj.tool_version == "0.126.0"
    assert inj.cwe is None
    assert inj.param == "0"

    sql = by_plugin["sqlInjection"]
    assert sql.severity == "critical"
    assert sql.variant == "basic"
    assert "sqlInjection" in sql.original_id
    assert "basic" in sql.original_id


# @lat: [[tests#AASI Phase 1 promptfoo importer#All-pass yields no findings]]
def test_all_pass_yields_empty():
    assert promptfoo.parse(_load("results_passed.json")) == []


# @lat: [[tests#AASI Phase 1 promptfoo importer#Malformed raises ValueError]]
def test_malformed_raises_value_error():
    with pytest.raises(ValueError, match="Unsupported promptfoo structure"):
        promptfoo.parse(_load("results_malformed.json"))


def test_invalid_json_raises_value_error():
    with pytest.raises(ValueError, match="Invalid promptfoo JSON"):
        promptfoo.parse(b"{not-json")


def test_empty_bytes_yields_empty():
    assert promptfoo.parse(b"") == []


def test_plugin_and_strategy_on_rule_or_original_id():
    out = promptfoo.parse(_load("results_failed.json"))
    for f in out:
        blob = f"{f.rule_id}|{f.original_id}|{f.variant}"
        assert f.rule_id  # plugin id preferred as rule_id
        assert f.variant  # strategy id as variant
        assert f.rule_id in blob and f.variant in blob
