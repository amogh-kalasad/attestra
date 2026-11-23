"""AASI Phase 1 — load and validate ai_taxonomy.yaml required keys."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
TAXONOMY = ROOT / "attestra" / "compliance" / "data" / "ai_taxonomy.yaml"
ISO_PACK = ROOT / "attestra" / "compliance" / "data" / "packs" / "iso_42001_2023.yaml"

REQUIRED_TOP = ("version", "sources", "tools", "categories")
REQUIRED_SOURCES = ("owasp_llm_top10_2025", "owasp_agentic", "iso_42001_2023")
REQUIRED_TOOLS = ("garak", "promptfoo", "safelabs", "pyrit")
REQUIRED_CATEGORIES = ("ai_llm", "ai_agent")
LLM_IDS = tuple(f"LLM{i:02d}" for i in range(1, 11))


def _load() -> dict:
    assert TAXONOMY.is_file(), f"missing {TAXONOMY}"
    data = yaml.safe_load(TAXONOMY.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


# @lat: [[tests#AI taxonomy mapping#Required keys and sources]]
def test_ai_taxonomy_required_top_level_keys():
    data = _load()
    for key in REQUIRED_TOP:
        assert key in data, f"missing top-level key {key}"
    assert str(data["version"]) == "1"


def test_ai_taxonomy_sources():
    sources = _load()["sources"]
    assert isinstance(sources, dict)
    for key in REQUIRED_SOURCES:
        assert key in sources, f"missing source {key}"
        entry = sources[key]
        assert isinstance(entry, dict)
        assert entry.get("name") or entry.get("url") or entry.get("pack")
    agentic = sources["owasp_agentic"]
    assert agentic.get("edition") or agentic.get("status")
    assert "status" in agentic


def test_ai_taxonomy_tools_have_mapping_blocks():
    tools = _load()["tools"]
    for name in REQUIRED_TOOLS:
        assert name in tools, f"missing tool {name}"
        block = tools[name]
        assert isinstance(block, dict)
        if name == "garak":
            assert "probes" in block and isinstance(block["probes"], dict)
            assert len(block["probes"]) >= 1
        elif name == "promptfoo":
            assert "plugins" in block and isinstance(block["plugins"], dict)
            assert len(block["plugins"]) >= 1
        elif name == "safelabs":
            assert "tests" in block and isinstance(block["tests"], dict)
            assert len(block["tests"]) >= 1
        elif name == "pyrit":
            assert "scenarios" in block and isinstance(block["scenarios"], dict)
            assert len(block["scenarios"]) >= 1


# @lat: [[tests#AI taxonomy mapping#Categories and ISO pack tool refs]]
def test_ai_taxonomy_categories_ai_llm_and_ai_agent():
    cats = _load()["categories"]
    for key in REQUIRED_CATEGORIES:
        assert key in cats
        entry = cats[key]
        assert isinstance(entry, dict)
        assert entry.get("primary_taxonomy")
        assert entry.get("tools")
        assert "not_claiming" in entry


def test_ai_taxonomy_cwe_only_from_iso_pack_lists():
    """Every non-empty cwe list under tools must be a subset of pack llm_top10 CWEs."""
    data = _load()
    allowed = set()
    for ids in (data.get("cwe_from_iso_pack") or {}).values():
        allowed.update(int(x) for x in ids)

    def walk(node: object) -> None:
        if isinstance(node, dict):
            if "cwe" in node and isinstance(node["cwe"], list):
                for c in node["cwe"]:
                    assert int(c) in allowed, f"invented or out-of-pack CWE-{c}"
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(data["tools"])


def test_iso_pack_assessment_tools_on_llm_top10():
    pack = yaml.safe_load(ISO_PACK.read_text(encoding="utf-8"))
    llm = pack.get("llm_top10") or {}
    for lid in LLM_IDS:
        assert lid in llm
    # Active-test entries that claim tools must list known tool names
    known = {"garak", "promptfoo", "safelabs", "pyrit"}
    for lid, entry in llm.items():
        tools = entry.get("assessment_tools") or []
        for t in tools:
            assert t in known, f"{lid} unknown assessment tool {t}"
    assert "assessment_tools" in pack
    for name in ("garak", "promptfoo", "safelabs", "pyrit"):
        assert name in pack["assessment_tools"]

