"""AASI Phase 1: AI asset kind and test-type catalogues."""

from attestra.models import (
    ASSET_KINDS,
    DEFAULT_TESTS,
    DISPLAY_LABELS,
    PT_TEST_TYPES,
    TEST_TYPES,
    VA_TEST_TYPES,
    allowed_test_types_for,
    default_tests_for,
)


# @lat: [[tests#AASI Phase 1 asset types#AI catalogues registered]]
def test_ai_catalogues_registered():
    assert "ai_app" in ASSET_KINDS
    assert ASSET_KINDS["ai_app"]
    assert "ai_llm" in TEST_TYPES
    assert "ai_agent" in TEST_TYPES
    assert TEST_TYPES["ai_llm"]["standard"] == "OWASP LLM Top 10 (2025)"
    assert TEST_TYPES["ai_agent"]["standard"] == "OWASP Agentic Applications"
    assert TEST_TYPES["ai_llm"]["imports"] == ["garak", "promptfoo", "pyrit"]
    assert TEST_TYPES["ai_agent"]["imports"] == ["safelabs", "promptfoo", "garak"]
    for key in ("ai_app", "ai_llm", "ai_agent"):
        assert key in DISPLAY_LABELS


# @lat: [[tests#AASI Phase 1 asset types#ai_app defaults]]
def test_ai_app_defaults():
    assert DEFAULT_TESTS["ai_app"] == ["ai_llm", "ai_agent"]
    assert default_tests_for("ai_app", "va") == ["ai_llm", "ai_agent"]
    assert default_tests_for("ai_app", "vapt") == ["ai_llm", "ai_agent"]
    assert "manual_pt" not in DEFAULT_TESTS["ai_app"]


# @lat: [[tests#AASI Phase 1 asset types#VA includes AI tests]]
def test_va_includes_ai_test_types():
    assert "ai_llm" in VA_TEST_TYPES
    assert "ai_agent" in VA_TEST_TYPES
    allowed = allowed_test_types_for("va")
    assert "ai_llm" in allowed
    assert "ai_agent" in allowed


# @lat: [[tests#AASI Phase 1 asset types#PT excludes AI tests]]
def test_pt_excludes_ai_test_types():
    assert "ai_llm" not in PT_TEST_TYPES
    assert "ai_agent" not in PT_TEST_TYPES
    allowed = allowed_test_types_for("pt")
    assert "ai_llm" not in allowed
    assert "ai_agent" not in allowed
    assert allowed == PT_TEST_TYPES
    assert "manual_pt" in allowed
