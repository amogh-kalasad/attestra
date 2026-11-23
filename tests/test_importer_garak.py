"""Unit tests for the Garak JSONL importer (AASI Phase 1)."""

from __future__ import annotations

from pathlib import Path

import pytest

from attestra.importers.garak import HIT_THRESHOLD, parse

FIXTURES = Path(__file__).parent / "fixtures" / "ai" / "garak"


def test_hit_attempt_produces_finding():
    findings = parse((FIXTURES / "hits.report.jsonl").read_bytes())
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "garak"
    assert f.rule_id == "dan.Dan_11_0:dan.DAN"
    assert f.original_id
    assert "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" in f.original_id
    assert f.severity in ("high", "medium")
    assert f.tool_version == "0.13.0"
    assert f.cwe is None
    assert f.confidence
    assert any(r.startswith("prompt:") for r in f.evidence_refs)
    assert "llm.example.com" in f.location


def test_no_hit_attempt_produces_no_finding():
    findings = parse((FIXTURES / "no_hit.report.jsonl").read_bytes())
    assert findings == []


def test_malformed_detector_results_raises():
    with pytest.raises(ValueError, match="detector_results"):
        parse((FIXTURES / "malformed.report.jsonl").read_bytes())


def test_empty_input_returns_empty():
    assert parse(b"") == []
    assert parse(b"\n\n") == []


def test_invalid_jsonl_raises():
    with pytest.raises(ValueError, match="valid JSON"):
        parse(b"{not-json\n")


def test_tool_field_is_garak():
    findings = parse((FIXTURES / "hits.report.jsonl").read_bytes())
    assert findings
    assert all(f.tool == "garak" for f in findings)


def test_original_id_present_on_hits():
    findings = parse((FIXTURES / "hits.report.jsonl").read_bytes())
    assert findings
    assert all(f.original_id for f in findings)


def test_hitlog_produces_finding():
    findings = parse((FIXTURES / "hitlog.jsonl").read_bytes())
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "garak"
    assert f.rule_id == "dan.Dan_11_0:dan.DAN"
    assert f.original_id.startswith("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    assert float(f.confidence) >= HIT_THRESHOLD


def test_started_attempt_without_complete_is_ignored():
    """status=1 rows must not become findings even if scores were present."""
    raw = (
        b'{"entry_type":"init","garak_version":"0.13.0","run":"r1"}\n'
        b'{"entry_type":"attempt","uuid":"u1","seq":0,"status":1,'
        b'"probe_classname":"dan.Dan_11_0","prompt":{"text":"x"},'
        b'"outputs":[],"detector_results":{"dan.DAN":[0.99]},"goal":"g"}\n'
    )
    assert parse(raw) == []


def test_eval_fails_alone_do_not_create_findings():
    """Aggregate eval rows are handled but never invent findings without a hit."""
    raw = (
        b'{"entry_type":"init","garak_version":"0.13.0","run":"r1"}\n'
        b'{"entry_type":"eval","probe":"dan.Dan_11_0","detector":"dan.DAN",'
        b'"passed":0,"fails":3,"nones":0,"total_evaluated":3}\n'
    )
    assert parse(raw) == []


def test_json_array_form():
    raw = (
        b'[{"entry_type":"init","garak_version":"0.13.0","run":"r1"},'
        b'{"entry_type":"attempt","uuid":"u2","seq":0,"status":2,'
        b'"probe_classname":"leakreplay.GuardianCloze","prompt":{"text":"p"},'
        b'"outputs":[{"text":"secret"}],'
        b'"detector_results":{"leakreplay.StartsWith":[0.6]},"goal":"leak"}]'
    )
    findings = parse(raw)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].tool == "garak"
