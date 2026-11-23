"""SafeLabs safelabs-eval importer tests."""
# @lat: [[tests#AASI Phase 1 SafeLabs importer]]

from __future__ import annotations

from pathlib import Path

import pytest

from attestra.importers.safelabs import parse

FIXTURES = Path(__file__).parent / "fixtures" / "ai" / "safelabs"


# @lat: [[tests#AASI Phase 1 SafeLabs importer#Positive verdicts become findings]]
def test_safelabs_positive_detections_only():
    findings = parse((FIXTURES / "report.json").read_bytes())
    assert len(findings) == 2
    by_id = {f.original_id: f for f in findings}
    assert set(by_id) == {"ASI01-001", "ASI06-010"}
    assert by_id["ASI01-001"].variant == "vulnerable"
    assert by_id["ASI06-010"].variant == "fail"


def test_safelabs_preserves_identifier_detector_evidence_score():
    findings = parse((FIXTURES / "report.json").read_bytes())
    f = next(x for x in findings if x.original_id == "ASI01-001")
    assert f.tool == "safelabs"
    assert f.rule_id == "ASI01-001"
    assert f.param == "prompt_injection"
    assert f.tool_version == "0.12.0"
    assert f.location == "http://localhost:8000/chat"
    assert f.severity == "critical"
    assert "system override accepted" in f.evidence_refs
    assert "evidence_score=70%" in f.confidence
    assert "validation=potential" in f.confidence
    assert "heuristic" in f.confidence
    assert "confirmed" not in f.confidence.lower()
    assert f.recommendation.startswith("Reject instruction-override")
    assert f.cwe == 1427


def test_safelabs_taxonomy_labelled_asi_source_not_official_owasp():
    findings = parse((FIXTURES / "report.json").read_bytes())
    for f in findings:
        assert "SafeLabs ASI-source" in f.title
        assert "official OWASP" not in f.title
        assert "OWASP Agentic" not in f.title
        assert "SafeLabs ASI-source" in f.description
        assert "not official OWASP Agentic" in f.description


# @lat: [[tests#AASI Phase 1 SafeLabs importer#Uncertain pass and errors skipped]]
def test_safelabs_skips_uncertain_pass_missing_errors():
    findings = parse((FIXTURES / "report.json").read_bytes())
    ids = {f.original_id for f in findings}
    assert "ASI01-002" not in ids  # uncertain
    assert "ASI01-003" not in ids  # pass
    assert "ASI03-004" not in ids  # missing_infrastructure
    assert "ASI08-002" not in ids  # error-only


def test_safelabs_eval_records_shape():
    findings = parse((FIXTURES / "eval_records.json").read_bytes())
    assert len(findings) == 1
    f = findings[0]
    assert f.original_id == "ASI01-018"
    assert f.tool_version == "0.12.0"
    assert f.param == "prompt_injection"
    assert "revealed system prompt fragment" in f.evidence_refs
    assert "validation=potential" in f.confidence


def test_safelabs_empty_bytes_no_findings():
    assert parse(b"") == []
    assert parse(b"[]") == []
    assert parse(b'{"results":[]}') == []


# @lat: [[tests#AASI Phase 1 SafeLabs importer#Malformed raises ValueError]]
def test_safelabs_malformed_raises():
    with pytest.raises(ValueError, match="malformed"):
        parse(b"{not-json")
    with pytest.raises(ValueError, match="malformed"):
        parse(b"null")
    with pytest.raises(ValueError, match="malformed"):
        parse(b'"just a string"')
