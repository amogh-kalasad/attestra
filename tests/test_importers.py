"""Unit tests for all scanner result importers.

Tests parse each fixture file and assert expected normalized fields.
No database interaction needed — importers are pure functions.
"""
from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------- ZAP


def test_zap_parse_nonempty():
    from attestra.importers.zap import parse

    findings = parse((FIXTURES / "zap.json").read_bytes())
    assert len(findings) > 0


def test_zap_parse_expected_fields():
    from attestra.importers.zap import parse

    findings = parse((FIXTURES / "zap.json").read_bytes())
    f = findings[0]
    assert f.tool == "zap"
    assert f.title
    assert f.severity in ("critical", "high", "medium", "low", "info")
    assert f.location.startswith("https://shop.example.com")
    assert f.cwe is not None


def test_zap_skips_confidence_zero():
    """ZAP confidence=0 means the scanner itself flagged it a false positive — skip."""
    from attestra.importers.zap import parse

    findings = parse((FIXTURES / "zap.json").read_bytes())
    locations = [f.location for f in findings]
    # The fixture has one alert with confidence 0 at /skip-me — must be absent.
    assert not any("skip-me" in loc for loc in locations)


def test_zap_html_stripped():
    """HTML tags in ZAP desc/solution must be stripped."""
    from attestra.importers.zap import parse

    findings = parse((FIXTURES / "zap.json").read_bytes())
    for f in findings:
        assert "<p>" not in f.description
        assert "<p>" not in f.recommendation


def test_zap_multi_instance_expands():
    """Each ZAP alert instance becomes a separate NormalizedFinding."""
    from attestra.importers.zap import parse

    findings = parse((FIXTURES / "zap.json").read_bytes())
    # XSS alert has 2 instances in fixture → 2 findings for that rule
    xss = [f for f in findings if "Cross Site Scripting" in f.title]
    assert len(xss) == 2


# ---------------------------------------------------------------- Nuclei


def test_nuclei_parse_nonempty():
    from attestra.importers.nuclei import parse

    findings = parse((FIXTURES / "nuclei.jsonl").read_bytes())
    assert len(findings) > 0


def test_nuclei_parse_cve_fields():
    from attestra.importers.nuclei import parse

    findings = parse((FIXTURES / "nuclei.jsonl").read_bytes())
    cve_findings = [f for f in findings if f.cves]
    assert cve_findings, "expected at least one finding with CVEs"
    # Critical RCE finding should carry CVE-2024-9999
    rce = next(f for f in cve_findings if "CVE-2024-9999" in f.cves)
    assert rce.severity == "critical"
    assert rce.cvss_score is not None
    assert rce.cvss_score >= 9.0


def test_nuclei_parse_cwe():
    from attestra.importers.nuclei import parse

    findings = parse((FIXTURES / "nuclei.jsonl").read_bytes())
    cwe_findings = [f for f in findings if f.cwe]
    assert cwe_findings, "expected at least one finding with CWE"


def test_nuclei_locations_populated():
    from attestra.importers.nuclei import parse

    findings = parse((FIXTURES / "nuclei.jsonl").read_bytes())
    assert all(f.location for f in findings), "every finding must have a location"


# ---------------------------------------------------------------- Trivy


def test_trivy_parse_nonempty():
    from attestra.importers.trivy import parse

    findings = parse((FIXTURES / "trivy.json").read_bytes())
    assert len(findings) > 0


def test_trivy_parse_vulnerability():
    from attestra.importers.trivy import parse

    findings = parse((FIXTURES / "trivy.json").read_bytes())
    vuln = [f for f in findings if "CVE-2024-9999" in f.cves]
    assert vuln, "expected CVE-2024-9999 in trivy findings"
    f = vuln[0]
    assert f.severity == "critical"
    assert f.cvss_score == pytest.approx(9.8, abs=0.01)
    assert "example-lib" in f.package


def test_trivy_parse_misconfiguration():
    from attestra.importers.trivy import parse

    findings = parse((FIXTURES / "trivy.json").read_bytes())
    misc = [f for f in findings if f.rule_id == "DS002"]
    assert misc, "DS002 misconfiguration should appear"
    assert misc[0].cwe == 16  # CWE-16 Configuration


def test_trivy_location_contains_artifact():
    from attestra.importers.trivy import parse

    findings = parse((FIXTURES / "trivy.json").read_bytes())
    vuln = [f for f in findings if f.cves]
    assert all("registry.example.com/shop/api" in f.location for f in vuln)


# ---------------------------------------------------------------- SARIF


def test_sarif_parse_nonempty():
    from attestra.importers.sarif import parse

    findings = parse((FIXTURES / "semgrep.sarif").read_bytes())
    assert len(findings) > 0


def test_sarif_parse_cwe89():
    from attestra.importers.sarif import parse

    findings = parse((FIXTURES / "semgrep.sarif").read_bytes())
    sql = [f for f in findings if f.cwe == 89]
    assert sql, "expected CWE-89 SQL injection finding"
    f = sql[0]
    assert "services/payments" in f.location
    assert f.severity in ("high", "medium")


def test_sarif_parse_location_has_line():
    from attestra.importers.sarif import parse

    findings = parse((FIXTURES / "semgrep.sarif").read_bytes())
    # Both results have startLine in the fixture
    assert all(":" in f.location for f in findings)


def test_sarif_tool_name_normalised():
    from attestra.importers.sarif import parse

    findings = parse((FIXTURES / "semgrep.sarif").read_bytes())
    assert all(f.tool == "semgrep" for f in findings)


# ---------------------------------------------------------------- Dispatch


def test_unsupported_tool_raises():
    from attestra.importers import parse

    with pytest.raises(ValueError, match="Unsupported format"):
        parse("nessus", b"{}")


def test_parse_dispatch_zap():
    from attestra.importers import parse

    findings = parse("zap", (FIXTURES / "zap.json").read_bytes())
    assert findings
