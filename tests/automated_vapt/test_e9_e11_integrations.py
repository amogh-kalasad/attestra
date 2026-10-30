"""Elite Phases E9–E11: manifest/redaction, Burp import, finding mapping."""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest

from attestra import config, db, services
from attestra.automated_vapt.evidence.evidence_hasher import EvidenceManifest, sha256_hex
from attestra.automated_vapt.evidence.evidence_redactor import redact_http_pair
from attestra.automated_vapt.integrations.attestra_findings import create_finding_from_validation
from attestra.automated_vapt.integrations.burp_importer import import_burp_bytes
from attestra.proof.pair import HttpPair

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture
def elite_flag(monkeypatch):
    monkeypatch.setattr(config, "AUTOMATED_VAPT_ENABLED", True)


# @lat: [[tests#Elite Phase E9 evidence integrity#Manifest hash verify]]
def test_manifest_hash_verify():
    data = b"elite-evidence"
    man = EvidenceManifest(engagement_id=1, test_execution_id=2)
    entry = man.add(evidence_id="e1", file_name="a.bin", data=data, capture_method="httpx")
    assert entry.hash == sha256_hex(data)
    assert man.verify("e1", data) is True
    assert man.verify("e1", b"tampered") is False


# @lat: [[tests#Elite Phase E9 evidence integrity#Redact http pair]]
def test_redact_http_pair():
    pair = HttpPair(
        method="GET",
        url="http://localhost/x?token=abc",
        request_headers={"Authorization": "Bearer secret"},
        request_body="",
        status=200,
        response_body="ok",
    )
    red = redact_http_pair(pair)
    assert red.request_headers.get("Authorization") == "[REDACTED]" or any(
        v == "[REDACTED]" for k, v in red.request_headers.items() if k.lower() == "authorization"
    )


# @lat: [[tests#Elite Phase E10 burp import#Import sample burp]]
def test_import_sample_burp():
    path = FIXTURES / "burp" / "burp_issues.xml"
    if not path.exists():
        pytest.skip("burp fixture missing")
    out = import_burp_bytes(path.read_bytes())
    assert out["finding_count"] >= 1


# @lat: [[tests#Elite Phase E11 finding integration#Create from confirmed]]
def test_create_from_confirmed(fresh_db, elite_flag):
    today = date.today()
    with db.session() as s:
        e = services.create_engagement(
            s,
            tenant="Elite E11",
            name="Elite E11",
            type="vapt",
            frameworks=["pci_dss_4"],
            window_start=today,
            window_end=today + timedelta(days=7),
            actor="tester",
        )
        services.add_authorization(
            s,
            e.id,
            filename="roe.txt",
            data=b"authorized",
            signer="Client",
            signed_on=today,
            expires_on=today + timedelta(days=7),
            rules_of_engagement="local",
            environments=["dev"],
            actor="tester",
        )
        a = services.add_asset(
            s,
            e.id,
            kind="web_app",
            identifier="http://localhost:8765/",
            name="Mock",
            environment="dev",
            actor="tester",
        )
        f1 = create_finding_from_validation(
            s,
            engagement_id=e.id,
            asset_id=a.id,
            title="BOLA on project API",
            description="Account A accessed Project B",
            validation={"status": "CONFIRMED", "confidence": "high", "reasons": ["exposure"]},
            location="/api/projects/proj-b",
        )
        assert f1 is not None
        assert f1.severity in ("high", "medium", "critical")
        f2 = create_finding_from_validation(
            s,
            engagement_id=e.id,
            asset_id=a.id,
            title="BOLA on project API",
            description="Account A accessed Project B",
            validation={"status": "CONFIRMED", "confidence": "high", "reasons": ["exposure"]},
            location="/api/projects/proj-b",
        )
        assert f2 is not None and f2.id == f1.id
        none = create_finding_from_validation(
            s,
            engagement_id=e.id,
            asset_id=a.id,
            title="No issue",
            description="ok",
            validation={"status": "NOT_VULNERABLE", "confidence": "high", "reasons": []},
        )
        assert none is None


# @lat: [[tests#Elite Phase E11 finding integration#Document evidence in report HTML]]
def test_document_evidence_in_report_html(fresh_db, elite_flag):
    """When documenting, HTTP pair + two-panel PNG attach and appear in technical HTML."""
    from attestra.automated_vapt.integrations.attestra_findings import document_finding_evidence
    from attestra.reports import generate_report

    today = date.today()
    tiny_png = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05"
        b"\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    pair = HttpPair(
        method="GET",
        url="http://localhost:8765/api/projects/proj-b",
        request_headers={"Authorization": "Bearer secret-token"},
        status=200,
        response_body='{"id":"proj-b","secret_note":"SENSITIVE"}',
        source="automated_vapt",
    )
    with db.session() as s:
        e = services.create_engagement(
            s,
            tenant="Elite E11 Docs",
            name="Elite E11 Docs",
            type="vapt",
            frameworks=["pci_dss_4"],
            window_start=today,
            window_end=today + timedelta(days=7),
            actor="tester",
        )
        services.add_authorization(
            s,
            e.id,
            filename="roe.txt",
            data=b"authorized",
            signer="Client",
            signed_on=today,
            expires_on=today + timedelta(days=7),
            rules_of_engagement="local",
            environments=["dev"],
            actor="tester",
        )
        a = services.add_asset(
            s,
            e.id,
            kind="web_app",
            identifier="http://localhost:8765/",
            name="Mock",
            environment="dev",
            actor="tester",
        )
        finding = create_finding_from_validation(
            s,
            engagement_id=e.id,
            asset_id=a.id,
            title="BOLA documented with images",
            description="Cross-owner access exposed secrets",
            validation={"status": "CONFIRMED", "confidence": "high", "reasons": ["exposure"]},
            location="/api/projects/proj-b",
        )
        assert finding is not None
        meta = document_finding_evidence(
            s,
            finding.id,
            actor="tester",
            http_pairs=[pair],
            screenshots=[("elite_browser.png", tiny_png)],
        )
        assert meta["http_pair_ids"]
        assert meta["two_panel_ids"]
        assert meta["screenshot_ids"]
        report = generate_report(s, e.id, kind="technical", actor="tester")
        body = Path(report.path).read_text(encoding="utf-8")
        assert "data:image/png;base64," in body
        assert "http-pair" in body or "HTTP request" in body or "GET" in body
        assert "Elite two-panel" in body or "Elite browser" in body or "Fig." in body
