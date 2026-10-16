"""ZAP CSP alertRef variants must stay as separate findings."""
from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import select

FIXTURES = Path(__file__).parent / "fixtures"

CSP_VARIANTS = FIXTURES / "zap_csp_variants.json"

# Legacy import: same plugin/location/CWE/param, no distinct alertRef.
_LEGACY_CSP = {
    "site": [
        {
            "@name": "https://shop.example.com",
            "alerts": [
                {
                    "pluginid": "10055",
                    "alertRef": "10055",
                    "alert": "CSP: Wildcard Directive",
                    "riskcode": "1",
                    "confidence": "2",
                    "cweid": "693",
                    "desc": "<p>Content Security Policy contains a wildcard directive.</p>",
                    "solution": "<p>Remove wildcard sources from the Content-Security-Policy header.</p>",
                    "instances": [
                        {"uri": "https://shop.example.com/", "param": "Content-Security-Policy"}
                    ],
                }
            ],
        }
    ]
}


def test_zap_csp_variants_import_keeps_three(engagement):
    """Three CSP alertRefs at the same URL must not collapse into one finding."""
    from attestra import db, services
    from attestra.models import Finding

    with db.session() as s:
        run = services.import_results(
            s,
            engagement,
            tool="zap",
            filename="zap_csp_variants.json",
            data=CSP_VARIANTS.read_bytes(),
            actor="tester",
        )
        findings = list(s.scalars(select(Finding).where(Finding.engagement_id == engagement)))

    assert run.new_findings == 3
    assert len(findings) == 3
    titles = {f.title for f in findings}
    assert "CSP: Wildcard Directive" in titles
    assert "CSP: script-src unsafe-inline" in titles
    assert "CSP: style-src unsafe-inline" in titles


def test_zap_csp_legacy_fingerprint_merge(engagement):
    """Old-fingerprint finding re-imported: 1 merged + 2 new."""
    from attestra import db, services
    from attestra.models import Finding

    with db.session() as s:
        run1 = services.import_results(
            s,
            engagement,
            tool="zap",
            filename="zap_csp_legacy.json",
            data=json.dumps(_LEGACY_CSP).encode(),
            actor="tester",
        )
        assert run1.new_findings == 1

        run2 = services.import_results(
            s,
            engagement,
            tool="zap",
            filename="zap_csp_variants.json",
            data=CSP_VARIANTS.read_bytes(),
            actor="tester",
        )
        findings = list(s.scalars(select(Finding).where(Finding.engagement_id == engagement)))

    assert run2.updated_findings == 1
    assert run2.new_findings == 2
    assert len(findings) == 3
