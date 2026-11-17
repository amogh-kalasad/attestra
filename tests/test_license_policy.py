"""F-04 licence policy over CycloneDX (opt-in importer findings)."""
# @lat: [[intel-and-reporting#Licence policy]]

from __future__ import annotations

import json
from pathlib import Path

from attestra.importers import cyclonedx
from attestra.supply_chain import license_policy as lp

FIXTURES = Path(__file__).parent / "fixtures"
BOM = {
    "bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {"name": "app"}},
    "components": [
        {"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21", "licenses": [{"license": {"id": "MIT"}}]},
        {"name": "agpl-lib", "version": "1.0", "purl": "pkg:npm/agpl-lib@1.0", "licenses": [{"license": {"id": "AGPL-3.0-only"}}]},
        {"name": "dual", "version": "2.0", "licenses": [{"expression": "GPL-2.0-only OR MIT"}]},
        {"name": "both", "version": "3.0", "licenses": [{"expression": "Apache-2.0 AND LGPL-2.1-only"}]},
        {"name": "nolicense", "version": "0.1", "components": [
            {"name": "nested-gpl", "version": "1", "licenses": [{"license": {"id": "GPL-3.0-or-later"}}]}]},
    ],
}


def _by_name(decisions):
    return {d.component: d.decision for d in decisions}


def test_default_policy_decisions():
    got = _by_name(lp.evaluate_bom(BOM))
    assert got == {"lodash": "allow", "agpl-lib": "deny", "dual": "allow", "both": "review",
                   "nolicense": "unknown", "nested-gpl": "review"}
    assert {d.component for d in lp.violations(lp.evaluate_bom(BOM))} == {"agpl-lib", "both", "nolicense", "nested-gpl"}


def test_custom_policy_file(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text("name: strict\nversion: s1\ndeny: [GPL-3.0-or-later]\nunknown: deny\n", encoding="utf-8")
    pol = lp.load_policy(p)
    got = _by_name(lp.evaluate_bom(BOM, pol))
    assert got["nested-gpl"] == "deny" and got["nolicense"] == "deny"


def test_importer_off_by_default(monkeypatch):
    monkeypatch.delenv("ATTESTRA_LICENSE_POLICY", raising=False)
    raw = (FIXTURES / "cyclonedx.json").read_bytes()
    before = cyclonedx.parse(raw)
    assert all(not f.rule_id.startswith("license-policy") for f in before)
    bom_only = cyclonedx.parse(json.dumps(BOM).encode())
    assert bom_only == []


def test_importer_emits_license_findings_when_enabled(monkeypatch):
    monkeypatch.setenv("ATTESTRA_LICENSE_POLICY", "default")
    out = cyclonedx.parse(json.dumps(BOM).encode())
    rules = sorted(f.rule_id for f in out)
    assert rules == ["license-policy:deny", "license-policy:review", "license-policy:review", "license-policy:unknown"]
    deny = next(f for f in out if f.rule_id == "license-policy:deny")
    assert deny.severity == "medium" and "AGPL-3.0-only" in deny.description and deny.location == "app::pkg:npm/agpl-lib@1.0"
