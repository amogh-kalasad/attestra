"""G-05 OSV correlation with stated match confidence (never certainty). Offline fixtures."""
# @lat: [[intel-and-reporting#NVD and OSV]]

from __future__ import annotations

import json
from pathlib import Path

from attestra.intel import osv

VULNS = [
    {"id": "GHSA-aaaa", "aliases": ["CVE-2021-23337"], "summary": "Command injection in lodash",
     "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                   "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]},
    {"id": "PYSEC-2023-74", "aliases": ["CVE-2023-32681"],
     "affected": [{"package": {"ecosystem": "PyPI", "name": "Requests"}, "versions": ["2.30.0", "2.29.0"],
                   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.3.0"}, {"fixed": "2.31.0"}]}]}]},
    {"id": "OSV-WITHDRAWN", "withdrawn": "2024-01-01T00:00:00Z",
     "affected": [{"package": {"ecosystem": "npm", "name": "lodash"}, "versions": ["4.17.20"]}]},
    {"id": "GHSA-odd", "affected": [{"package": {"ecosystem": "npm", "name": "weird"},
                                     "ranges": [{"type": "GIT", "events": [{"introduced": "abc123"}]}]}]},
]


def test_confidence_levels():
    comps = ["pkg:npm/lodash@4.17.20", "pkg:pypi/requests@2.30.0", "pkg:pypi/requests@2.28.1",
             "pkg:npm/lodash@4.17.21", {"ecosystem": "npm", "name": "weird", "version": "1.0.0"},
             {"ecosystem": "npm", "name": "lodash"}]
    got = {(m.component, m.version, m.vuln_id): m.confidence for m in osv.correlate(comps, VULNS)}
    assert got[("npm:lodash", "4.17.20", "GHSA-aaaa")] == "medium"
    assert got[("PyPI:requests", "2.30.0", "PYSEC-2023-74")] == "high"
    assert got[("PyPI:requests", "2.28.1", "PYSEC-2023-74")] == "medium"
    assert ("npm:lodash", "4.17.21", "GHSA-aaaa") not in got  # fixed version
    assert got[("npm:weird", "1.0.0", "GHSA-odd")] == "low"
    assert got[("npm:lodash", "", "GHSA-aaaa")] == "low"
    assert not [k for k in got if k[2] == "OSV-WITHDRAWN"]
    assert all(c in ("high", "medium", "low") for c in got.values())


def test_cves_from_aliases_and_purl_parsing():
    m = osv.correlate(["pkg:npm/lodash@4.17.20"], VULNS)[0]
    assert m.cves == ["CVE-2021-23337"]
    c = osv.parse_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar")
    assert (c.ecosystem, c.name, c.version) == ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")
    assert osv.parse_purl("pkg:npm/%40scope/pkg@1.0.0").name == "@scope/pkg"
    assert osv.parse_purl("not-a-purl") is None


def test_load_formats_and_cyclonedx_components():
    assert len(osv.load_vulns(json.dumps({"vulns": VULNS}))) == 4
    assert len(osv.load_vulns({"results": [{"vulns": VULNS[:1]}, {}]})) == 1
    raw = (Path(__file__).parent / "fixtures" / "cyclonedx.json").read_bytes()
    comps = osv.components_from_cyclonedx(raw)
    assert comps and all(c.ecosystem and c.name for c in comps)
