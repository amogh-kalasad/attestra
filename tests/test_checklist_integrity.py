"""FND-05: checklist catalog integrity (single YAML source of truth, WP1 part)."""

from __future__ import annotations

from attestra.auth_web import checklist_catalog as cc


# @lat: [[run-validity-and-policy#Checklist catalog]]
def test_catalog_validates_clean_against_registry():
    problems = cc.validate_catalog()
    assert problems == [], [str(p) for p in problems]


def test_catalog_version_and_size():
    assert cc.catalog_version() == "wstg-4.2+asvs-4.0.3/attestra-1"
    assert len(cc.default_items()) >= 120


def test_ssrf_maps_to_inpv19_with_legacy_alias():
    assert cc.automated_map()["SSRF"] == ("WSTG-INPV-19",)
    cat = cc.load_catalog()
    assert cat.resolve("WSTG-BUSL-09-legacy-ssrf") == "WSTG-INPV-19"
    assert "WSTG-INPV-19" in cc.zap_map()
    assert "40046" in cc.zap_map()["WSTG-INPV-19"]["rules"]


def test_new_wp1_cases_are_mapped():
    m = cc.automated_map()
    assert "WSTG-SESS-03" in m["SESSLIFE"] and "WSTG-SESS-06" in m["SESSLIFE"]
    assert m["OIDCMETA"]
    assert "WSTG-INFO-05" in m["T07"]


def test_unregistered_or_orphan_mappings_are_reported():
    assert cc.audit_unmapped(["NOPE"]) == [{"test_id": "NOPE", "ref": "", "kind": "unmapped"}]
    problems = cc.validate_catalog(registry_ids=["BRANDNEW"])
    assert any(p.kind == "unmapped_test" and p.subject == "BRANDNEW" for p in problems)


def test_current_python_maps_point_at_catalog_refs():
    """Drift guard until INT switches checklist_auto to the catalog: every ref used today exists."""
    from attestra.auth_web import checklist_auto as ca

    refs = set(cc.load_catalog().refs)
    used = {r for rs in ca.AUTOMATED_MAP.values() for r in rs} | set(ca.ZAP_MAP) | set(ca.WEBCHECK_MAP) | {ca.TESTSSL_REF}
    used |= {ref for ref, _p, _e in ca.NUCLEI_MAP}
    missing = sorted(used - refs - {"WSTG-BUSL-09"})
    assert missing == []
