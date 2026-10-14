"""Phase 8.4: v2.1 framework packs load from YAML and pass library integrity."""

from __future__ import annotations

import pytest

PACKS = ("cert_in_2022", "rbi_csf_2016", "sebi_cscrf_2024", "dora_2022", "nist_csf_2")


@pytest.fixture()
def lib():
    from attestra.compliance.engine import clear_library_cache, load_library

    clear_library_cache()
    return load_library()


def test_all_v21_packs_loaded(lib):
    for fw in PACKS:
        assert fw in lib.frameworks, fw
        assert lib.frameworks[fw]["name"]
        assert lib.frameworks[fw].get("pack")


def test_core_frameworks_still_present(lib):
    for fw in ("pci_dss_4", "iso_27001_2022", "soc2"):
        assert fw in lib.frameworks


@pytest.mark.parametrize("fw", PACKS)
def test_pack_refs_have_titles_and_known_objectives(lib, fw):
    import yaml

    from attestra.compliance.engine import DATA

    raw = yaml.safe_load((DATA / "packs" / f"{fw}.yaml").read_text(encoding="utf-8"))
    for obj, refs in raw["controls"].items():
        assert obj in lib.objectives, f"{fw}: unknown objective {obj}"
        for ref in refs:
            assert ref in lib.titles[fw], f"{fw}: {ref} has no title"
            assert ref in lib.objectives[obj]["controls"][fw]


def test_sqli_maps_into_india_packs(lib):
    from attestra.compliance.engine import mapping_for_cwe

    m = mapping_for_cwe(89, lib)
    assert m is not None
    refs_rbi = {r for o in m.objectives for r in lib.objectives[o]["controls"].get("rbi_csf_2016", [])}
    assert "A1.6" in refs_rbi
    refs_cert = {r for o in m.objectives for r in lib.objectives[o]["controls"].get("cert_in_2022", [])}
    assert "Annex I" in refs_cert


def test_duplicate_framework_pack_rejected(tmp_path):
    from attestra.compliance.engine import _merge_pack

    frameworks = {"soc2": {"name": "x"}}
    with pytest.raises(ValueError):
        _merge_pack({"framework": "soc2", "name": "dup", "controls": {}, "titles": {}}, frameworks, {}, {})


def test_pack_with_unknown_objective_rejected():
    from attestra.compliance.engine import _merge_pack

    with pytest.raises(ValueError):
        _merge_pack({"framework": "zz", "name": "z", "controls": {"nope": ["1"]}, "titles": {"1": "t"}}, {}, {}, {})


@pytest.mark.parametrize("fw", PACKS)
def test_compliance_rollup_for_pack(loaded, fw):
    from attestra import db, services
    from attestra.compliance.engine import clear_library_cache

    clear_library_cache()
    with db.session() as s:
        results = services.compliance(s, loaded, fw)
    assert results
    assert all(r.framework == fw and r.title for r in results)
    refs = [r.ref for r in results]
    assert len(refs) == len(set(refs))


def test_engagement_accepts_pack_framework(fresh_db):
    from attestra import db, services

    with db.session() as s:
        e = services.create_engagement(
            s, tenant="Pack Co", name="RBI review", type="vapt", frameworks=["rbi_csf_2016", "cert_in_2022"],
            window_start=None, window_end=None, actor="tester",
        )
        assert e.frameworks == ["rbi_csf_2016", "cert_in_2022"]
        with pytest.raises(services.ServiceError):
            services.create_engagement(
                s, tenant="Pack Co", name="bad", type="vapt", frameworks=["not_a_pack"],
                window_start=None, window_end=None, actor="tester",
            )


def test_compliance_report_renders_pack(loaded):
    from attestra import db
    from attestra.reports import generate_report

    with db.session() as s:
        r = generate_report(s, loaded, kind="compliance", actor="tester", framework="rbi_csf_2016")
    assert r is not None
