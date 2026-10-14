"""C4-C6 crosswalk coverage and C8 external control library import (OSCAL, SCF)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture()
def lib():
    from attestra.compliance.engine import clear_library_cache, load_library

    clear_library_cache()
    yield load_library()
    clear_library_cache()


def _refs(lib, fw: str) -> set[str]:
    return {r for o in lib.objectives.values() for r in (o.get("controls") or {}).get(fw, [])}


def test_pci_crosswalk_coverage(lib):
    refs = _refs(lib, "pci_dss_4")
    assert len(refs) >= 19
    for ref in ("1.3.1", "6.3.1", "6.4.2", "8.4.2", "10.4.1", "11.3.2", "11.4.5", "12.3.1"):
        assert ref in refs


def test_iso_crosswalk_coverage(lib):
    refs = _refs(lib, "iso_27001_2022")
    assert len(refs) >= 12
    for ref in ("A.5.15", "A.8.8", "A.8.16", "A.8.22", "A.8.32", "Clause 6.1.2", "Clause 10.2"):
        assert ref in refs


def test_soc2_crosswalk_coverage(lib):
    refs = _refs(lib, "soc2")
    assert len(refs) >= 11
    for ref in ("CC3.2", "CC6.3", "CC6.8", "CC7.3", "CC7.4", "CC9.2"):
        assert ref in refs


def test_every_finding_objective_reaches_all_three_frameworks(lib):
    for key, obj in lib.objectives.items():
        if obj.get("kind") != "finding":
            continue
        ctrls = obj.get("controls") or {}
        for fw in ("pci_dss_4", "iso_27001_2022", "soc2"):
            assert ctrls.get(fw), f"{key} has no {fw} ref"


def test_oscal_import_maps_by_file_and_prop():
    from attestra.compliance.libraries import import_oscal_catalog

    lib = import_oscal_catalog(
        (FIX / "oscal_catalog_sample.json").read_bytes(),
        framework="sample_oscal",
        objective_map=FIX / "oscal_objective_map.yaml",
    )
    assert set(lib.titles) == {"RA-5", "RA-5(2)", "RA-3", "SC-8", "SC-99"}
    assert lib.controls["vuln_identification"] == ["RA-5"]
    assert sorted(lib.controls["internal_scanning"]) == ["RA-5", "RA-5(2)"]
    assert lib.controls["risk_assessment_process"] == ["RA-3"]
    assert lib.controls["crypto_in_transit"] == ["SC-8"]
    assert lib.unmapped == ["SC-99"]
    assert lib.summary()["controls_mapped"] == 4


def test_oscal_rejects_non_catalog_and_bad_objective():
    from attestra.compliance.libraries import import_oscal_catalog

    with pytest.raises(ValueError):
        import_oscal_catalog(b'{"profile": {}}', framework="x_lib")
    with pytest.raises(ValueError):
        import_oscal_catalog(
            (FIX / "oscal_catalog_sample.json").read_bytes(), framework="x_lib", objective_map={"nope": ["ra-5"]}
        )
    with pytest.raises(ValueError):
        import_oscal_catalog((FIX / "oscal_catalog_sample.json").read_bytes(), framework="Bad Key")


def test_scf_import_uses_crosswalk_columns():
    from attestra.compliance.libraries import import_scf_csv

    lib = import_scf_csv((FIX / "scf_sample.csv").read_bytes())
    assert lib.framework == "scf"
    assert "patching" in lib.controls and "VPM-02" in lib.controls["patching"]
    assert "VPM-02" in lib.controls["vuln_identification"]  # via A.8.8 / CC7.1
    assert "CRY-03" in lib.controls["crypto_in_transit"]  # bare ISO "8.24" -> A.8.24
    assert "NET-06" in lib.controls["network_segmentation"]
    assert "IAC-06" in lib.controls["authentication"]  # lower-case cc6.1 normalised
    assert lib.unmapped == ["SAT-02"]


def test_scf_requires_id_and_title_columns():
    from attestra.compliance.libraries import import_scf_csv

    with pytest.raises(ValueError):
        import_scf_csv("foo,bar\n1,2\n")


def test_install_pack_merges_into_library(tmp_path, monkeypatch):
    from attestra.compliance import engine
    from attestra.compliance.libraries import common, import_scf_csv, install_pack

    data = tmp_path / "data"
    (data / "packs").mkdir(parents=True)
    for name in ("controls.yaml", "cwe_map.yaml"):
        (data / name).write_text((engine.DATA / name).read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setattr(engine, "DATA", data)
    monkeypatch.setattr(common, "PACKS_DIR", data / "packs")
    engine.clear_library_cache()
    try:
        lib = import_scf_csv((FIX / "scf_sample.csv").read_bytes())
        path = install_pack(lib)
        assert path.parent == data / "packs"
        loaded = engine.load_library()
        assert "scf" in loaded.frameworks
        assert "VPM-02" in loaded.objectives["patching"]["controls"]["scf"]
        assert loaded.titles["scf"]["VPM-02"] == "Vulnerability Remediation Process"
        with pytest.raises(ValueError):
            install_pack(lib)
    finally:
        engine.clear_library_cache()


def test_cli_library_import_writes_pack(tmp_path, capsys):
    from attestra import cli

    out = tmp_path / "sample.yaml"
    cli.main(
        [
            "library-import",
            "oscal",
            str(FIX / "oscal_catalog_sample.json"),
            "--framework",
            "sample_oscal",
            "--map",
            str(FIX / "oscal_objective_map.yaml"),
            "-o",
            str(out),
        ]
    )
    pack = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert pack["framework"] == "sample_oscal"
    assert pack["controls"]["crypto_in_transit"] == ["SC-8"]
    assert '"controls_mapped": 4' in capsys.readouterr().out
