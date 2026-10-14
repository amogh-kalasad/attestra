"""Library integrity: every CWE mapping has strength + rationale; refs resolve."""
# @lat: [[tests#Phase 3 compliance tests#tests/test_library_integrity.py]]

from __future__ import annotations


def test_every_cwe_mapping_has_strength_and_rationale():
    from attestra.compliance.engine import clear_library_cache, load_library

    clear_library_cache()
    lib = load_library()
    assert lib.cwe_map, "expected CWE mappings"
    for cwe, mapping in lib.cwe_map.items():
        assert mapping.strength in {"full", "partial"}, f"CWE-{cwe} bad strength {mapping.strength!r}"
        assert mapping.rationale.strip(), f"CWE-{cwe} missing rationale"
        for obj in mapping.objectives:
            assert obj in lib.objectives, f"CWE-{cwe} unknown objective {obj!r}"


def test_every_control_ref_has_title():
    from attestra.compliance.engine import clear_library_cache, load_library

    clear_library_cache()
    lib = load_library()
    for key, obj in lib.objectives.items():
        for fw, refs in (obj.get("controls") or {}).items():
            titles = lib.titles.get(fw) or {}
            for ref in refs:
                assert ref in titles, f"objective {key}: {fw} {ref} missing from control_titles"


def test_phase3_pci_refs_present():
    from attestra.compliance.engine import clear_library_cache, load_library

    clear_library_cache()
    lib = load_library()
    titles = lib.titles["pci_dss_4"]
    for ref in ("11.3.1.1", "11.3.1.2", "11.3.2", "11.4.2", "11.4.3", "11.4.5", "11.4.6", "6.4.2", "12.3.1"):
        assert ref in titles, f"missing PCI ref {ref}"


def test_phase3_iso_soc_refs_present():
    from attestra.compliance.engine import clear_library_cache, load_library

    clear_library_cache()
    lib = load_library()
    for ref in ("A.8.22", "Clause 6.1.2", "Clause 8.2", "A.5.21"):
        assert ref in lib.titles["iso_27001_2022"]
    for ref in ("CC7.4", "CC6.8", "CC3.2"):
        assert ref in lib.titles["soc2"]
