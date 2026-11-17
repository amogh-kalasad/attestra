"""G-06 compliance/CWE mapping integrity + J-04 assessor-only guard (no DB)."""
# @lat: [[intel-and-reporting#Compliance mapping provenance]]

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import yaml

from attestra.compliance import engine
from attestra.compliance.owasp import get_wstg

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "attestra" / "compliance" / "data"
_EMIT_RE = re.compile(r"""(?:finding_cwe["']?\s*[:=]\s*|["']cwe["']\s*:\s*|\bcwe\s*=\s*|CWE-)(\d{2,4})\b""")
# CWEs the WP1/WP2 safe probes and planned modules emit (CORS, host header, cache, JWT, upload, SSRF, ...).
PLANNED_PROBE_CWES = {20, 22, 79, 89, 113, 200, 285, 287, 307, 345, 347, 352, 384, 434, 524, 538, 601, 611,
                      613, 614, 639, 644, 693, 770, 862, 863, 915, 918, 942, 1004, 1021, 1336, 1392}


def _emitted_cwes() -> set[int]:
    found: set[int] = set()
    for base in ("attestra/automated_vapt", "attestra/importers", "attestra/checks.py"):
        p = ROOT / base
        files = [p] if p.is_file() else [f for f in p.rglob("*.py") if ".bak_" not in f.name]
        for f in files:
            for m in _EMIT_RE.finditer(f.read_text(encoding="utf-8", errors="replace")):
                found.add(int(m.group(1)))
    return found


def test_ssrf_is_wstg_inpv_19():
    assert get_wstg()["918"] == "WSTG-INPV-19"
    raw = yaml.safe_load((DATA / "owasp.yaml").read_text(encoding="utf-8"))
    assert raw["cwe"][918]["top10"] == "A10"


def test_library_valid_and_has_provenance():
    engine.clear_library_cache()
    lib = engine.load_library()
    assert engine.validate_library(lib) == []
    meta = engine.mapping_metadata(lib)
    assert all(meta[k] for k in engine.MAPPING_METADATA_KEYS)


def test_invalid_reference_fails(monkeypatch):
    lib = engine.load_library()
    broken = engine.Library(
        frameworks=lib.frameworks, objectives=lib.objectives, titles=lib.titles,
        cwe_map={**lib.cwe_map, 99999: engine.CweMapping(("no_such_objective",), "strongish", "")},
        default_objectives=lib.default_objectives, cwe_metadata={},
    )
    errs = engine.validate_library(broken)
    assert any("unknown objective" in e for e in errs)
    assert any("invalid strength" in e for e in errs)
    assert any("metadata missing" in e for e in errs)


def test_every_emitted_cwe_is_mapped():
    lib = engine.load_library()
    owasp = yaml.safe_load((DATA / "owasp.yaml").read_text(encoding="utf-8"))["cwe"]
    emitted = _emitted_cwes() | PLANNED_PROBE_CWES
    missing_map = sorted(c for c in emitted if c not in lib.cwe_map)
    missing_owasp = sorted(c for c in emitted if c not in owasp)
    assert missing_map == [], f"cwe_map.yaml missing {missing_map}"
    assert missing_owasp == [], f"owasp.yaml missing {missing_owasp}"


def test_owasp_refs_well_formed():
    raw = yaml.safe_load((DATA / "owasp.yaml").read_text(encoding="utf-8"))
    top10 = set(raw["top10_2021"])
    for cwe, ref in raw["cwe"].items():
        assert ref["top10"] in top10, cwe
        assert re.fullmatch(r"V\d+\.\d+\.\d+", ref["asvs"]), cwe
        assert re.fullmatch(r"WSTG-[A-Z]{4}-\d{2}", ref["wstg"]), cwe


def _eng():
    return SimpleNamespace(authorizations=[], type="vapt", asv_scans=[], segmentation_tests=[],
                           scan_schedules=[], risk_acceptances=[], control_assessments=[])


def test_assessor_only_controls_never_auto_compliant():
    lib = engine.load_library()
    assessor_objs = [k for k, o in lib.objectives.items() if engine.is_assessor_only(o)]
    assert assessor_objs, "expected assessor-evidence objectives in controls.yaml"
    for fw in lib.frameworks:
        results = engine.evaluate(_eng(), [], [], import_count=3, framework=fw, lib=lib)
        for r in results:
            if r.assessor_only:
                assert r.status not in ("met", "no_exceptions"), (fw, r.ref, r.status)
            assert r.mapping_provenance.get("version")


def test_assessor_only_guard_downgrades_forced_met(monkeypatch):
    lib = engine.load_library()
    key = next(k for k, o in lib.objectives.items() if engine.is_assessor_only(o))
    fw = next(iter(lib.objectives[key]["controls"]))
    monkeypatch.setattr(engine, "_process_status", lambda *a, **k: ("met", "forced"))
    results = engine.evaluate(_eng(), [], [], import_count=0, framework=fw, lib=lib)
    flagged = [r for r in results if key in r.objectives]
    assert flagged and all(r.proposed == "not_assessed" for r in flagged)
    # a named assessor's confirmation still wins
    ref = flagged[0].ref
    conf = SimpleNamespace(framework=fw, control_ref=ref, status="met", assessor="Attestra Team", rationale="evidence")
    confirmed = {r.ref: r for r in engine.evaluate(_eng(), [], [conf], import_count=0, framework=fw, lib=lib)}
    assert confirmed[ref].status == "met"
