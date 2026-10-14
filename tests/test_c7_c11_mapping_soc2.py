"""C7 mapping strength/rationale in compliance output; C11 SOC 2 Type II sampling."""
from __future__ import annotations

import json
from datetime import date

import pytest


def test_mappings_for_objective_uses_cwe_map():
    from attestra.compliance.engine import load_library, mappings_for_objective
    from attestra.models import Finding

    lib = load_library()
    cwe, m = next(iter(sorted(lib.cwe_map.items())))
    f = Finding(id=1, cwe=cwe, severity="high", status="new", title="x")
    out = mappings_for_objective([f], m.objectives[0], lib)
    assert out == [{"cwe": cwe, "objective": m.objectives[0], "strength": m.strength, "rationale": m.rationale}]
    assert mappings_for_objective([f], "no_such_objective", lib) == []


def test_partial_mapping_wins():
    from attestra.compliance.engine import ControlResult, _apply_mappings

    r = ControlResult(framework="x", ref="1", title="", objectives=[], proposed="partial", reason="")
    _apply_mappings(r, [{"cwe": 1, "objective": "a", "strength": "full", "rationale": "A"},
                        {"cwe": 2, "objective": "a", "strength": "partial", "rationale": "B"}])
    assert r.mapping_strength == "partial"
    assert "CWE-1 (full): A" in r.mapping_rationale and "CWE-2 (partial): B" in r.mapping_rationale


def test_compliance_results_carry_mapping(loaded):
    from attestra import db, services

    with db.session() as s:
        results = services.compliance(s, loaded, "pci_dss_4")
    mapped = [r for r in results if r.mappings]
    assert mapped, "expected CWE-mapped controls"
    for r in mapped:
        assert r.mapping_strength in ("full", "partial")
        assert r.mapping_rationale


def test_compliance_api_and_report_show_mapping(client, loaded):
    from attestra import db
    from attestra.reports import generate_report

    r = client.get(f"/api/engagements/{loaded}/compliance", params={"framework": "pci_dss_4"})
    assert r.status_code == 200
    rows = r.json()
    assert all("mapping_strength" in x and "mapping_rationale" in x for x in rows)
    assert any(x["mapping_strength"] for x in rows)
    with db.session() as s:
        rep = generate_report(s, loaded, kind="compliance", framework="pci_dss_4", actor="t")
        path = rep.path
    html = open(path, encoding="utf-8").read()
    assert "Mapping" in html and "CWE-" in html


def test_sample_size_table():
    from attestra.reports.soc2_sampling import sample_size_for

    sizes = [sample_size_for(n) for n in (0, 1, 2, 3, 12, 13, 52, 53, 250, 251, 5000)]
    assert sizes == [0, 1, 2, 2, 2, 5, 5, 25, 25, 40, 40]


def test_sampling_reproducible(loaded):
    from attestra import db
    from attestra.reports.soc2_sampling import build_sample, to_csv

    with db.session() as s:
        a = build_sample(s, loaded, "findings", seed=7)
        b = build_sample(s, loaded, "findings", seed=7)
        c = build_sample(s, loaded, "findings")
        d = build_sample(s, loaded, "findings")
        o = build_sample(s, loaded, "findings", seed=7, size=1)
    assert a["sample_ids"] == b["sample_ids"]
    assert c["seed"] == d["seed"] and c["sample_ids"] == d["sample_ids"]
    assert a["population_size"] > 0
    assert a["sample_size"] == a["documented_sample_size"] == len(a["sample_ids"])
    assert o["sample_size"] == 1 and o["size_overridden"]
    assert set(a["sample_ids"]) <= {r["id"] for r in a["population_rows"]}
    text = to_csv(a)
    assert "# seed: 7" in text and "sampled" in text


def test_sampling_period_and_errors(loaded):
    from attestra import db, services
    from attestra.reports.soc2_sampling import build_sample

    with db.session() as s:
        empty = build_sample(s, loaded, "findings", period_start=date(1990, 1, 1), period_end=date(1990, 12, 31))
        assert empty["population_size"] == 0 and empty["sample_ids"] == []
        rem = build_sample(s, loaded, "remediations")
        assert all(r["status"] not in ("new", "triaged", "validated") for r in rem["population_rows"])
        with pytest.raises(services.ServiceError):
            build_sample(s, loaded, "bogus")
        with pytest.raises(services.ServiceError):
            build_sample(s, loaded, "findings", period_start=date(2025, 2, 1), period_end=date(2025, 1, 1))


def test_sampling_api(client, loaded):
    url = f"/api/engagements/{loaded}/soc2/sample"
    r = client.get(url, params={"seed": 3})
    assert r.status_code == 200
    body = r.json()
    assert body["seed"] == 3 and body["population"] == "findings"
    assert client.get(url, params={"seed": 3}).json()["sample_ids"] == body["sample_ids"]
    r = client.get(url, params={"seed": 3, "format": "csv"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert "# seed: 3" in r.text
    assert client.get(url, params={"population": "bogus"}).status_code in (400, 409, 422)
    from fastapi.testclient import TestClient

    from attestra.api import app

    assert TestClient(app).get(url).status_code in (401, 403)


def test_sampling_cli(loaded, tmp_path, capsys):
    from attestra.cli import main

    out = tmp_path / "s.json"
    main(["soc2-sample", str(loaded), "--seed", "5", "--format", "json", "-o", str(out)])
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["seed"] == 5
    main(["soc2-sample", str(loaded), "--seed", "5"])
    assert "# seed: 5" in capsys.readouterr().out