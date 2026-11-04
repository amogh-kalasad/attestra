"""Reports track (mongofull): exports / sampling / SEBI timeline / checklist sync run on MongoSession.

The ``loaded`` engagement lives in a throwaway ``attestra_test_*`` database
(``db.session()`` -> MongoSession). Outputs must be present and sensible; no SQL parity.
"""
from __future__ import annotations

from datetime import date, datetime

import pytest

pytestmark = pytest.mark.mongo

VOLATILE = {"exported_at", "generated_at", "export_generated_at"}


def _norm(v):
    """Drop volatile keys; normalise datetimes/dates to ISO strings."""
    if isinstance(v, dict):
        return {k: _norm(x) for k, x in v.items() if k not in VOLATILE}
    if isinstance(v, (list, tuple)):
        return [_norm(x) for x in v]
    if isinstance(v, datetime):
        return v.replace(tzinfo=None).isoformat()
    if isinstance(v, date):
        return v.isoformat()
    return v


def _outputs(s, eid):
    from attestra import services
    from attestra.auth_web.checklist_auto import sync_engagement
    from attestra.compliance.sebi_timeline import derive_milestones
    from attestra.reports import engagement_export, soc2_sampling, xlsx_export

    eng = services.get_engagement(s, eid)
    return {
        "export": _norm(engagement_export.export_engagement_json(s, eid, actor="tester")),
        "xlsx_evidence": _norm(xlsx_export._evidence_rows(s, eid)),
        "xlsx_controls": _norm(xlsx_export._controls_rows(s, eid)),
        "xlsx_bytes": len(xlsx_export.render_engagement_xlsx(s, eid)) > 0,
        "soc2": _norm(soc2_sampling.build_sample(s, eid, "findings", seed=7)),
        "soc2_rem": _norm(soc2_sampling.build_sample(s, eid, "remediations", seed=7)),
        "sebi": _norm(derive_milestones(s, eng)),
        "checklist": _norm(sync_engagement(s, eid, dry_run=True)),
    }


@pytest.fixture
def both(loaded, monkeypatch):
    """``loaded`` engagement + a report and an evidence item, with exports computed under MongoSession."""
    from attestra import db, services
    from attestra.models import Finding
    from attestra.reports import render

    monkeypatch.setattr(render, "_assert_not_before_window", lambda *a, **k: None)
    with db.session() as s:
        render.generate_report(s, loaded, kind="technical", actor="author")
        f = s.get(Finding, services.list_findings(s, loaded)[0].id)
        f.status = "validated"
        services.add_evidence(s, f.id, kind="note", filename="proof.txt", data=b"mongo export proof", note="n1",
                              actor="tester")
    with db.session() as s:
        assert type(s).__name__ == "MongoSession"
        out = _outputs(s, loaded)
    return loaded, out


@pytest.mark.parametrize("key", ["export", "xlsx_evidence", "xlsx_controls", "xlsx_bytes", "soc2", "soc2_rem",
                                 "sebi", "checklist"])
def test_mongo_session_outputs_non_empty(both, key):
    eid, out = both
    assert key in out
    if key == "soc2_rem":
        assert isinstance(out[key], dict)  # remediation population may legitimately be empty
        return
    assert out[key], f"{key} should be non-empty"
    if key == "soc2":
        assert out[key]["population_size"] > 0
    if key == "export":
        assert out[key]["evidence"], "fixture should include evidence"
    if key == "xlsx_evidence":
        assert out[key], "fixture should include evidence"


def test_outputs_are_deterministic_under_mongo(both):
    """Re-running the export-side calls yields identical (seeded) results."""
    from attestra import db

    eid, first = both
    with db.session() as s:
        again = _outputs(s, eid)
    for key in ("export", "xlsx_evidence", "xlsx_controls", "soc2", "soc2_rem", "sebi"):
        assert again[key] == first[key], key


def test_checklist_sync_writes_in_mongo(both):
    """Non-dry-run backfill persists through MongoSession and is idempotent."""
    from attestra import db
    from attestra.auth_web.checklist_auto import sync_engagement
    from attestra.persistence.mongo.adapters import _db

    eid, out = both
    with db.session() as s:
        first = sync_engagement(s, eid, dry_run=False)
    assert first["final"] == out["checklist"]["final"]
    assert list(_db()["auth_checklist_items"].find({"engagement_id": eid})), "checklist items persisted in Mongo"
    with db.session() as s:
        again = sync_engagement(s, eid, dry_run=False)
    assert again["changes"] == []
