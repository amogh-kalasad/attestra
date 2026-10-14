"""Retest false-close guards."""
# @lat: [[tests#Phase 4 report tests#tests/test_retest_false_close.py]]

from __future__ import annotations

from sqlalchemy import select

from attestra import db, services
from attestra.models import Finding, ScanRun
from attestra.retest import finalize_retest, request_retest


def test_retest_never_fixed_if_asset_not_reached(loaded):
    with db.session() as s:
        f = s.scalars(select(Finding).where(Finding.engagement_id == loaded)).first()
        # Move to validated then fixed so retest can request
        if f.status == "new":
            services.transition(s, f.id, to="triaged", actor="tester")
        if f.status == "triaged":
            services.transition(s, f.id, to="validated", actor="tester")
        if f.status == "validated":
            services.transition(s, f.id, to="fixed", actor="tester", note="patched")
        # Scan run on a different asset (or none matching)
        other_asset = next(a for a in services.get_engagement(s, loaded).assets if a.id != f.asset_id)
        run = ScanRun(
            engagement_id=loaded,
            asset_id=other_asset.id,
            tool="zap",
            profile="baseline",
            status="done",
            requested_by="tester",
        )
        s.add(run)
        s.flush()
        rt = request_retest(s, f.id, scan_run_id=run.id, actor="tester")
        finalized = finalize_retest(s, rt.id, result="fixed", actor="qa")
        assert finalized.result == "inconclusive"
        assert finalized.asset_reached is False
        s.refresh(f)
        assert f.status != "retest_passed"


def test_retest_fixed_when_asset_reached(loaded):
    with db.session() as s:
        f = s.scalars(
            select(Finding).where(Finding.engagement_id == loaded, Finding.asset_id.is_not(None))
        ).first()
        if f.status == "new":
            services.transition(s, f.id, to="triaged", actor="tester")
        if f.status == "triaged":
            services.transition(s, f.id, to="validated", actor="tester")
        if f.status == "validated":
            services.transition(s, f.id, to="fixed", actor="tester", note="patched")
        run = ScanRun(
            engagement_id=loaded,
            asset_id=f.asset_id,
            tool="zap",
            profile="baseline",
            status="done",
            requested_by="tester",
        )
        s.add(run)
        s.flush()
        rt = request_retest(s, f.id, scan_run_id=run.id, actor="tester")
        finalized = finalize_retest(s, rt.id, result="fixed", actor="qa")
        assert finalized.result == "fixed"
        assert finalized.asset_reached is True
