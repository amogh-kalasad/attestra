"""Retest orchestration with false-close guards.

A finding is marked ``fixed`` / ``retest_passed`` only when the linked ScanRun
actually reached the affected asset (or URL). Otherwise the result is
``inconclusive``.
"""
# @lat: [[reports#Retests]]

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra import audit, services
from attestra.fingerprint import normalize_location
from attestra.models import Finding, Retest, ScanRun, utcnow


def request_retest(
    s: Session,
    finding_id: int,
    *,
    scan_run_id: int | None = None,
    actor: str,
    user_id: int | None = None,
    note: str = "",
) -> Retest:
    f = s.get(Finding, finding_id)
    if not f:
        raise LookupError(f"finding {finding_id} not found")
    if f.status not in ("validated", "fixed"):
        raise services.ServiceError(f"cannot request retest from status '{f.status}'")
    if scan_run_id is not None:
        run = s.get(ScanRun, scan_run_id)
        if not run or run.engagement_id != f.engagement_id:
            raise LookupError(f"scan run {scan_run_id} not found on engagement")
    row = Retest(
        finding_id=finding_id,
        scan_run_id=scan_run_id,
        requested_by=actor,
        requested_by_user_id=user_id,
        note=note,
        result="",
    )
    s.add(row)
    s.flush()
    audit.record(s, actor, "retest.request", "retest", row.id, finding_id=finding_id, scan_run_id=scan_run_id)
    return row


def scan_reached_finding(run: ScanRun, finding: Finding) -> bool:
    """True if the scan run targeted the finding's asset (or that asset's URL)."""
    if finding.asset_id is not None:
        return run.asset_id == finding.asset_id
    # Unmatched finding: require the scan asset identifier to appear in the location
    if not finding.location or not run.asset:
        return False
    loc = normalize_location(finding.location)
    ident = normalize_location(run.asset.identifier)
    if not ident:
        return False
    return loc == ident or loc.startswith(ident.rstrip("/") + "/") or ident in loc


def finalize_retest(
    s: Session,
    retest_id: int,
    *,
    result: str,
    actor: str,
    note: str = "",
    force_asset_reached: bool | None = None,
) -> Retest:
    """Finalize a retest. ``fixed`` is forced to ``inconclusive`` if asset was not reached."""
    row = s.get(Retest, retest_id)
    if not row:
        raise LookupError(f"retest {retest_id} not found")
    if row.finalized_at is not None:
        raise services.ServiceError("retest already finalized")
    if result not in ("fixed", "still_open", "inconclusive"):
        raise services.ServiceError("result must be fixed | still_open | inconclusive")

    f = s.get(Finding, row.finding_id)
    if not f:
        raise LookupError(f"finding {row.finding_id} not found")

    reached = force_asset_reached
    if reached is None:
        if row.scan_run_id is None:
            reached = False
        else:
            run = s.get(ScanRun, row.scan_run_id)
            reached = bool(run and scan_reached_finding(run, f))

    row.asset_reached = bool(reached)
    if result == "fixed" and not row.asset_reached:
        result = "inconclusive"
        note = (note + " [asset not reached by retest scan]").strip()

    row.result = result
    row.finalized_by = actor
    row.note = (row.note + " " + note).strip() if note else row.note
    row.finalized_at = utcnow()

    if result == "fixed":
        # Prefer retest_passed lifecycle when coming from fixed/validated
        if f.status == "fixed":
            services.transition(s, f.id, to="retest_passed", actor=actor, note=row.note or "retest clean")
        elif f.status == "validated":
            services.transition(s, f.id, to="fixed", actor=actor, note=row.note or "fixed on retest")
            services.transition(s, f.id, to="retest_passed", actor=actor, note=row.note or "retest clean")
    elif result == "still_open" and f.status == "fixed":
        f.status = "validated"
        audit.record(s, actor, "finding.reopened", "finding", f.id, reason="retest still_open")

    audit.record(
        s, actor, "retest.finalize", "retest", row.id,
        result=result, asset_reached=row.asset_reached, finding_id=f.id,
    )
    return row


def cancel_retest(s: Session, retest_id: int, *, actor: str) -> Retest:
    row = s.get(Retest, retest_id)
    if not row:
        raise LookupError(f"retest {retest_id} not found")
    if row.finalized_at is not None:
        raise services.ServiceError("cannot cancel a finalized retest")
    row.result = "inconclusive"
    row.finalized_by = actor
    row.finalized_at = utcnow()
    row.note = (row.note + " [cancelled]").strip()
    audit.record(s, actor, "retest.cancel", "retest", row.id)
    return row


def open_retests(s: Session, finding_id: int) -> list[Retest]:
    return list(
        s.scalars(
            select(Retest).where(Retest.finding_id == finding_id, Retest.finalized_at.is_(None)).order_by(Retest.id)
        )
    )
