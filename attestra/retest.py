"""Retest orchestration with false-close guards.

A finding is marked ``fixed`` / ``retest_passed`` only when the linked ScanRun
actually reached the affected asset (or URL). Otherwise the result is
``inconclusive``.

H-01 explicit outcomes: ``finalize_retest`` accepts the legacy results
(``fixed | still_open | inconclusive``) and the explicit outcomes in
:data:`OUTCOMES`. Only ``confirmed_fixed`` on a reached asset in a VALID (or legacy,
not-computed) run can close a finding; ``blocked``, ``challenged``, ``auth_expired``,
``not_reached``, ``environment_changed`` and ``inconclusive`` never close anything.
``Retest.result`` keeps storing the legacy value (compatibility map) so existing
readers, templates, webhooks and the API are unchanged; the explicit outcome lives in
``Retest.outcome_detail_json`` (added by INT; written only when the column exists),
the audit trail and :func:`outcome_of`.
"""
# @lat: [[reports#Retests]]
# @lat: [[intel-and-reporting#Retest outcomes]]

from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra import audit, services
from attestra.fingerprint import normalize_location
from attestra.models import Finding, Retest, ScanRun, utcnow

OUTCOMES: tuple[str, ...] = (
    "confirmed_fixed",
    "still_present",
    "not_reached",
    "blocked",
    "challenged",
    "auth_expired",
    "environment_changed",
    "inconclusive",
)
LEGACY_RESULTS: tuple[str, ...] = ("fixed", "still_open", "inconclusive")
LEGACY_TO_OUTCOME = {"fixed": "confirmed_fixed", "still_open": "still_present", "inconclusive": "inconclusive"}
OUTCOME_TO_LEGACY = {o: "inconclusive" for o in OUTCOMES} | {"confirmed_fixed": "fixed", "still_present": "still_open"}
# Run validity (PHASE2 §3.2) that prevents a clean retest from closing a finding.
RUN_VALIDITY_TO_OUTCOME = {
    "PARTIALLY_BLOCKED": "blocked",
    "RATE_LIMITED": "blocked",
    "CHALLENGE_DETECTED": "challenged",
    "AUTH_EXPIRED": "auth_expired",
    "NETWORK_FAILED": "not_reached",
    "INCONCLUSIVE": "inconclusive",
}
OUTCOME_VERSION = "rt1"


def normalize_outcome(result: str) -> str:
    """Map a legacy or explicit result to an explicit outcome; raise for anything else."""
    r = (result or "").strip().lower()
    if r in OUTCOMES:
        return r
    if r in LEGACY_TO_OUTCOME:
        return LEGACY_TO_OUTCOME[r]
    raise services.ServiceError(
        "result must be one of " + " | ".join(LEGACY_RESULTS + tuple(o for o in OUTCOMES if o != "inconclusive"))
    )


def _run_validity_state(run_validity) -> str:
    if isinstance(run_validity, dict):
        run_validity = run_validity.get("state")
    return str(run_validity or "").strip().upper()


def decide_outcome(requested: str, *, asset_reached: bool, run_validity=None) -> tuple[str, list[str]]:
    """Pure decision: the explicit outcome to record and the reasons for any downgrade.

    * ``confirmed_fixed`` needs the asset reached and a VALID run (an empty / legacy
      run validity is treated as not computed and allowed, as before H-01).
    * ``still_present`` is a positive observation and is kept even on degraded runs.
    """
    outcome = normalize_outcome(requested)
    reasons: list[str] = []
    state = _run_validity_state(run_validity)
    if outcome == "confirmed_fixed":
        if not asset_reached:
            outcome = "not_reached"
            reasons.append("asset not reached by retest scan")
        elif state and state not in ("VALID", "NOT_COMPUTED"):
            outcome = RUN_VALIDITY_TO_OUTCOME.get(state, "inconclusive")
            reasons.append(f"retest run validity {state}: a clean result cannot close the finding")
    return outcome, reasons


def can_close(outcome: str) -> bool:
    return outcome == "confirmed_fixed"


def regression_link(finding, *, previous_run_id: int | None, current_run_id: int | None,
                    retest_id: int | None = None, detected_at=None) -> dict:
    """Regression record for a finding that reappears after being fixed (H-01).

    INT wires this into the ``services`` reopen path so the reopened finding keeps both
    run ids (the run that showed it fixed and the run where it came back).
    """
    return {
        "regression_of_finding_id": getattr(finding, "id", None),
        "previous_status": getattr(finding, "status", None),
        "previous_run_id": previous_run_id,
        "current_run_id": current_run_id,
        "retest_id": retest_id,
        "detected_at": (detected_at or utcnow()).isoformat(),
        "version": OUTCOME_VERSION,
    }


def outcome_of(row) -> str:
    """Explicit outcome of a Retest row; reads ``outcome_detail_json`` when present,
    else maps the legacy ``result`` (``fixed`` -> ``confirmed_fixed``, ...)."""
    detail = getattr(row, "outcome_detail_json", None)
    if detail:
        try:
            doc = json.loads(detail)
            if isinstance(doc, dict) and doc.get("outcome") in OUTCOMES:
                return doc["outcome"]
        except (TypeError, ValueError):
            pass
    res = (getattr(row, "result", "") or "").strip().lower()
    if not res:
        return ""
    if res == "inconclusive" and getattr(row, "finalized_at", None) is not None and not getattr(row, "asset_reached", True):
        return "not_reached"
    if res in OUTCOMES:
        return res
    return LEGACY_TO_OUTCOME.get(res, "inconclusive")


def retest_public_dict(row) -> dict:
    """API-friendly view: explicit ``result`` plus the old value in ``legacy_result``."""
    outcome = outcome_of(row)
    return {
        "id": getattr(row, "id", None),
        "finding_id": getattr(row, "finding_id", None),
        "result": outcome,
        "legacy_result": getattr(row, "result", "") or "",
        "asset_reached": bool(getattr(row, "asset_reached", False)),
        "closes_finding": can_close(outcome),
    }


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
    run_validity=None,
) -> Retest:
    """Finalize a retest with an explicit outcome (legacy results still accepted).

    ``fixed`` / ``confirmed_fixed`` becomes ``not_reached`` (stored as legacy
    ``inconclusive``) if the asset was not reached, or blocked/challenged/auth_expired
    when the retest run validity is not VALID. ``run_validity`` may be a state string or
    the ``result_json.run_validity`` dict; when omitted, the linked run's
    ``run_validity`` attribute is used if present.
    """
    row = s.get(Retest, retest_id)
    if not row:
        raise LookupError(f"retest {retest_id} not found")
    if row.finalized_at is not None:
        raise services.ServiceError("retest already finalized")
    requested = normalize_outcome(result)

    f = s.get(Finding, row.finding_id)
    if not f:
        raise LookupError(f"finding {row.finding_id} not found")

    run = s.get(ScanRun, row.scan_run_id) if row.scan_run_id is not None else None
    reached = force_asset_reached
    if reached is None:
        reached = bool(run and scan_reached_finding(run, f))
    if run_validity is None and run is not None:
        run_validity = getattr(run, "run_validity", None)

    row.asset_reached = bool(reached)
    outcome, reasons = decide_outcome(requested, asset_reached=row.asset_reached, run_validity=run_validity)
    result = OUTCOME_TO_LEGACY[outcome]
    for reason in reasons:
        note = (note + f" [{reason}]").strip()
    if outcome != requested or outcome not in ("confirmed_fixed", "still_present", "inconclusive"):
        note = (note + f" [outcome: {outcome}]").strip()

    row.result = result
    row.finalized_by = actor
    row.note = (row.note + " " + note).strip() if note else row.note
    row.finalized_at = utcnow()
    detail = {
        "version": OUTCOME_VERSION,
        "outcome": outcome,
        "requested": requested,
        "reasons": reasons,
        "run_validity": _run_validity_state(run_validity) or "NOT_COMPUTED",
        "asset_reached": row.asset_reached,
        "scan_run_id": row.scan_run_id,
    }
    if hasattr(type(row), "outcome_detail_json") or hasattr(row, "outcome_detail_json"):
        row.outcome_detail_json = json.dumps(detail, sort_keys=True)

    regression = None
    if can_close(outcome):
        # Prefer retest_passed lifecycle when coming from fixed/validated
        if f.status == "fixed":
            services.transition(s, f.id, to="retest_passed", actor=actor, note=row.note or "retest clean")
        elif f.status == "validated":
            services.transition(s, f.id, to="fixed", actor=actor, note=row.note or "fixed on retest")
            services.transition(s, f.id, to="retest_passed", actor=actor, note=row.note or "retest clean")
    elif outcome == "still_present" and f.status == "fixed":
        regression = regression_link(f, previous_run_id=None, current_run_id=row.scan_run_id, retest_id=row.id)
        f.status = "validated"
        audit.record(s, actor, "finding.reopened", "finding", f.id, reason="retest still_open",
                     outcome=outcome, regression=regression)

    audit.record(
        s, actor, "retest.finalize", "retest", row.id,
        result=result, outcome=outcome, asset_reached=row.asset_reached, finding_id=f.id,
        run_validity=detail["run_validity"], reasons=reasons,
    )
    from attestra.webhooks.service import safe_emit_finding

    safe_emit_finding(s, f, "retest.completed", actor=actor, retest_id=row.id, result=result, outcome=outcome)
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
