"""SEBI CSCRF periodic security-testing timeline derived from engagement evidence.

Milestones are computed from window, authorizations, scans, signed reports, and
retests. Optional notes/status overrides persist as JSON under
``DATA_DIR/tenants/{tid}/sebi_timeline/{eid}.json`` (no Alembic migration).
"""

from __future__ import annotations

import json
import threading
from datetime import date, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra import config
from attestra.models import Engagement, ImportRun, Report, Retest, ScanRun, utcnow

# Ordered milestones mapped to SEBI CSCRF periodic security-testing expectations
# (ID.RA risk assessment / periodic testing; GV.OV testing authorization).
MILESTONE_DEFS: tuple[tuple[str, str], ...] = (
    ("planning", "Planning"),
    ("authorization_recorded", "Authorization recorded"),
    ("testing_window", "Testing window"),
    ("scans_completed", "Scans completed"),
    ("report_signed", "Report signed"),
    ("retest", "Retest"),
)

STATUS_PENDING = "pending"
STATUS_IN_PROGRESS = "in_progress"
STATUS_DONE = "done"
STATUS_OVERDUE = "overdue"
STATUS_NA = "n/a"

_VALID_STATUSES = frozenset(
    {STATUS_PENDING, STATUS_IN_PROGRESS, STATUS_DONE, STATUS_OVERDUE, STATUS_NA}
)

_lock = threading.Lock()


def timeline_path(tenant_id: int, engagement_id: int) -> Path:
    """JSON path for optional milestone overrides for one engagement."""
    return (
        config.DATA_DIR
        / "tenants"
        / str(int(tenant_id))
        / "sebi_timeline"
        / f"{int(engagement_id)}.json"
    )


def _iso_date(value: date | datetime | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.date().isoformat()
    return value.isoformat()


def load_overrides(tenant_id: int, engagement_id: int) -> dict[str, Any]:
    """Load optional persisted milestone notes/status overrides (empty if missing)."""
    path = timeline_path(tenant_id, engagement_id)
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    return raw if isinstance(raw, dict) else {}


def save_overrides(
    tenant_id: int,
    engagement_id: int,
    *,
    milestones: dict[str, dict[str, Any]] | None = None,
    notes: str = "",
) -> Path:
    """Persist optional milestone overrides. Keys are milestone ids; values may hold status/note/date."""
    path = timeline_path(tenant_id, engagement_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "engagement_id": int(engagement_id),
        "tenant_id": int(tenant_id),
        "notes": (notes or "").strip(),
        "milestones": milestones or {},
        "updated_at": utcnow().replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    with _lock:
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


def _milestone(
    key: str,
    label: str,
    *,
    status: str,
    date_value: date | datetime | None = None,
    detail: str = "",
) -> dict[str, Any]:
    return {
        "id": key,
        "label": label,
        "status": status if status in _VALID_STATUSES else STATUS_PENDING,
        "date": _iso_date(date_value),
        "detail": detail or "",
    }


def derive_milestones(s: Session, eng: Engagement) -> list[dict[str, Any]]:
    """Compute SEBI security-testing milestones from engagement evidence (no secrets)."""
    today = date.today()
    auths = list(eng.authorizations or [])
    auth_date = min((a.signed_on for a in auths), default=None) if auths else None

    scans = list(
        s.scalars(select(ScanRun).where(ScanRun.engagement_id == eng.id).order_by(ScanRun.id))
    )
    imports = list(
        s.scalars(select(ImportRun).where(ImportRun.engagement_id == eng.id).order_by(ImportRun.id))
    )
    done_scans = [r for r in scans if r.status in ("done", "succeeded", "completed")]
    scan_done = bool(done_scans) or bool(imports)
    scan_date: date | datetime | None = None
    if done_scans:
        ended = [r.ended_at or r.started_at for r in done_scans if (r.ended_at or r.started_at)]
        scan_date = min(ended) if ended else None
    elif imports:
        scan_date = min((i.imported_at for i in imports), default=None)

    reports = list(s.scalars(select(Report).where(Report.engagement_id == eng.id)))
    signed = [r for r in reports if r.status == "signed"]
    signed_date = None
    if signed:
        dates = [r.signed_at for r in signed if r.signed_at]
        signed_date = min(dates) if dates else None

    finding_ids = [f.id for f in (eng.findings or [])]
    retests: list[Retest] = []
    if finding_ids:
        retests = list(
            s.scalars(select(Retest).where(Retest.finding_id.in_(finding_ids)).order_by(Retest.id))
        )
    finalized = [r for r in retests if r.finalized_at is not None]
    retest_date = min((r.finalized_at for r in finalized), default=None) if finalized else None

    # planning
    planning = _milestone(
        "planning",
        "Planning",
        status=STATUS_DONE if eng.id else STATUS_PENDING,
        date_value=eng.created_at,
        detail=f"Engagement status: {eng.status}",
    )

    # authorization
    if auths:
        auth = _milestone(
            "authorization_recorded",
            "Authorization recorded",
            status=STATUS_DONE,
            date_value=auth_date,
            detail=f"{len(auths)} authorization(s) on file",
        )
    else:
        auth = _milestone(
            "authorization_recorded",
            "Authorization recorded",
            status=STATUS_PENDING,
            detail="No signed authorization recorded",
        )

    # testing window
    ws, we = eng.window_start, eng.window_end
    if ws is None and we is None:
        window = _milestone(
            "testing_window",
            "Testing window",
            status=STATUS_NA,
            detail="No test window set",
        )
    elif we is not None and today > we:
        window = _milestone(
            "testing_window",
            "Testing window",
            status=STATUS_DONE if scan_done else STATUS_OVERDUE,
            date_value=ws or we,
            detail=f"Window {ws or '—'} to {we}",
        )
    elif ws is not None and today < ws:
        window = _milestone(
            "testing_window",
            "Testing window",
            status=STATUS_PENDING,
            date_value=ws,
            detail=f"Window opens {ws}",
        )
    else:
        window = _milestone(
            "testing_window",
            "Testing window",
            status=STATUS_IN_PROGRESS,
            date_value=ws or today,
            detail=f"Window {ws or '—'} to {we or '—'}",
        )

    # scans
    if scan_done:
        scans_m = _milestone(
            "scans_completed",
            "Scans completed",
            status=STATUS_DONE,
            date_value=scan_date,
            detail=f"{len(done_scans)} scan run(s), {len(imports)} import(s)",
        )
    elif scans:
        scans_m = _milestone(
            "scans_completed",
            "Scans completed",
            status=STATUS_IN_PROGRESS,
            detail=f"{len(scans)} scan run(s) not yet done",
        )
    else:
        scans_m = _milestone(
            "scans_completed",
            "Scans completed",
            status=STATUS_PENDING,
            detail="No scans or imports yet",
        )

    # report signed
    if signed:
        report_m = _milestone(
            "report_signed",
            "Report signed",
            status=STATUS_DONE,
            date_value=signed_date,
            detail=f"{len(signed)} signed report(s)",
        )
    elif reports:
        report_m = _milestone(
            "report_signed",
            "Report signed",
            status=STATUS_IN_PROGRESS,
            detail=f"{len(reports)} report(s); none signed yet",
        )
    else:
        report_m = _milestone(
            "report_signed",
            "Report signed",
            status=STATUS_PENDING,
            detail="No reports generated",
        )

    # retest
    if finalized:
        retest_m = _milestone(
            "retest",
            "Retest",
            status=STATUS_DONE,
            date_value=retest_date,
            detail=f"{len(finalized)} finalized retest(s)",
        )
    elif retests:
        retest_m = _milestone(
            "retest",
            "Retest",
            status=STATUS_IN_PROGRESS,
            detail=f"{len(retests)} retest(s) not finalized",
        )
    else:
        retest_m = _milestone(
            "retest",
            "Retest",
            status=STATUS_PENDING,
            detail="No retests recorded",
        )

    by_id = {
        m["id"]: m
        for m in (planning, auth, window, scans_m, report_m, retest_m)
    }
    return [by_id[k] for k, _ in MILESTONE_DEFS]


def _apply_overrides(milestones: list[dict[str, Any]], overrides: dict[str, Any]) -> list[dict[str, Any]]:
    stored = overrides.get("milestones") or {}
    if not isinstance(stored, dict):
        return milestones
    out: list[dict[str, Any]] = []
    for m in milestones:
        row = dict(m)
        ov = stored.get(m["id"])
        if isinstance(ov, dict):
            if ov.get("status") in _VALID_STATUSES:
                row["status"] = ov["status"]
            if ov.get("date"):
                row["date"] = str(ov["date"])
            if ov.get("note") or ov.get("detail"):
                note = str(ov.get("note") or ov.get("detail") or "").strip()
                if note:
                    row["detail"] = note
        out.append(row)
    return out


def build_timeline(s: Session, eng: Engagement) -> dict[str, Any]:
    """Full SEBI CSCRF security-testing timeline for UI and report context."""
    derived = derive_milestones(s, eng)
    overrides = load_overrides(eng.tenant_id, eng.id)
    milestones = _apply_overrides(derived, overrides)
    return {
        "engagement_id": eng.id,
        "tenant_id": eng.tenant_id,
        "framework": "sebi_cscrf_2024",
        "framework_name": "SEBI CSCRF (2024)",
        "expectation": (
            "Periodic security testing under SEBI CSCRF "
            "(ID.RA risk assessment including periodic security testing; "
            "GV.OV testing authorization)."
        ),
        "window_start": _iso_date(eng.window_start),
        "window_end": _iso_date(eng.window_end),
        "milestones": milestones,
        "notes": str(overrides.get("notes") or ""),
        "statuses": [m["status"] for m in milestones],
    }
