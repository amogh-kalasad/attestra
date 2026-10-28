"""Per-target scan history, A–F grades, and new/fixed/still-open diffs (C11)."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra import importers
from attestra.fingerprint import fingerprint, group_kwargs
from attestra.models import SEVERITIES, Asset, ImportRun, ScanRun

# Statuses that contribute a history row (finished runs with usable results).
# Cancelled and failed scans are excluded from grade and trend.
_HISTORY_STATUSES = frozenset({"done", "quarantined"})


def observatory_score_for_scan(s: Session, run: ScanRun, asset: Asset) -> int | None:
    """Observatory-style numeric score from one finished scan's saved raw results.

    Returns None when raw results are missing or cannot be parsed. Cancelled and
    failed runs should not be passed in (callers filter with ``_HISTORY_STATUSES``).
    """
    # @lat: [[interfaces#Web dashboard#Sites dashboard]]
    from attestra.grade import score_from_findings

    if run.status not in _HISTORY_STATUSES:
        return None
    raw, tool = _raw_for_scan(s, run)
    if not raw or not tool:
        return None
    try:
        parsed = importers.parse(tool, raw)
    except (ValueError, KeyError, Exception):  # noqa: BLE001 - bad/missing parser → no score
        return None
    findings = [
        {
            "title": nf.title,
            "variant": getattr(nf, "variant", "") or "",
            "param": getattr(nf, "param", "") or "",
            "tools": [nf.tool],
            "status": "new",
        }
        for nf in parsed
    ]
    return int(score_from_findings(findings)["score"])


def scan_letter_grade(by_sev: Counter | dict[str, int]) -> str:
    """A–F letter grade from finding counts by severity for one scan.

    A — no medium/high/critical (clean, or only low/info)
    B — medium present, no high/critical
    C — high present, no critical
    D — exactly one critical
    F — two or more critical
    """
    crit = int(by_sev.get("critical", 0) or 0)
    high = int(by_sev.get("high", 0) or 0)
    medium = int(by_sev.get("medium", 0) or 0)
    if crit >= 2:
        return "F"
    if crit == 1:
        return "D"
    if high:
        return "C"
    if medium:
        return "B"
    return "A"


def diff_fingerprints(previous: set[str], current: set[str]) -> dict[str, int]:
    """Compare two scan fingerprint sets: new, fixed, still-open."""
    return {
        "new": len(current - previous),
        "fixed": len(previous - current),
        "still_open": len(previous & current),
    }


def trend_svg(current: Counter, previous: Counter | None) -> str:
    """Inline SVG bar chart comparing finding counts by severity (reuse of report chart)."""
    sevs = list(SEVERITIES)
    colors = {
        "critical": "#b91c1c",
        "high": "#c2410c",
        "medium": "#a16207",
        "low": "#15803d",
        "info": "#475569",
    }
    width, height, gap = 320, 120, 8
    bar_w = (width - gap * (len(sevs) + 1)) // (len(sevs) * (2 if previous is not None else 1))
    max_v = max(
        [current.get(s, 0) for s in sevs]
        + ([previous.get(s, 0) for s in sevs] if previous else [1])
        + [1]
    )
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height + 24}" '
        f'role="img" aria-label="Findings by severity trend">'
    ]
    for i, sev in enumerate(sevs):
        x0 = gap + i * ((bar_w * (2 if previous is not None else 1)) + gap)
        h1 = int((current.get(sev, 0) / max_v) * height)
        parts.append(
            f'<rect x="{x0}" y="{height - h1}" width="{bar_w}" height="{h1}" fill="{colors[sev]}" />'
        )
        if previous is not None:
            h0 = int((previous.get(sev, 0) / max_v) * height)
            parts.append(
                f'<rect x="{x0 + bar_w}" y="{height - h0}" width="{bar_w}" height="{h0}" '
                f'fill="{colors[sev]}" opacity="0.35" />'
            )
        parts.append(f'<text x="{x0}" y="{height + 14}" font-size="9" fill="#334155">{sev[:4]}</text>')
    parts.append("</svg>")
    return "".join(parts)


def _read_bytes(path_str: str) -> bytes | None:
    if not path_str:
        return None
    try:
        p = Path(path_str)
        if p.is_file():
            return p.read_bytes()
    except OSError:
        return None
    return None


def _raw_for_scan(s: Session, run: ScanRun) -> tuple[bytes | None, str]:
    """Return (raw bytes, tool key) for a scan's result file."""
    tool = (run.tool or "").lower()
    if run.import_run_id:
        imp = s.get(ImportRun, run.import_run_id)
        if imp:
            raw = _read_bytes(imp.raw_path or "")
            if raw is not None:
                return raw, (imp.tool or tool).lower()
    raw = _read_bytes(run.raw_artifact_uri or "")
    return raw, tool


def _fingerprints_and_sev(
    raw: bytes | None, tool: str, *, asset_id: int, location_fallback: str = ""
) -> tuple[set[str], Counter]:
    if not raw or not tool:
        return set(), Counter()
    try:
        parsed = importers.parse(tool, raw)
    except (ValueError, KeyError, Exception):  # noqa: BLE001 - bad/missing parser → empty snapshot
        return set(), Counter()
    fps: set[str] = set()
    by_sev: Counter = Counter()
    for nf in parsed:
        loc = nf.location or location_fallback
        param = nf.param
        variant = getattr(nf, "variant", "") or ""
        # Same grouping as import (ZAP: one finding per rule per origin).
        grp = group_kwargs(tool=nf.tool, location=loc, param=param, variant=variant, rule_key=nf.rule_id or "")
        if grp is not None:
            loc, param, variant = grp
        try:
            fp = fingerprint(
                location=loc,
                cwe=nf.cwe,
                cves=nf.cves,
                title=nf.title,
                param=param,
                package=nf.package,
                asset_id=asset_id,
                variant=variant,
            )
        except (ValueError, TypeError):
            # Masked/redacted locations in stored evidence can break URL parsing.
            fp = fingerprint(
                location=location_fallback or "unknown",
                cwe=nf.cwe,
                cves=nf.cves,
                title=nf.title,
                param=param,
                package=nf.package,
                asset_id=asset_id,
                variant=variant,
            )
        if grp is not None and fp in fps:
            continue  # another URL of an already-counted grouped finding
        fps.add(fp)
        by_sev[nf.severity] += 1
    return fps, by_sev


def asset_scan_history(s: Session, asset_id: int) -> list[dict[str, Any]]:
    """Past scans for one target with grade, severity counts, and diffs vs previous scan.

    Rows are oldest-first so diffs compare each scan to the one before it.
    Only ``done`` / ``quarantined`` runs are included. When raw results are missing,
    counts stay zero and grade is ``—``.
    """
    asset = s.get(Asset, asset_id)
    if not asset:
        raise LookupError(f"target {asset_id} not found")

    runs = list(
        s.scalars(
            select(ScanRun)
            .where(ScanRun.asset_id == asset_id, ScanRun.status.in_(tuple(_HISTORY_STATUSES)))
            .order_by(ScanRun.id.asc())
        )
    )
    rows: list[dict[str, Any]] = []
    # Last fingerprint set per tool so ZAP→ZAP diffs stay meaningful across other tools.
    prev_by_tool: dict[str, set[str]] = {}
    for run in runs:
        raw, tool = _raw_for_scan(s, run)
        fps, by_sev = _fingerprints_and_sev(
            raw, tool, asset_id=asset_id, location_fallback=asset.identifier
        )
        has_data = raw is not None and bool(tool)
        grade = scan_letter_grade(by_sev) if has_data else "—"
        prev_fps = prev_by_tool.get(tool) if has_data else None
        diff = (
            diff_fingerprints(prev_fps, fps)
            if prev_fps is not None
            else {"new": None, "fixed": None, "still_open": None}
        )
        rows.append(
            {
                "scan_id": run.id,
                "tool": run.tool,
                "status": run.status,
                "profile": run.profile,
                "started_at": run.started_at,
                "ended_at": run.ended_at or run.started_at,
                "grade": grade,
                "by_sev": {sev: int(by_sev.get(sev, 0)) for sev in SEVERITIES},
                "total": sum(by_sev.values()),
                "new": diff["new"],
                "fixed": diff["fixed"],
                "still_open": diff["still_open"],
                "has_data": has_data,
            }
        )
        if has_data and tool:
            prev_by_tool[tool] = fps

    # Attach trend SVG comparing latest vs previous snapshot (newest last in rows).
    if rows and rows[-1]["has_data"]:
        current = Counter(rows[-1]["by_sev"])
        previous_row = next((r for r in reversed(rows[:-1]) if r["has_data"]), None)
        prev_counter = Counter(previous_row["by_sev"]) if previous_row else None
        trend = trend_svg(current, prev_counter)
    else:
        trend = ""

    for row in rows:
        row["trend_svg"] = trend
    return rows
