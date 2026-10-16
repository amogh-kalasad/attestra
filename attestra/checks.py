"""Passed / failed check lists for scans and imports (C5).

Checks are stored as JSON on ScanRun / ImportRun and as a ``checks.json``
sidecar next to raw scanner output. Old audit rows are never rewritten.
"""
# @lat: [[findings#Passed checks]]

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Status values used in stored check rows and the UI.
PASSED = "passed"
FAILED = "failed"
SKIPPED = "skipped"

# ZAP Baseline passive rules we treat as explicit checks for C5.
# Alert present → failed; catalog rule with no alert → passed.
# Names are short labels for the findings view and report.
ZAP_BASELINE_CHECK_CATALOG: dict[str, str] = {
    "10020": "X-Frame-Options header",
    "10021": "X-Content-Type-Options header",
    "10016": "X-XSS-Protection header",
    "10035": "Strict-Transport-Security (HSTS)",
    "10038": "Content-Security-Policy header",
    "10055": "Content-Security-Policy directives",
    "10054": "Cookie Secure flag",
    "10010": "Cookie HttpOnly flag",
    "10011": "Cookie SameSite attribute",
    "10098": "Cross-domain misconfiguration",
    "10017": "Character set / Content-Type",
    "10015": "Cache-control directives",
    "10063": "Permissions-Policy / Feature-Policy",
    "90004": "Cross-Origin isolation headers (COEP/COOP/CORP)",
    "10109": "Modern Web Application",
    "10049": "Storable and cacheable content",
}


def check_row(
    *,
    check_id: str,
    name: str,
    status: str,
    source: str,
    evidence: str = "",
) -> dict[str, str]:
    """One normalized check row for storage and display."""
    row = {
        "id": check_id,
        "name": name,
        "status": status,
        "source": source,
    }
    if evidence:
        row["evidence"] = evidence
    return row


def write_checks_sidecar(raw_path: Path | str, checks: list[dict[str, str]]) -> Path:
    """Write ``checks.json`` next to a raw report. Returns the sidecar path."""
    path = Path(raw_path)
    side = path.with_name("checks.json") if path.suffix else path / "checks.json"
    if path.is_dir():
        side = path / "checks.json"
    side.write_text(json.dumps({"checks": checks}, indent=2), encoding="utf-8")
    return side


def load_checks_json(data: str | bytes | None) -> list[dict[str, str]]:
    """Parse a stored checks_json column or sidecar body into a list of rows."""
    if not data:
        return []
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")
    try:
        doc = json.loads(data)
    except json.JSONDecodeError:
        return []
    if isinstance(doc, list):
        return [r for r in doc if isinstance(r, dict) and r.get("id")]
    if isinstance(doc, dict):
        rows = doc.get("checks") or []
        return [r for r in rows if isinstance(r, dict) and r.get("id")]
    return []


def checks_from_webcheck_report(doc: dict[str, Any], *, source: str = "webcheck") -> list[dict[str, str]]:
    """Prefer the embedded ``checks`` list; otherwise derive from findings."""
    embedded = doc.get("checks")
    if isinstance(embedded, list) and embedded:
        out = []
        for row in embedded:
            if not isinstance(row, dict) or not row.get("id"):
                continue
            out.append(
                check_row(
                    check_id=str(row["id"]),
                    name=str(row.get("name") or row["id"]),
                    status=str(row.get("status") or FAILED),
                    source=str(row.get("source") or source),
                    evidence=str(row.get("evidence") or ""),
                )
            )
        return out
    failed_ids = {str(f.get("id") or "") for f in (doc.get("findings") or []) if isinstance(f, dict)}
    return [
        check_row(
            check_id=fid,
            name=fid,
            status=FAILED,
            source=source,
        )
        for fid in sorted(failed_ids)
        if fid
    ]


def zap_checks_from_report(raw: bytes | str, *, source: str = "zap") -> list[dict[str, str]]:
    """Build passed/failed rows from a ZAP traditional-json report.

    Catalog rules with at least one alert → failed.
    Catalog rules with no alert → passed (Baseline ran the rule with a clean result).
    Alert plugin ids not in the catalog still appear as failed so nothing is lost.
    """
    if isinstance(raw, str):
        raw_b = raw.encode("utf-8")
    else:
        raw_b = raw
    try:
        doc = json.loads(raw_b.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return []
    alerted: dict[str, str] = {}
    for site in doc.get("site") or []:
        if not isinstance(site, dict):
            continue
        for alert in site.get("alerts") or []:
            if not isinstance(alert, dict):
                continue
            pid = str(alert.get("pluginid") or alert.get("pluginId") or "").strip()
            if not pid:
                continue
            title = str(alert.get("alert") or alert.get("name") or pid)
            alerted.setdefault(pid, title)
    rows: list[dict[str, str]] = []
    for pid, name in sorted(ZAP_BASELINE_CHECK_CATALOG.items()):
        if pid in alerted:
            rows.append(
                check_row(
                    check_id=f"zap/{pid}",
                    name=name,
                    status=FAILED,
                    source=source,
                    evidence=alerted[pid],
                )
            )
        else:
            rows.append(
                check_row(
                    check_id=f"zap/{pid}",
                    name=name,
                    status=PASSED,
                    source=source,
                )
            )
    for pid, title in sorted(alerted.items()):
        if pid in ZAP_BASELINE_CHECK_CATALOG:
            continue
        rows.append(
            check_row(
                check_id=f"zap/{pid}",
                name=title,
                status=FAILED,
                source=source,
                evidence=title,
            )
        )
    return rows


def merge_check_lists(*lists: list[dict[str, str]]) -> list[dict[str, str]]:
    """Merge check rows; failed wins over passed for the same id."""
    by_id: dict[str, dict[str, str]] = {}
    rank = {FAILED: 2, SKIPPED: 1, PASSED: 0}
    for rows in lists:
        for row in rows:
            cid = row.get("id") or ""
            if not cid:
                continue
            prev = by_id.get(cid)
            if prev is None or rank.get(row.get("status", ""), 0) > rank.get(prev.get("status", ""), 0):
                by_id[cid] = row
    return [by_id[k] for k in sorted(by_id)]
