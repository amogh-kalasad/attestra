"""Run-validity and coverage disclosure for every report format (J-01) and QA (J-02).

Reads ``AutomatedTestExecution.result_json["run_validity"]`` (PHASE2 §3.2 contract,
written by WP1's ``core/run_validity.py``) and turns it into one report-ready dict used
by the HTML/PDF/DOCX templates (``_run_validity.html.j2``), the Markdown and XLSX
exports, and the QA gate. Runs without the key (legacy) are shown as *not computed*.

The point: a report must distinguish "zero findings" from "testing was incomplete".
"""
# @lat: [[intel-and-reporting#Run validity in reports]]

from __future__ import annotations

import json
from typing import Any

SECTION_VERSION = "rvs1"
VALID = "VALID"
NOT_COMPUTED = "NOT_COMPUTED"
# Worst first (PHASE2 §3.2 precedence).
PRECEDENCE: tuple[str, ...] = (
    "NETWORK_FAILED",
    "AUTH_EXPIRED",
    "CHALLENGE_DETECTED",
    "RATE_LIMITED",
    "PARTIALLY_BLOCKED",
    "INCONCLUSIVE",
    VALID,
)
STATE_LABELS: dict[str, str] = {
    "VALID": "Valid",
    "PARTIALLY_BLOCKED": "Partially blocked",
    "CHALLENGE_DETECTED": "Challenge detected",
    "RATE_LIMITED": "Rate limited",
    "AUTH_EXPIRED": "Authentication expired",
    "NETWORK_FAILED": "Network failed",
    "INCONCLUSIVE": "Inconclusive",
    "NOT_COMPUTED": "Not computed",
}
STATE_MEANING: dict[str, str] = {
    "VALID": "The target answered normally; results are representative.",
    "PARTIALLY_BLOCKED": "A web application firewall or CDN blocked part of the test traffic.",
    "CHALLENGE_DETECTED": "A bot or browser challenge page was served instead of the application.",
    "RATE_LIMITED": "The target rate-limited the test traffic (HTTP 429).",
    "AUTH_EXPIRED": "The authenticated session expired during testing.",
    "NETWORK_FAILED": "Most requests failed at the network level.",
    "INCONCLUSIVE": "Too few usable responses to decide.",
    "NOT_COMPUTED": "This run predates run-validity tracking; validity was not computed.",
}
INCOMPLETE_CASE_STATUSES = frozenset({"BLOCKED", "INCONCLUSIVE", "NOT_TESTED", "SKIPPED", "DEFERRED", "FAILED"})
# Marker text that QA looks for (J-02).
INCOMPLETE_NOTICE = (
    "Testing was incomplete: zero findings in an incomplete run does not mean the target "
    "is free of vulnerabilities."
)


def _state_of(rv: Any) -> str:
    if isinstance(rv, dict):
        rv = rv.get("state")
    st = str(rv or "").strip().upper()
    if not st:
        return NOT_COMPUTED
    return st if st in STATE_LABELS else "INCONCLUSIVE"


def worst_state(states: list[str]) -> str:
    computed = [s for s in states if s != NOT_COMPUTED]
    if not computed:
        return NOT_COMPUTED
    rank = {s: i for i, s in enumerate(PRECEDENCE)}
    return min(computed, key=lambda s: rank.get(s, len(PRECEDENCE)))


def _payload(raw: Any) -> dict:
    if isinstance(raw, dict):
        return raw
    try:
        doc = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def build_section(executions: list[tuple[int, Any]], *, reportable_count: int | None = None) -> dict:
    """Pure builder. ``executions`` = ``[(execution_id, result_json str|dict), ...]`` newest first.

    Returns a dict with ``has_runs``, ``computed``, ``overall_state`` (+ label/meaning),
    ``incomplete`` (overall is computed and not VALID), ``runs`` and ``incomplete_cases``.
    """
    runs: list[dict] = []
    incomplete_cases: list[dict] = []
    checklist_versions: set[str] = set()
    for ex_id, raw in executions:
        p = _payload(raw)
        rv = p.get("run_validity") if isinstance(p.get("run_validity"), dict) else {}
        state = _state_of(rv or p.get("run_validity"))
        cv = str(p.get("checklist_version") or "").strip()
        if cv:
            checklist_versions.add(cv)
        runs.append(
            {
                "execution_id": ex_id,
                "state": state,
                "label": STATE_LABELS.get(state, state),
                "meaning": STATE_MEANING.get(state, ""),
                "reasons": [str(r)[:200] for r in (rv.get("reasons") or [])][:10],
                "sample_count": rv.get("sample_count"),
                "by_class": rv.get("by_class") or {},
                "affected_cases": [str(c) for c in (rv.get("affected_cases") or [])][:40],
                "computed_at": str(rv.get("computed_at") or ""),
                "version": str(rv.get("version") or ""),
                "checklist_version": cv,
            }
        )
        for c in p.get("cases") or []:
            if not isinstance(c, dict):
                continue
            status = str(c.get("status") or "").upper()
            cval = c.get("validity")
            cstate = _state_of(cval) if cval else ""
            if status in INCOMPLETE_CASE_STATUSES or (cstate and cstate not in (VALID, NOT_COMPUTED)):
                incomplete_cases.append(
                    {
                        "execution_id": ex_id,
                        "test_id": str(c.get("test_id") or ""),
                        "status": status,
                        "validity": cstate,
                        "reason": str(c.get("skip_reason") or c.get("reason") or "")[:200],
                    }
                )
    overall = worst_state([r["state"] for r in runs])
    computed = overall != NOT_COMPUTED
    incomplete = computed and overall != VALID
    zero = reportable_count == 0 if reportable_count is not None else None
    return {
        "version": SECTION_VERSION,
        "has_runs": bool(runs),
        "computed": computed,
        "overall_state": overall,
        "overall_label": STATE_LABELS.get(overall, overall),
        "overall_meaning": STATE_MEANING.get(overall, ""),
        "incomplete": incomplete,
        "zero_findings": zero,
        "notice": INCOMPLETE_NOTICE if incomplete else "",
        "runs": runs[:10],
        "incomplete_cases": incomplete_cases[:80],
        "checklist_versions": sorted(checklist_versions),
    }


def load_executions(s, engagement_id: int, *, limit: int = 10) -> list[tuple[int, Any]]:
    """Newest automated executions for an engagement as ``(id, result_json)``; [] on any error."""
    try:
        from sqlalchemy import select

        from attestra.models import AutomatedTestExecution

        rows = list(
            s.scalars(
                select(AutomatedTestExecution)
                .where(AutomatedTestExecution.engagement_id == engagement_id)
                .order_by(AutomatedTestExecution.id.desc())
                .limit(limit)
            )
        )
    except Exception:  # noqa: BLE001 — optional subsystem must never break reports/QA
        return []
    out: list[tuple[int, Any]] = []
    for ex in rows:
        status = str(getattr(ex, "status", "") or "").upper()
        if status in ("QUEUED", "RUNNING"):
            continue
        raw = getattr(ex, "result_json", None) or "{}"
        mirror = str(getattr(ex, "run_validity", "") or "").strip()
        if mirror:
            doc = _payload(raw)
            if not isinstance(doc.get("run_validity"), dict):
                doc["run_validity"] = {"state": mirror}
                raw = doc
        out.append((int(getattr(ex, "id", 0) or 0), raw))
    return out


def section_for_engagement(s, engagement_id: int, *, reportable_count: int | None = None) -> dict:
    return build_section(load_executions(s, engagement_id), reportable_count=reportable_count)


def markdown_lines(section: dict) -> list[str]:
    """Markdown block for the engagement export (empty when there are no automated runs)."""
    if not section or not section.get("has_runs"):
        return []
    lines = ["## Run validity and coverage", ""]
    lines.append(f"- Overall run validity: **{section['overall_label']}** — {section['overall_meaning']}")
    if section.get("notice"):
        lines.append(f"- {section['notice']}")
    for r in section.get("runs") or []:
        bits = [f"run #{r['execution_id']}: {r['label']}"]
        if r.get("sample_count") is not None:
            bits.append(f"samples={r['sample_count']}")
        if r.get("reasons"):
            bits.append("reasons: " + "; ".join(r["reasons"][:3]))
        if r.get("affected_cases"):
            bits.append("affected cases: " + ", ".join(r["affected_cases"][:10]))
        lines.append("- " + " · ".join(bits))
    cases = section.get("incomplete_cases") or []
    if cases:
        lines.append("")
        lines.append(f"Incomplete test cases ({len(cases)}):")
        for c in cases[:40]:
            extra = f" ({c['reason']})" if c.get("reason") else ""
            lines.append(f"- run #{c['execution_id']} {c['test_id']}: {c['status'] or c['validity']}{extra}")
    lines.append("")
    return lines


XLSX_COLUMNS = ("execution id", "run validity", "meaning", "sample count", "reasons", "affected cases",
                "computed at", "version")


def xlsx_rows(section: dict) -> list[list[Any]]:
    rows: list[list[Any]] = []
    for r in (section or {}).get("runs") or []:
        rows.append([
            r["execution_id"], r["label"], r["meaning"],
            "" if r.get("sample_count") is None else r["sample_count"],
            "; ".join(r.get("reasons") or []), ", ".join(r.get("affected_cases") or []),
            r.get("computed_at") or "", r.get("version") or "",
        ])
    return rows
