"""AASI Phase 7 report section builders (data dicts for render context).

Produces executive / technical / traceability / AI coverage payloads for the
existing report renderer. Never treats AI confidence as confirmed severity,
and never converts missing evidence into a pass. When AASI is disabled or the
engagement has no AASI runs, sections are empty / absent.
"""
# @lat: [[reports#AASI reporting sections (Phase 7)]]

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from attestra import __version__

# Honest coverage cell statuses — never invent "pass" from silence.
COVERAGE_STATUSES: frozenset[str] = frozenset(
    {
        "not_assessed",
        "assessed_no_issue",
        "potential",
        "confirmed",
        "needs_manual",
        "inconclusive",
        "not_tested",
    }
)

# Worst-wins order when multiple signals land on one matrix cell.
_STATUS_RANK: dict[str, int] = {
    "not_assessed": 0,
    "assessed_no_issue": 1,
    "not_tested": 2,
    "inconclusive": 3,
    "needs_manual": 4,
    "potential": 5,
    "confirmed": 6,
}

_AI_TOOLS: tuple[str, ...] = ("garak", "promptfoo", "safelabs", "pyrit")

_CONFIDENCE_IS_NOT_SEVERITY = (
    "AI confidence and uncertainty labels are planning signals only; "
    "they are never presented as confirmed vulnerability severity."
)


def empty_aasi_payload() -> dict[str, Any]:
    """Absent AASI block for render context when the feature is off or unused."""
    return {
        "present": False,
        "executive": None,
        "technical": None,
        "traceability": None,
        "coverage_matrix": None,
        "limitations": [],
        "qa_issues": [],
    }


def aasi_report_context(
    *,
    enabled: bool | None = None,
    tenant_id: int | None = None,
    engagement_id: int | None = None,
    runs: Sequence[Mapping[str, Any]] | None = None,
    decisions: Sequence[Mapping[str, Any]] | None = None,
    findings: Sequence[Any] | None = None,
    assets: Sequence[Any] | None = None,
    known_evidence_ids: Iterable[str] | None = None,
    framework_version: str | None = None,
) -> dict[str, Any]:
    """Build ``{"aasi": ...}`` for report context.

    When ``enabled`` is false or there are no runs, returns an empty payload
    (``present=False``). Callers may inject ``runs`` / ``decisions`` for tests;
    otherwise Mongo is queried when AASI is on.
    """
    if enabled is None:
        enabled = _aasi_enabled()
    if not enabled:
        return {"aasi": empty_aasi_payload()}

    tid = int(tenant_id or 0)
    eid = int(engagement_id or 0)
    run_rows = list(runs) if runs is not None else _load_runs(tid, eid)
    if not run_rows:
        return {"aasi": empty_aasi_payload()}

    decision_rows = (
        list(decisions) if decisions is not None else _load_decisions(tid, eid, run_rows)
    )
    # Drop cross-tenant rows early (QA also flags them).
    run_rows = [r for r in run_rows if _tenant_ok(r, tid)]
    decision_rows = [d for d in decision_rows if _tenant_ok(d, tid)]
    if not run_rows:
        return {"aasi": empty_aasi_payload()}

    finding_rows = list(findings or [])
    asset_rows = list(assets or [])
    known = {str(x) for x in (known_evidence_ids or []) if str(x).strip()}
    fw_ver = (framework_version or "").strip() or f"Attestra {__version__}"

    executive = build_executive_section(
        runs=run_rows,
        decisions=decision_rows,
        findings=finding_rows,
        assets=asset_rows,
    )
    technical = build_technical_section(
        runs=run_rows,
        decisions=decision_rows,
        findings=finding_rows,
        framework_version=fw_ver,
    )
    traceability = build_traceability_appendix(
        runs=run_rows,
        decisions=decision_rows,
        findings=finding_rows,
    )
    coverage_matrix = build_coverage_matrix(
        findings=finding_rows,
        decisions=decision_rows,
        runs=run_rows,
    )
    limitations = list(executive.get("limitations") or [])
    payload = {
        "present": True,
        "executive": executive,
        "technical": technical,
        "traceability": traceability,
        "coverage_matrix": coverage_matrix,
        "limitations": limitations,
        "qa_issues": [],
        "tenant_id": tid,
        "engagement_id": eid,
        "known_evidence_ids": sorted(known),
        "runs": [_run_summary(r) for r in run_rows],
    }
    payload["qa_issues"] = aasi_qa_issues({"aasi": payload, "findings": finding_rows})
    return {"aasi": payload}


def aasi_context_for_engagement(s: Any, eng: Any, *, findings: Sequence[Any] | None = None) -> dict[str, Any]:
    """Session/engagement helper used by [[attestra/reports/render.py#_context]]."""
    tid = int(getattr(eng, "tenant_id", 0) or 0)
    eid = int(getattr(eng, "id", 0) or 0)
    assets = list(getattr(eng, "assets", None) or [])
    known: set[str] = set()
    for f in findings or []:
        for ev in getattr(f, "evidence", None) or []:
            eid_s = getattr(ev, "id", None)
            if eid_s is not None:
                known.add(str(eid_s))
            sha = getattr(ev, "sha256", None) or getattr(ev, "raw_sha256", None)
            if sha:
                known.add(str(sha))
    return aasi_report_context(
        tenant_id=tid,
        engagement_id=eid,
        findings=findings,
        assets=assets,
        known_evidence_ids=known,
    )


def build_executive_section(
    *,
    runs: Sequence[Mapping[str, Any]],
    decisions: Sequence[Mapping[str, Any]],
    findings: Sequence[Any],
    assets: Sequence[Any],
) -> dict[str, Any]:
    """Executive AI posture: inventory, coverage counts, gaps — not severity from confidence."""
    inventory = _ai_inventory(assets)
    val_counts = _validation_counts(findings)
    unresolved = _unresolved_hypotheses(decisions)
    gaps = _coverage_gaps(decisions, runs)
    limitations = [
        _CONFIDENCE_IS_NOT_SEVERITY,
        "Skipped, refused, rate-limited, or failed AI-tool outcomes are not treated as passed.",
        "AASI recommendations are advise-only; Attestra authorizes and executes registered tests.",
    ]
    if not inventory:
        limitations.append("No ai_app assets were in scope for this engagement.")
    if unresolved:
        limitations.append(
            f"{len(unresolved)} unresolved AASI hypothesis(es) remain without a linked conclusion."
        )

    posture = _posture_sentence(val_counts, inventory, unresolved, gaps)
    return {
        "posture": posture,
        "inventory": inventory,
        "coverage": {
            "runs": len(runs),
            "decisions": len(decisions),
            "ai_assets": len(inventory),
        },
        "confirmed": val_counts.get("confirmed", 0),
        "potential": val_counts.get("potential", 0),
        "needs_manual": val_counts.get("needs_manual_validation", 0),
        "unvalidated": val_counts.get("unvalidated", 0),
        "unresolved_hypotheses": unresolved,
        "gaps": gaps,
        "limitations": limitations,
        "confidence_disclaimer": _CONFIDENCE_IS_NOT_SEVERITY,
    }


def build_technical_section(
    *,
    runs: Sequence[Mapping[str, Any]],
    decisions: Sequence[Mapping[str, Any]],
    findings: Sequence[Any],
    framework_version: str,
) -> dict[str, Any]:
    """Technical rows: test ids, hypothesis, recommendation, outcomes, evidence, uncertainty."""
    by_kind = _decisions_by_kind(decisions)
    hyps = {str(p.get("id") or ""): p for p in (_payloads(by_kind.get("hypothesis", [])))}
    recs = list(_payloads(by_kind.get("recommendation", [])))
    planners = list(_payloads(by_kind.get("planner_outcome", [])))
    conclusions = list(_payloads(by_kind.get("conclusion", [])))
    finding_by_id = {
        str(getattr(f, "id", "")): f for f in findings if getattr(f, "id", None) is not None
    }

    rows: list[dict[str, Any]] = []
    for rec in recs:
        hyp_id = str(rec.get("hypothesis_id") or "")
        hyp = hyps.get(hyp_id) or {}
        planner = _match_planner(planners, rec)
        conclusion = _match_conclusion(conclusions, rec, hyp_id)
        finding = _match_finding(finding_by_id, conclusion, rec)
        evidence_hash = _evidence_hash(conclusion, finding)
        rows.append(
            {
                "test_id": str(rec.get("registered_test_id") or rec.get("test_id") or ""),
                "framework": str(rec.get("authorized_test_type") or "ai_llm"),
                "framework_version": framework_version,
                "hypothesis_id": hyp_id,
                "hypothesis": str(hyp.get("statement") or ""),
                "recommendation_id": str(rec.get("id") or ""),
                "recommendation": str(rec.get("rationale") or ""),
                "planner_outcome": str(
                    (planner or {}).get("outcome")
                    or (planner or {}).get("status")
                    or ""
                ),
                "execution_outcome": str(
                    (conclusion or {}).get("conclusion_type")
                    or (planner or {}).get("execution_outcome")
                    or ""
                ),
                "evidence_hash": evidence_hash,
                "validation": _finding_validation(finding),
                "uncertainty": hyp.get("uncertainty", (conclusion or {}).get("confidence")),
                "remediation": str(
                    (conclusion or {}).get("recommended_action")
                    or getattr(finding, "remediation", None)
                    or ""
                ),
                # Explicit: confidence is not severity.
                "confidence_is_not_severity": True,
            }
        )

    return {
        "framework_version": framework_version,
        "rows": rows,
        "run_ids": [str(r.get("id") or r.get("_id") or "") for r in runs],
    }


def build_traceability_appendix(
    *,
    runs: Sequence[Mapping[str, Any]],
    decisions: Sequence[Mapping[str, Any]],
    findings: Sequence[Any],
) -> dict[str, Any]:
    """Hypothesis → recommendation → planner/execution → conclusion → finding chain."""
    by_kind = _decisions_by_kind(decisions)
    hyps = {str(p.get("id") or ""): (d, p) for d, p in _pairs(by_kind.get("hypothesis", []))}
    rec_pairs = list(_pairs(by_kind.get("recommendation", [])))
    planners = list(_payloads(by_kind.get("planner_outcome", [])))
    conclusions = list(_pairs(by_kind.get("conclusion", [])))
    finding_ids = {str(getattr(f, "id", "")) for f in findings if getattr(f, "id", None) is not None}

    chains: list[dict[str, Any]] = []
    for dec, rec in rec_pairs:
        hyp_id = str(rec.get("hypothesis_id") or "")
        hyp_dec, hyp = hyps.get(hyp_id, (None, {}))
        planner = _match_planner(planners, rec)
        conc_dec, conc = _match_conclusion_pair(conclusions, rec, hyp_id)
        finding_id = _finding_id_from_conclusion(conc)
        if finding_id and finding_id not in finding_ids:
            # Keep the real id even when the finding row is missing — QA flags it.
            pass
        chains.append(
            {
                "run_id": str(
                    dec.get("run_id")
                    or (hyp_dec or {}).get("run_id")
                    or (conc_dec or {}).get("run_id")
                    or ""
                ),
                "hypothesis_id": hyp_id or None,
                "recommendation_id": str(rec.get("id") or "") or None,
                "planner_outcome_id": str((planner or {}).get("id") or "") or None,
                "conclusion_id": str((conc or {}).get("id") or "") or None,
                "finding_id": finding_id,
                "evidence_ids": list(
                    (conc or {}).get("evidence_citations")
                    or (hyp or {}).get("evidence_ids")
                    or []
                ),
                "registered_test_id": str(rec.get("registered_test_id") or rec.get("test_id") or ""),
            }
        )

    return {"chains": chains, "run_count": len(runs)}


def build_coverage_matrix(
    *,
    findings: Sequence[Any],
    decisions: Sequence[Mapping[str, Any]],
    runs: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """OWASP LLM / Agentic / CWE / ISO 42001 / tools matrix with honest statuses."""
    llm_catalog = _llm_catalog()
    agentic_catalog = _agentic_catalog()
    cwe_catalog = _cwe_catalog()
    iso_catalog = _iso42001_ai_controls()

    tested_tools = _tools_mentioned(runs, decisions, findings)
    llm_status = {cid: "not_assessed" for cid in llm_catalog}
    agentic_status = {cid: "not_assessed" for cid in agentic_catalog}
    cwe_status = {cid: "not_assessed" for cid in cwe_catalog}
    iso_status = {cid: "not_assessed" for cid in iso_catalog}
    tool_status = {t: ("not_tested" if t not in tested_tools else "not_assessed") for t in _AI_TOOLS}

    # Explicit not_tested from planner / AI-tool outcomes — never "assessed_no_issue".
    for payload in _payloads(_decisions_by_kind(decisions).get("planner_outcome", [])):
        outcome = str(payload.get("outcome") or payload.get("status") or "").upper()
        tool = str(payload.get("tool") or payload.get("adapter") or "").lower()
        if outcome in {"NOT_TESTED", "SKIPPED", "REFUSED", "RATE_LIMITED", "FAILED", "EMPTY"}:
            if tool in tool_status:
                tool_status[tool] = _worse(tool_status[tool], "not_tested")
            for cid in payload.get("llm_ids") or payload.get("owasp_llm") or []:
                if cid in llm_status:
                    llm_status[cid] = _worse(llm_status[cid], "not_tested")

    for f in findings:
        status = _status_from_finding(f)
        for cid in _llm_ids_for_finding(f, llm_catalog):
            llm_status[cid] = _worse(llm_status[cid], status)
        for cid in _agentic_ids_for_finding(f, agentic_catalog):
            agentic_status[cid] = _worse(agentic_status[cid], status)
        cwe = _finding_cwe(f)
        if cwe and cwe in cwe_status:
            cwe_status[cwe] = _worse(cwe_status[cwe], status)
        for ref in _iso_refs_for_finding(f, iso_catalog):
            iso_status[ref] = _worse(iso_status[ref], status)
        for tool in _tools_on_finding(f):
            if tool in tool_status:
                # Tool ran and produced a finding signal — still not a pass.
                if status == "confirmed":
                    tool_status[tool] = _worse(tool_status[tool], "confirmed")
                elif status == "potential":
                    tool_status[tool] = _worse(tool_status[tool], "potential")
                elif status == "needs_manual":
                    tool_status[tool] = _worse(tool_status[tool], "needs_manual")
                else:
                    tool_status[tool] = _worse(tool_status[tool], "inconclusive")

    # assessed_no_issue only when an explicit clean outcome is recorded — never by default.
    for payload in _payloads(_decisions_by_kind(decisions).get("conclusion", [])):
        if str(payload.get("conclusion_type") or "") == "observed_fact" and not payload.get(
            "evidence_citations"
        ):
            continue
        if str(payload.get("conclusion_type") or "") == "rejected":
            for cid in payload.get("llm_ids") or []:
                if cid in llm_status and llm_status[cid] == "not_assessed":
                    llm_status[cid] = "assessed_no_issue"

    def _rows(catalog: Mapping[str, str], statuses: Mapping[str, str]) -> list[dict[str, Any]]:
        return [
            {
                "id": cid,
                "name": name,
                "status": statuses.get(cid, "not_assessed"),
                "notes": _status_note(statuses.get(cid, "not_assessed")),
            }
            for cid, name in catalog.items()
        ]

    return {
        "statuses": sorted(COVERAGE_STATUSES),
        "honesty": (
            "Missing evidence never becomes a pass. "
            "Default cell status is not_assessed; not_tested means a planned test did not run."
        ),
        "owasp_llm": _rows(llm_catalog, llm_status),
        "owasp_agentic": _rows(agentic_catalog, agentic_status),
        "cwe": _rows(cwe_catalog, cwe_status),
        "iso42001": _rows(iso_catalog, iso_status),
        "tools": [
            {
                "id": t,
                "name": t,
                "status": tool_status[t],
                "notes": _status_note(tool_status[t]),
            }
            for t in _AI_TOOLS
        ],
    }


def aasi_qa_issues(report_ctx: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Conceptual AASI QA extensions; does not bypass hashing / signing / four-eyes.

    Returns issue dicts ``{code, severity, message, details?}``. Callers may fold
    these into sealed-report QA without changing approval gates here.
    """
    issues: list[dict[str, Any]] = []
    aasi = report_ctx.get("aasi") if isinstance(report_ctx, Mapping) else None
    if not isinstance(aasi, Mapping) or not aasi.get("present"):
        return issues

    tenant_id = aasi.get("tenant_id")
    known = {str(x) for x in (aasi.get("known_evidence_ids") or [])}
    findings = list(report_ctx.get("findings") or [])
    finding_by_id = {
        str(getattr(f, "id", "")): f for f in findings if getattr(f, "id", None) is not None
    }

    for run in aasi.get("runs") or []:
        if tenant_id is not None and run.get("tenant_id") not in (None, tenant_id):
            issues.append(
                {
                    "code": "aasi_cross_tenant",
                    "severity": "critical",
                    "message": f"AASI run {run.get('id')} tenant_id does not match report tenant",
                    "details": {"run_id": run.get("id"), "tenant_id": run.get("tenant_id")},
                }
            )

    tech = aasi.get("technical") or {}
    for row in tech.get("rows") or []:
        # Confirmed without evidence hash / citations.
        if str(row.get("validation") or "").lower() == "confirmed" and not row.get("evidence_hash"):
            issues.append(
                {
                    "code": "aasi_unreproduced_confirmed",
                    "severity": "critical",
                    "message": (
                        f"Confirmed AASI-linked row for test {row.get('test_id')!r} "
                        "lacks evidence hash / reproduction proof"
                    ),
                    "details": {"recommendation_id": row.get("recommendation_id")},
                }
            )
        # Guardrail: never allow confidence to be used as severity in the payload.
        if row.get("uncertainty") is not None and row.get("confidence_is_not_severity") is not True:
            issues.append(
                {
                    "code": "aasi_confidence_as_severity",
                    "severity": "critical",
                    "message": "Technical row missing confidence_is_not_severity=True guard",
                    "details": {"recommendation_id": row.get("recommendation_id")},
                }
            )

    trace = aasi.get("traceability") or {}
    for chain in trace.get("chains") or []:
        for eid in chain.get("evidence_ids") or []:
            if known and str(eid) not in known:
                issues.append(
                    {
                        "code": "aasi_invalid_evidence_ref",
                        "severity": "critical",
                        "message": f"Traceability cites unknown evidence id {eid!r}",
                        "details": {
                            "evidence_id": str(eid),
                            "hypothesis_id": chain.get("hypothesis_id"),
                            "recommendation_id": chain.get("recommendation_id"),
                        },
                    }
                )
        fid = chain.get("finding_id")
        if fid and str(fid) not in finding_by_id and findings:
            issues.append(
                {
                    "code": "aasi_orphan_finding_ref",
                    "severity": "warning",
                    "message": f"Traceability cites finding_id {fid!r} not in reportable findings",
                    "details": {"finding_id": fid},
                }
            )
        if not chain.get("hypothesis_id") or not chain.get("recommendation_id"):
            issues.append(
                {
                    "code": "aasi_broken_traceability",
                    "severity": "warning",
                    "message": "Traceability chain missing hypothesis_id or recommendation_id",
                    "details": dict(chain),
                }
            )

    matrix = aasi.get("coverage_matrix") or {}
    for group in ("owasp_llm", "owasp_agentic", "cwe", "iso42001", "tools"):
        for row in matrix.get(group) or []:
            st = str(row.get("status") or "")
            if st not in COVERAGE_STATUSES:
                issues.append(
                    {
                        "code": "aasi_invalid_coverage_status",
                        "severity": "critical",
                        "message": f"Coverage cell {row.get('id')} has invalid status {st!r}",
                        "details": {"group": group, "id": row.get("id"), "status": st},
                    }
                )
            if st in {"pass", "passed", "ok", "clean"}:
                issues.append(
                    {
                        "code": "aasi_missing_evidence_as_pass",
                        "severity": "critical",
                        "message": "Coverage matrix must never encode missing evidence as pass",
                        "details": {"group": group, "id": row.get("id")},
                    }
                )

    exec_sec = aasi.get("executive") or {}
    if exec_sec.get("confirmed") and not any(
        str(getattr(f, "validation_status", "") or "").lower() == "confirmed" for f in findings
    ):
        # Executive confirmed count must come from finding validation, not AI confidence.
        issues.append(
            {
                "code": "aasi_confirmed_without_validation",
                "severity": "critical",
                "message": "Executive confirmed count does not match finding validation_status",
            }
        )

    return issues


# --- helpers -----------------------------------------------------------------


def _aasi_enabled() -> bool:
    try:
        from attestra.aasi import enabled

        return bool(enabled())
    except Exception:  # noqa: BLE001
        return False


def _tenant_ok(doc: Mapping[str, Any], tenant_id: int) -> bool:
    if not tenant_id:
        return True
    raw = doc.get("tenant_id")
    if raw is None:
        return True
    try:
        return int(raw) == int(tenant_id)
    except (TypeError, ValueError):
        return False


def _load_runs(tenant_id: int, engagement_id: int) -> list[dict[str, Any]]:
    if not tenant_id or not engagement_id:
        return []
    try:
        from attestra.aasi.store import AasiStore
        from attestra.persistence.mongo.serialization import with_id

        store = AasiStore()
        cursor = store.runs.find(
            {"tenant_id": int(tenant_id), "engagement_id": int(engagement_id)}
        ).sort("created_at", 1)
        return [with_id(d) for d in cursor]
    except Exception:  # noqa: BLE001 — report generation must not fail if AASI store is down
        return []


def _load_decisions(
    tenant_id: int, engagement_id: int, runs: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    try:
        from attestra.aasi.store import AasiStore

        store = AasiStore()
        for run in runs:
            rid = run.get("id") if run.get("id") is not None else run.get("_id")
            if rid is None:
                continue
            out.extend(store.list_decisions(int(rid), int(tenant_id)))
        # Prefer engagement filter when present on documents.
        return [
            d
            for d in out
            if d.get("engagement_id") in (None, engagement_id)
            and _tenant_ok(d, tenant_id)
        ]
    except Exception:  # noqa: BLE001
        return []


def _run_summary(run: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": run.get("id") if run.get("id") is not None else run.get("_id"),
        "tenant_id": run.get("tenant_id"),
        "engagement_id": run.get("engagement_id"),
        "status": run.get("status"),
    }


def _ai_inventory(assets: Sequence[Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for a in assets:
        kind = getattr(a, "kind", None)
        if kind is None and isinstance(a, Mapping):
            kind = a.get("kind")
        if kind != "ai_app":
            continue
        rows.append(
            {
                "id": getattr(a, "id", None) if not isinstance(a, Mapping) else a.get("id"),
                "name": getattr(a, "name", None) if not isinstance(a, Mapping) else a.get("name"),
                "identifier": (
                    getattr(a, "identifier", None)
                    if not isinstance(a, Mapping)
                    else a.get("identifier")
                ),
                "kind": "ai_app",
            }
        )
    return rows


def _validation_counts(findings: Sequence[Any]) -> Counter:
    c: Counter = Counter()
    for f in findings:
        vs = str(getattr(f, "validation_status", None) or "unvalidated").strip().lower()
        c[vs] += 1
    return c


def _unresolved_hypotheses(decisions: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    by_kind = _decisions_by_kind(decisions)
    hyp_ids = {str(p.get("id") or "") for p in _payloads(by_kind.get("hypothesis", [])) if p.get("id")}
    linked: set[str] = set()
    for p in _payloads(by_kind.get("recommendation", [])):
        if p.get("hypothesis_id"):
            linked.add(str(p["hypothesis_id"]))
    for p in _payloads(by_kind.get("conclusion", [])):
        for sid in p.get("subject_ids") or []:
            linked.add(str(sid))
    out: list[dict[str, Any]] = []
    for p in _payloads(by_kind.get("hypothesis", [])):
        hid = str(p.get("id") or "")
        if hid and hid not in linked:
            out.append(
                {
                    "id": hid,
                    "statement": str(p.get("statement") or ""),
                    "uncertainty": p.get("uncertainty", "unknown"),
                    "basis": p.get("basis"),
                }
            )
    # Hypotheses with recommendations but no conclusion also count as unresolved.
    concluded_subjects: set[str] = set()
    for p in _payloads(by_kind.get("conclusion", [])):
        for sid in p.get("subject_ids") or []:
            concluded_subjects.add(str(sid))
    for p in _payloads(by_kind.get("recommendation", [])):
        hid = str(p.get("hypothesis_id") or "")
        if hid and hid in hyp_ids and hid not in concluded_subjects:
            if not any(x["id"] == hid for x in out):
                hyp = next((h for h in _payloads(by_kind.get("hypothesis", [])) if str(h.get("id")) == hid), {})
                out.append(
                    {
                        "id": hid,
                        "statement": str(hyp.get("statement") or ""),
                        "uncertainty": hyp.get("uncertainty", "unknown"),
                        "basis": hyp.get("basis"),
                        "has_recommendation": True,
                    }
                )
    return out


def _coverage_gaps(
    decisions: Sequence[Mapping[str, Any]], runs: Sequence[Mapping[str, Any]]
) -> list[str]:
    gaps: list[str] = []
    for payload in _payloads(_decisions_by_kind(decisions).get("planner_outcome", [])):
        outcome = str(payload.get("outcome") or payload.get("status") or "").upper()
        if outcome in {"NOT_TESTED", "SKIPPED", "DEFERRED", "REFUSED", "FAILED"}:
            tid = payload.get("registered_test_id") or payload.get("test_id") or "?"
            gaps.append(f"{tid}: {outcome}")
    for run in runs:
        if str(run.get("status") or "").upper() in {"BLOCKED", "FAILED", "CANCELLED"}:
            gaps.append(f"run {run.get('id') or run.get('_id')}: {run.get('status')}")
    return gaps


def _posture_sentence(
    val_counts: Counter,
    inventory: list[dict[str, Any]],
    unresolved: list[dict[str, Any]],
    gaps: list[str],
) -> str:
    parts = [
        f"AI asset inventory: {len(inventory)} ai_app target(s).",
        (
            "Finding validation classes — "
            f"confirmed {val_counts.get('confirmed', 0)}, "
            f"potential {val_counts.get('potential', 0)}, "
            f"needs manual review {val_counts.get('needs_manual_validation', 0)} "
            "(from Attestra validation_status, not AI confidence)."
        ),
    ]
    if unresolved:
        parts.append(f"Unresolved hypotheses: {len(unresolved)}.")
    if gaps:
        parts.append(f"Coverage gaps / incomplete runs: {len(gaps)}.")
    parts.append(_CONFIDENCE_IS_NOT_SEVERITY)
    return " ".join(parts)


def _decisions_by_kind(
    decisions: Sequence[Mapping[str, Any]],
) -> dict[str, list[Mapping[str, Any]]]:
    out: dict[str, list[Mapping[str, Any]]] = {}
    for d in decisions:
        kind = str(d.get("kind") or "")
        out.setdefault(kind, []).append(d)
    return out


def _payloads(decisions: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for d in decisions:
        p = d.get("payload")
        if isinstance(p, Mapping):
            rows.append(dict(p))
    return rows


def _pairs(
    decisions: Sequence[Mapping[str, Any]],
) -> list[tuple[Mapping[str, Any], dict[str, Any]]]:
    rows: list[tuple[Mapping[str, Any], dict[str, Any]]] = []
    for d in decisions:
        p = d.get("payload")
        if isinstance(p, Mapping):
            rows.append((d, dict(p)))
    return rows


def _match_planner(
    planners: Sequence[Mapping[str, Any]], rec: Mapping[str, Any]
) -> Mapping[str, Any] | None:
    rid = str(rec.get("id") or "")
    tid = str(rec.get("registered_test_id") or rec.get("test_id") or "")
    for p in planners:
        if rid and str(p.get("recommendation_id") or "") == rid:
            return p
        if tid and str(p.get("registered_test_id") or p.get("test_id") or "") == tid:
            return p
    return None


def _match_conclusion(
    conclusions: Sequence[Mapping[str, Any]], rec: Mapping[str, Any], hyp_id: str
) -> Mapping[str, Any] | None:
    rid = str(rec.get("id") or "")
    for c in conclusions:
        subjects = {str(x) for x in (c.get("subject_ids") or [])}
        if rid and rid in subjects:
            return c
        if hyp_id and hyp_id in subjects:
            return c
    return None


def _match_conclusion_pair(
    conclusions: Sequence[tuple[Mapping[str, Any], dict[str, Any]]],
    rec: Mapping[str, Any],
    hyp_id: str,
) -> tuple[Mapping[str, Any] | None, dict[str, Any]]:
    rid = str(rec.get("id") or "")
    for dec, c in conclusions:
        subjects = {str(x) for x in (c.get("subject_ids") or [])}
        if rid and rid in subjects:
            return dec, c
        if hyp_id and hyp_id in subjects:
            return dec, c
    return None, {}


def _match_finding(
    finding_by_id: Mapping[str, Any],
    conclusion: Mapping[str, Any] | None,
    rec: Mapping[str, Any],
) -> Any | None:
    if conclusion:
        fid = _finding_id_from_conclusion(conclusion)
        if fid and fid in finding_by_id:
            return finding_by_id[fid]
        for sid in conclusion.get("subject_ids") or []:
            if str(sid) in finding_by_id:
                return finding_by_id[str(sid)]
    # Soft match via recommendation id embedded on finding metadata when present.
    rid = str(rec.get("id") or "")
    for f in finding_by_id.values():
        meta = getattr(f, "meta", None) or getattr(f, "extra", None) or {}
        if isinstance(meta, Mapping) and str(meta.get("aasi_recommendation_id") or "") == rid:
            return f
    return None


def _finding_id_from_conclusion(conclusion: Mapping[str, Any] | None) -> str | None:
    if not conclusion:
        return None
    for key in ("finding_id", "findingId"):
        if conclusion.get(key) is not None:
            return str(conclusion[key])
    for sid in conclusion.get("subject_ids") or []:
        s = str(sid)
        if s.isdigit():
            return s
    return None


def _evidence_hash(conclusion: Mapping[str, Any] | None, finding: Any | None) -> str:
    if conclusion:
        for key in ("evidence_hash", "raw_sha256", "sha256"):
            val = conclusion.get(key)
            if val:
                return str(val)
        cites = conclusion.get("evidence_citations") or []
        if cites:
            return str(cites[0])
    if finding is not None:
        for ev in getattr(finding, "evidence", None) or []:
            sha = getattr(ev, "sha256", None) or getattr(ev, "raw_sha256", None)
            if sha:
                return str(sha)
    return ""


def _finding_validation(finding: Any | None) -> str:
    if finding is None:
        return ""
    return str(getattr(finding, "validation_status", None) or "").strip().lower()


def _status_from_finding(f: Any) -> str:
    vs = str(getattr(f, "validation_status", None) or "unvalidated").strip().lower()
    if vs == "confirmed":
        return "confirmed"
    if vs == "potential":
        return "potential"
    if vs == "needs_manual_validation":
        return "needs_manual"
    if vs in {"not_reproducible", "inconclusive"}:
        return "inconclusive"
    if vs in {"false_positive", "informational", "accepted_risk"}:
        return "assessed_no_issue"
    return "inconclusive"


def _worse(current: str, candidate: str) -> str:
    if candidate not in COVERAGE_STATUSES:
        return current if current in COVERAGE_STATUSES else "not_assessed"
    if current not in COVERAGE_STATUSES:
        return candidate
    return candidate if _STATUS_RANK[candidate] >= _STATUS_RANK[current] else current


def _status_note(status: str) -> str:
    notes = {
        "not_assessed": "No assessment evidence recorded for this cell.",
        "assessed_no_issue": "Explicit clean / rejected outcome recorded (not inferred from silence).",
        "potential": "Potential finding or heuristic hit; not confirmed.",
        "confirmed": "Confirmed via Attestra validation with evidence.",
        "needs_manual": "Needs manual validation / human review.",
        "inconclusive": "Inconclusive or unreproduced result.",
        "not_tested": "Planned or expected test did not run (never counted as pass).",
    }
    return notes.get(status, "")


def _llm_catalog() -> dict[str, str]:
    try:
        from attestra.compliance.owasp import get_llm_top10

        return dict(get_llm_top10())
    except Exception:  # noqa: BLE001
        return {f"LLM{i:02d}": f"LLM{i:02d}" for i in range(1, 11)}


def _agentic_catalog() -> dict[str, str]:
    try:
        from pathlib import Path

        import yaml

        path = Path(__file__).resolve().parents[1] / "compliance" / "data" / "ai_taxonomy.yaml"
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        raw = data.get("owasp_agentic_2026") or {}
        return {str(k): str(v) for k, v in raw.items()}
    except Exception:  # noqa: BLE001
        return {f"ASI{i:02d}": f"ASI{i:02d}" for i in range(1, 11)}


def _cwe_catalog() -> dict[str, str]:
    try:
        from attestra.compliance import iso42001

        ids: dict[str, str] = {}
        for meta in iso42001.llm_top10().values():
            for w in meta.get("cwe") or []:
                ids[str(int(w))] = f"CWE-{int(w)}"
        return ids
    except Exception:  # noqa: BLE001
        return {}


def _iso42001_ai_controls() -> dict[str, str]:
    try:
        from attestra.compliance import iso42001

        refs: dict[str, str] = {}
        for lid, meta in iso42001.llm_top10().items():
            for ctrl in meta.get("controls") or []:
                refs[str(ctrl)] = f"ISO/IEC 42001 {ctrl} (via {lid})"
        return refs
    except Exception:  # noqa: BLE001
        return {}


def _llm_ids_for_finding(f: Any, catalog: Mapping[str, str]) -> list[str]:
    out: list[str] = []
    label = str(getattr(f, "owasp_top10", None) or getattr(f, "owasp", None) or "")
    try:
        from attestra.compliance.owasp import top10_category_id

        cid = top10_category_id(label)
        if cid in catalog:
            out.append(cid)
    except Exception:  # noqa: BLE001
        pass
    cwe = _finding_cwe(f)
    if cwe:
        try:
            from attestra.compliance import iso42001

            for lid, meta in iso42001.llm_top10().items():
                if int(cwe) in {int(x) for x in (meta.get("cwe") or [])} and lid in catalog:
                    out.append(lid)
        except Exception:  # noqa: BLE001
            pass
    return list(dict.fromkeys(out))


def _agentic_ids_for_finding(f: Any, catalog: Mapping[str, str]) -> list[str]:
    out: list[str] = []
    for attr in ("owasp_top10", "title", "category"):
        text = str(getattr(f, attr, None) or "")
        for cid in catalog:
            if cid in text.upper():
                out.append(cid)
    return list(dict.fromkeys(out))


def _iso_refs_for_finding(f: Any, catalog: Mapping[str, str]) -> list[str]:
    cwe = _finding_cwe(f)
    if not cwe:
        return []
    try:
        from attestra.compliance import iso42001

        refs: list[str] = []
        for meta in iso42001.llm_top10().values():
            if int(cwe) in {int(x) for x in (meta.get("cwe") or [])}:
                for ctrl in meta.get("controls") or []:
                    if str(ctrl) in catalog:
                        refs.append(str(ctrl))
        return list(dict.fromkeys(refs))
    except Exception:  # noqa: BLE001
        return []


def _finding_cwe(f: Any) -> str | None:
    cwe = getattr(f, "cwe", None)
    if cwe is None or cwe == "":
        return None
    try:
        return str(int(cwe))
    except (TypeError, ValueError):
        text = str(cwe).upper().replace("CWE-", "").strip()
        return text if text.isdigit() else None


def _tools_on_finding(f: Any) -> list[str]:
    tools = getattr(f, "tools", None) or getattr(f, "detected_by", None) or []
    if isinstance(tools, str):
        tools = [tools]
    return [str(t).strip().lower() for t in tools if str(t).strip().lower() in _AI_TOOLS]


def _tools_mentioned(
    runs: Sequence[Mapping[str, Any]],
    decisions: Sequence[Mapping[str, Any]],
    findings: Sequence[Any],
) -> set[str]:
    found: set[str] = set()
    for f in findings:
        found.update(_tools_on_finding(f))
    for d in decisions:
        p = d.get("payload") if isinstance(d.get("payload"), Mapping) else {}
        for key in ("tool", "adapter", "import_tool"):
            t = str((p or {}).get(key) or "").lower()
            if t in _AI_TOOLS:
                found.add(t)
    for r in runs:
        for t in r.get("tasks") or []:
            if isinstance(t, Mapping):
                name = str(t.get("tool") or t.get("adapter") or "").lower()
                if name in _AI_TOOLS:
                    found.add(name)
    return found


__all__ = [
    "COVERAGE_STATUSES",
    "empty_aasi_payload",
    "aasi_report_context",
    "aasi_context_for_engagement",
    "build_executive_section",
    "build_technical_section",
    "build_traceability_appendix",
    "build_coverage_matrix",
    "aasi_qa_issues",
]
