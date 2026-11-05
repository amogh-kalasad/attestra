"""Per-case security-test execution ledger (World-Class Phase 4).

Persists structured coverage rows under AutomatedTestExecution.result_json
``coverage_ledger`` — one or more entries per catalogue case, keyed by
endpoint/method/params when extractable. Complements the Phase 3 honesty
snapshot; does not replace checklist or vuln counts.
"""
# @lat: [[architecture#World-class test execution ledger (Phase 4)]]

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra.models import AutomatedTestExecution

_STATUS_MAP = frozenset({"PASSED", "FINDING", "FAILED", "SKIPPED", "DEFERRED"})
_INCOMPLETE = frozenset({"SKIPPED", "DEFERRED"})


@dataclass
class CoverageLedgerEntry:
    """One coverage row for an automated security-test probe or case outcome."""

    test_id: str
    category: str = ""
    target_endpoint: str = ""
    http_method: str | None = None
    parameters: list[str] | str = field(default_factory=list)
    execution_status: str = "FAILED"
    executed_at: str = ""
    auth_context: str | dict[str, Any] = "anonymous"
    evidence_refs: list[str] = field(default_factory=list)
    result: str = ""
    limitation: str = ""
    block_or_fail_reason: str = ""
    engagement_id: int = 0
    execution_id: int = 0
    asset_id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-friendly dict for result_json / aggregation APIs."""
        return asdict(self)


def _iso_now(executed_at: datetime | str | None = None) -> str:
    if isinstance(executed_at, str) and executed_at.strip():
        return executed_at.strip()
    if isinstance(executed_at, datetime):
        dt = executed_at if executed_at.tzinfo else executed_at.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    return datetime.now(timezone.utc).isoformat()


def _map_status(raw: Any) -> str:
    st = str(raw or "").upper().strip()
    if st in _STATUS_MAP:
        return st
    if st in {"CONFIRMED", "VULNERABLE", "POTENTIAL"}:
        return "FINDING"
    if st in {"NOT_TESTED", "BLOCKED"}:
        return "SKIPPED"
    return "FAILED" if st else "FAILED"


def _normalize_auth_context(auth_context: Any, case_result: dict[str, Any]) -> str | dict[str, Any]:
    if isinstance(auth_context, dict) and auth_context:
        return dict(auth_context)
    if isinstance(auth_context, str) and auth_context.strip():
        return auth_context.strip()
    auth = case_result.get("auth")
    if isinstance(auth, dict):
        pid = auth.get("profile_id")
        status = str(auth.get("status") or "none")
        if pid and status == "ready":
            return {"kind": "profile", "profile_id": pid, "status": status}
        if pid:
            return {"kind": "profile", "profile_id": pid, "status": status}
        if status in {"none", ""}:
            return "anonymous"
        return {"kind": "session", "status": status, "note": str(auth.get("note") or "")[:200]}
    return "anonymous"


def _evidence_refs(case_result: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for key in ("evidence_files", "report_evidence_files"):
        for item in case_result.get(key) or []:
            s = str(item).strip()
            if s and s not in refs:
                refs.append(s)
    evid = case_result.get("evidence")
    if isinstance(evid, dict):
        for k in ("http_pair_ids", "screenshot_ids", "evidence_ids"):
            for item in evid.get(k) or []:
                s = str(item).strip()
                if s and s not in refs:
                    refs.append(s)
    elif isinstance(evid, list):
        for item in evid:
            s = str(item).strip()
            if s and s not in refs:
                refs.append(s)
    fid = case_result.get("finding_id")
    if fid is not None:
        tag = f"finding:{fid}"
        if tag not in refs:
            refs.append(tag)
    return refs


def _path_and_params(url_or_path: str) -> tuple[str, list[str]]:
    raw = (url_or_path or "").strip()
    if not raw:
        return "", []
    parts = urlsplit(raw if "://" in raw or raw.startswith("/") else f"/{raw.lstrip('/')}")
    path = parts.path or raw
    params: list[str] = []
    if parts.query:
        for name in parse_qs(parts.query, keep_blank_values=True):
            if name and name not in params:
                params.append(name)
    return path or raw, params


def _add_target(
    buckets: dict[tuple[str, str | None], dict[str, Any]],
    *,
    endpoint: str,
    method: str | None = None,
    parameters: list[str] | str | None = None,
    result: str = "",
    status_hint: str | None = None,
    allow_empty: bool = False,
) -> None:
    ep = (endpoint or "").strip()
    if not ep and not allow_empty:
        return
    meth = (method or None)
    if isinstance(meth, str):
        meth = meth.upper().strip() or None
    key = (ep, meth)
    row = buckets.setdefault(
        key,
        {
            "target_endpoint": ep,
            "http_method": meth,
            "parameters": [],
            "result": "",
            "status_hint": None,
        },
    )
    existing = row["parameters"]
    if isinstance(parameters, str) and parameters.strip():
        if parameters not in existing:
            existing.append(parameters.strip())
    elif isinstance(parameters, list):
        for p in parameters:
            ps = str(p).strip()
            if ps and ps not in existing:
                existing.append(ps)
    if result and not row["result"]:
        row["result"] = result[:500]
    if status_hint and not row["status_hint"]:
        row["status_hint"] = status_hint


def _from_pair_like(obj: Any) -> tuple[str, str | None, list[str]]:
    if obj is None:
        return "", None, []
    if hasattr(obj, "url") and hasattr(obj, "method"):
        path, params = _path_and_params(str(getattr(obj, "url") or ""))
        return path, str(getattr(obj, "method") or "").upper() or None, params
    if isinstance(obj, dict):
        url = str(obj.get("url") or obj.get("target") or obj.get("path") or "")
        path, params = _path_and_params(url)
        method = obj.get("method") or obj.get("http_method")
        meth = str(method).upper().strip() if method else None
        extra_params = obj.get("parameters") or obj.get("param") or obj.get("params")
        if isinstance(extra_params, str) and extra_params.strip() and extra_params not in params:
            params.append(extra_params.strip())
        elif isinstance(extra_params, list):
            for p in extra_params:
                ps = str(p).strip()
                if ps and ps not in params:
                    params.append(ps)
        return path, meth, params
    return "", None, []


def _extract_targets(case_result: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect endpoint/method/param buckets from a case result shape."""
    buckets: dict[tuple[str, str | None], dict[str, Any]] = {}

    for key in ("evidence_pairs", "finding_evidence_pairs"):
        for pair in case_result.get(key) or []:
            path, meth, params = _from_pair_like(pair)
            _add_target(buckets, endpoint=path, method=meth, parameters=params)

    loc = str(case_result.get("finding_location") or "").strip()
    if loc:
        path, params = _path_and_params(loc)
        _add_target(buckets, endpoint=path or loc, parameters=params)

    target = str(case_result.get("target") or "").strip()
    if target:
        path, params = _path_and_params(target)
        _add_target(buckets, endpoint=path or target, parameters=params)

    for page in case_result.get("pages") or []:
        if not isinstance(page, dict):
            continue
        url = str(page.get("url") or "")
        path, params = _path_and_params(url)
        st = page.get("status")
        _add_target(
            buckets,
            endpoint=path or url,
            method="GET",
            parameters=params,
            result=str(page.get("detail") or "")[:300],
            status_hint=str(st).upper() if st else None,
        )

    for ep in case_result.get("endpoints") or []:
        if not isinstance(ep, dict):
            continue
        url = str(ep.get("url") or ep.get("path") or "")
        path, params = _path_and_params(url)
        meta = ep.get("meta") if isinstance(ep.get("meta"), dict) else {}
        param = meta.get("param") or ep.get("param")
        if param:
            ps = str(param).strip()
            if ps and ps not in params:
                params.append(ps)
        method = ep.get("method") or meta.get("method") or "GET"
        _add_target(
            buckets,
            endpoint=path or url,
            method=str(method),
            parameters=params,
            result=str(ep.get("detail") or "")[:300],
            status_hint=str(ep.get("status") or "").upper() or None,
        )

    module = case_result.get("module")
    if isinstance(module, dict):
        obs = module.get("observations")
    else:
        obs = case_result.get("observations")
    if isinstance(obs, dict):
        probes = obs.get("probes") or []
        if isinstance(probes, list):
            for probe in probes:
                if not isinstance(probe, dict):
                    continue
                url = str(probe.get("url") or probe.get("path") or "")
                path, params = _path_and_params(url)
                param = probe.get("param") or probe.get("parameter")
                if param:
                    ps = str(param).strip()
                    if ps and ps not in params:
                        params.append(ps)
                method = probe.get("method") or "GET"
                _add_target(
                    buckets,
                    endpoint=path or url,
                    method=str(method),
                    parameters=params,
                    result=str(probe.get("detail") or "")[:300],
                )
        for key in ("endpoints", "urls", "paths"):
            for item in obs.get(key) or []:
                if isinstance(item, str):
                    path, params = _path_and_params(item)
                    _add_target(buckets, endpoint=path or item, method="GET", parameters=params)
                elif isinstance(item, dict):
                    path, meth, params = _from_pair_like(item)
                    _add_target(buckets, endpoint=path, method=meth or "GET", parameters=params)

    capture = case_result.get("capture")
    if isinstance(capture, dict):
        path, meth, params = _from_pair_like(capture)
        if path:
            _add_target(buckets, endpoint=path, method=meth, parameters=params)
        pair = capture.get("pair") or capture.get("report_pair")
        if isinstance(pair, dict):
            path, meth, params = _from_pair_like(pair)
            _add_target(buckets, endpoint=path, method=meth, parameters=params)

    if not buckets:
        # Case-level row when no endpoint was discovered (DEFERRED / unknown / smoke).
        _add_target(
            buckets, endpoint="", method=None, parameters=[], result="", allow_empty=True
        )

    return list(buckets.values())


def _limitation_for(status: str, case_result: dict[str, Any]) -> str:
    detail = str(case_result.get("detail") or "").strip()
    limited = case_result.get("limitation")
    explicit = limited.strip() if isinstance(limited, str) and limited.strip() else ""
    if status == "DEFERRED":
        base = explicit or detail or "handler not implemented"
        if "not full coverage" not in base.lower():
            base = f"{base}; not full coverage" if base else "not full coverage"
        return base[:500]
    if status == "SKIPPED":
        base = explicit or detail or "case skipped"
        if "not full coverage" not in base.lower():
            base = f"{base}; not full coverage" if base else "skipped; not full coverage"
        return base[:500]
    return explicit[:500] if explicit else ""


def _block_or_fail_reason(status: str, case_result: dict[str, Any]) -> str:
    if status not in {"FAILED", "SKIPPED", "DEFERRED", "FINDING"}:
        return ""
    for key in ("block_or_fail_reason", "error", "fail_reason"):
        val = case_result.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()[:500]
    detail = str(case_result.get("detail") or "").strip()
    if status in {"FAILED", "SKIPPED", "DEFERRED"} and detail:
        return detail[:500]
    return ""


def entries_from_case_result(
    case_result: dict[str, Any],
    *,
    engagement_id: int,
    execution_id: int,
    asset_id: int | None = None,
    auth_context: Any = None,
    executed_at: datetime | str | None = None,
) -> list[CoverageLedgerEntry]:
    """Build ledger rows from one orchestrator case_result dict.

    Prefer endpoint rows from observations, evidence pairs, pages, replay
    ``endpoints``, module probes, and ``finding_location``. When none exist,
    emit a single case-level row (empty ``target_endpoint``).
    """
    if not isinstance(case_result, dict):
        return []
    test_id = str(case_result.get("test_id") or "").strip() or "unknown"
    category = str(case_result.get("category") or "").strip()
    status = _map_status(case_result.get("status"))
    when = _iso_now(executed_at)
    auth = _normalize_auth_context(auth_context, case_result)
    refs = _evidence_refs(case_result)
    limitation = _limitation_for(status, case_result)
    reason = _block_or_fail_reason(status, case_result)
    case_detail = str(case_result.get("detail") or "").strip()[:500]

    targets = _extract_targets(case_result)
    entries: list[CoverageLedgerEntry] = []
    for t in targets:
        ep = str(t.get("target_endpoint") or "")
        # Preserve empty endpoint for case-level rows (deferred / no probe targets).
        row_status = _map_status(t.get("status_hint")) if t.get("status_hint") else status
        # Endpoint-level PASSED under a FINDING case still records case status for honesty.
        if status in _INCOMPLETE:
            row_status = status
        elif status == "FAILED" and row_status == "PASSED":
            row_status = "FAILED"
        elif status == "FINDING":
            row_status = status
        params = t.get("parameters") or []
        row_limitation = limitation
        if row_status in _INCOMPLETE and not row_limitation:
            row_limitation = (
                "deferred; not full coverage"
                if row_status == "DEFERRED"
                else "skipped; not full coverage"
            )
        entries.append(
            CoverageLedgerEntry(
                test_id=test_id,
                category=category,
                target_endpoint=ep,
                http_method=t.get("http_method"),
                parameters=list(params) if isinstance(params, list) else str(params),
                execution_status=row_status,
                executed_at=when,
                auth_context=auth,
                evidence_refs=list(refs),
                result=str(t.get("result") or case_detail)[:500],
                limitation=row_limitation,
                block_or_fail_reason=reason if row_status in {"FAILED", "SKIPPED", "DEFERRED"} else (
                    reason if status == "FINDING" and reason else ""
                ),
                engagement_id=int(engagement_id),
                execution_id=int(execution_id),
                asset_id=asset_id,
            )
        )
    return entries


def merge_ledger(
    existing: list[CoverageLedgerEntry | dict[str, Any]] | None,
    new: list[CoverageLedgerEntry | dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Append ``new`` ledger dicts onto ``existing``, de-duplicating identical keys.

    Dedup key: (execution_id, test_id, target_endpoint, http_method, auth_context).
    Later rows win when the key matches so per-case rewrites stay current.
    """
    out: list[dict[str, Any]] = []
    index: dict[tuple[Any, ...], int] = {}

    def _as_dict(item: CoverageLedgerEntry | dict[str, Any]) -> dict[str, Any]:
        if isinstance(item, CoverageLedgerEntry):
            return item.to_dict()
        return dict(item)

    def _key(d: dict[str, Any]) -> tuple[Any, ...]:
        auth = d.get("auth_context")
        auth_k = json.dumps(auth, sort_keys=True, default=str) if isinstance(auth, dict) else str(auth or "")
        return (
            d.get("execution_id"),
            str(d.get("test_id") or ""),
            str(d.get("target_endpoint") or ""),
            (str(d.get("http_method") or "").upper() or None),
            auth_k,
        )

    for src in (existing or [], new or []):
        for item in src:
            if item is None:
                continue
            d = _as_dict(item)
            k = _key(d)
            if k in index:
                out[index[k]] = d
            else:
                index[k] = len(out)
                out.append(d)
    return out


def ledger_dicts_from_result_json(result_json: str | dict[str, Any] | None) -> list[dict[str, Any]]:
    """Parse ``coverage_ledger`` from an execution result_json blob."""
    if isinstance(result_json, dict):
        data = result_json
    else:
        try:
            data = json.loads(result_json or "{}")
        except (TypeError, ValueError):
            return []
    if not isinstance(data, dict):
        return []
    rows = data.get("coverage_ledger") or []
    return [r for r in rows if isinstance(r, dict)]


def collect_engagement_ledger(session: Session, engagement_id: int) -> list[dict[str, Any]]:
    """Aggregate coverage_ledger rows from COMPLETED/FAILED executions for an engagement."""
    executions = list(
        session.scalars(
            select(AutomatedTestExecution).where(
                AutomatedTestExecution.engagement_id == engagement_id,
                AutomatedTestExecution.status.in_(("COMPLETED", "FAILED")),
            )
        ).all()
    )
    merged: list[dict[str, Any]] = []
    for ex in executions:
        merged = merge_ledger(merged, ledger_dicts_from_result_json(ex.result_json))
    return merged


def build_coverage_ledger(session: Session, engagement_id: int) -> list[dict[str, Any]]:
    """API/report-facing alias for [[collect_engagement_ledger]].

    Used by ``engagement_coverage_snapshot(..., include_ledger=True)``.
    """
    return collect_engagement_ledger(session, engagement_id)
