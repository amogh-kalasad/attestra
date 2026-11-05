"""Build a Phase 3/4 coverage honesty snapshot for an engagement."""
# @lat: [[architecture#World-class PT coverage honesty (Phase 3)]]
# @lat: [[architecture#World-class coverage execution engine (Phase 4)]]

from __future__ import annotations

import json
from collections import Counter
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra.auth_web.coverage import _route_bucket
from attestra.automated_vapt.coverage.models import CoverageSnapshot
from attestra.models import (
    AuthChecklistItem,
    AuthCredentialProfile,
    AuthElementInventory,
    AuthRouteInventory,
    AutomatedTestExecution,
    ELEMENT_TEST_STATUSES,
)

# Case outcomes that count as a successful automated execution of a test case.
_CASE_SUCCESS = frozenset({"PASSED"})
# Outcomes that demonstrate the case ran and reported a problem (not a skip).
_CASE_FAILED = frozenset({"FAILED", "FINDING"})
_CASE_SKIPPED = frozenset({"SKIPPED"})
# Policy / capability deferrals — distinct from runtime skips.
_CASE_BLOCKED = frozenset({"DEFERRED"})

# Form/control types treated as parameters (exclude pure navigation controls).
_PARAM_ELEMENT_TYPES = frozenset(
    {
        "textbox",
        "textarea",
        "select",
        "checkbox",
        "radio",
        "hidden",
        "password",
        "email",
        "number",
        "search",
        "tel",
        "url",
        "date",
        "file",
        "range",
    }
)


def _cases_from_execution(ex: AutomatedTestExecution) -> list[dict[str, Any]]:
    try:
        data = json.loads(ex.result_json or "{}")
    except (TypeError, ValueError):
        return []
    cases = data.get("cases") if isinstance(data, dict) else None
    return [c for c in (cases or []) if isinstance(c, dict)]


def _route_is_authenticated(route: AuthRouteInventory) -> bool:
    """True when the route was crawled with auth or has a non-empty role_name."""
    if bool(getattr(route, "authenticated", False)):
        return True
    return bool((route.role_name or "").strip())


def _is_param_element(el: AuthElementInventory) -> bool:
    et = (el.element_type or "").strip().lower()
    if et in _PARAM_ELEMENT_TYPES:
        return True
    # Unknown type with an input_type still looks like a parameter field.
    if et not in ("link", "button") and (el.input_type or "").strip():
        return True
    return False


def _query_param_names(url: str) -> set[str]:
    try:
        pairs = parse_qsl(urlsplit(url or "").query, keep_blank_values=True)
    except ValueError:
        return set()
    return {k for k, _ in pairs if k}


def _collect_ledger_rows(session: Session, engagement_id: int) -> list[dict[str, Any]]:
    """Load Phase 4 ledger rows when available; empty list if module or call fails."""
    try:
        from attestra.automated_vapt.coverage.ledger import collect_engagement_ledger
    except ImportError:  # pragma: no cover - sibling package optional during parallel work
        return []
    try:
        raw = collect_engagement_ledger(session, engagement_id)
    except Exception:
        return []
    if isinstance(raw, list):
        return [r for r in raw if isinstance(r, dict)]
    return []


def _ledger_param_names(entry: dict[str, Any]) -> set[str]:
    params = entry.get("parameters")
    if isinstance(params, str) and params.strip():
        return {params.strip()}
    if isinstance(params, (list, tuple)):
        return {str(p).strip() for p in params if str(p).strip()}
    return set()


def _ledger_method(entry: dict[str, Any]) -> str:
    m = entry.get("http_method")
    if isinstance(m, str) and m.strip():
        return m.strip().upper()
    return ""


def _ledger_status_tested(entry: dict[str, Any]) -> bool:
    st = str(entry.get("execution_status") or entry.get("status") or "").upper()
    return st in {"PASSED", "FINDING", "FAILED"}


def build_coverage_snapshot(session: Session, engagement_id: int) -> dict:
    """Aggregate checklist + route + element + automated-execution coverage for ``engagement_id``.

    Phase 4 adds authenticated/unauthenticated endpoint buckets, HTTP methods,
    parameter and role totals, deferred-case blocking, endpoint coverage %,
    optional execution-ledger count, and an explicit note that scan completion
    is not security-testing coverage.

    Returns a plain dict (via [[attestra/automated_vapt/coverage/models.py#CoverageSnapshot#to_dict]])
    suitable for reports and services. Does not include vulnerability severity totals.
    """
    snap = CoverageSnapshot(engagement_id=engagement_id)

    routes = list(
        session.scalars(
            select(AuthRouteInventory).where(AuthRouteInventory.engagement_id == engagement_id)
        ).all()
    )
    route_bucket = _route_bucket(routes)
    snap.endpoints_discovered = route_bucket["discovered"]
    snap.endpoints_tested = route_bucket["visited"]
    snap.endpoints_untested = max(0, snap.endpoints_discovered - snap.endpoints_tested)
    snap.coverage_pct_endpoints = float(route_bucket["coverage_pct"])

    auth_n = sum(1 for r in routes if _route_is_authenticated(r))
    snap.endpoints_authenticated = auth_n
    snap.endpoints_unauthenticated = max(0, snap.endpoints_discovered - auth_n)

    ledger_rows = _collect_ledger_rows(session, engagement_id)
    snap.ledger_entry_count = len(ledger_rows)

    visited = [r for r in routes if r.status == "visited"]
    methods = {
        (r.http_method or "").strip().upper()
        for r in visited
        if (r.http_method or "").strip()
    }
    for entry in ledger_rows:
        meth = _ledger_method(entry)
        if meth and _ledger_status_tested(entry):
            methods.add(meth)
    snap.methods_tested = sorted(methods)

    snap.tested_roles = sorted(
        {
            (r.role_name or "").strip()
            for r in visited
            if (r.role_name or "").strip()
        }
    )
    snap.roles_tested = len(snap.tested_roles)

    route_roles = {(r.role_name or "").strip() for r in routes if (r.role_name or "").strip()}
    profiles = list(
        session.scalars(
            select(AuthCredentialProfile).where(
                AuthCredentialProfile.engagement_id == engagement_id
            )
        ).all()
    )
    profile_roles = {
        (p.role_name or "").strip() for p in profiles if (p.role_name or "").strip()
    }
    snap.roles_discovered = len(route_roles | profile_roles)

    route_ids = [r.id for r in routes]
    if route_ids:
        elements = list(
            session.scalars(
                select(AuthElementInventory).where(AuthElementInventory.route_id.in_(route_ids))
            ).all()
        )
    else:
        elements = []
    param_els = [e for e in elements if _is_param_element(e)]
    if param_els:
        snap.parameters_discovered = len(param_els)
        tested_statuses = {s for s in ELEMENT_TEST_STATUSES if s != "not_tested"}
        snap.parameters_tested = sum(1 for e in param_els if e.test_status in tested_statuses)
    else:
        discovered: set[str] = set()
        tested: set[str] = set()
        for entry in ledger_rows:
            names = _ledger_param_names(entry)
            discovered |= names
            if _ledger_status_tested(entry):
                tested |= names
        if not discovered:
            for r in routes:
                discovered |= _query_param_names(r.url or "")
        snap.parameters_discovered = len(discovered)
        snap.parameters_tested = len(tested)

    checklist_rows = list(
        session.scalars(
            select(AuthChecklistItem).where(AuthChecklistItem.engagement_id == engagement_id)
        ).all()
    )
    cl = Counter(c.status for c in checklist_rows)
    snap.checklist_total = len(checklist_rows)
    snap.checklist_passed = cl.get("passed", 0)
    snap.checklist_failed = cl.get("failed", 0)
    snap.checklist_blocked = cl.get("blocked", 0)
    snap.checklist_skipped = cl.get("not_tested", 0)
    snap.checklist_not_started = cl.get("not_started", 0)
    snap.checklist_not_applicable = cl.get("not_applicable", 0)

    executions = list(
        session.scalars(
            select(AutomatedTestExecution).where(
                AutomatedTestExecution.engagement_id == engagement_id,
                AutomatedTestExecution.status.in_(("COMPLETED", "FAILED")),
            )
        ).all()
    )
    ok = fail = skipped = blocked = 0
    for ex in executions:
        for case in _cases_from_execution(ex):
            st = str(case.get("status") or "").upper()
            if st in _CASE_SUCCESS:
                ok += 1
            elif st in _CASE_FAILED:
                fail += 1
            elif st in _CASE_BLOCKED:
                blocked += 1
            elif st in _CASE_SKIPPED:
                skipped += 1
    snap.automated_cases_successful = ok
    snap.automated_cases_failed = fail
    snap.automated_cases_skipped = skipped
    snap.automated_cases_blocked = blocked
    snap.test_cases_blocked = blocked

    snap.scan_completion_is_not_security_coverage = True

    snap.incomplete = bool(
        snap.endpoints_discovered == 0
        or snap.endpoints_untested > 0
        or snap.checklist_not_started
        or snap.checklist_blocked
        or snap.checklist_skipped
        or snap.automated_cases_skipped
        or snap.automated_cases_blocked
    )
    return snap.to_dict()
