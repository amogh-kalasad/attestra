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



def _normalize_endpoint(url_or_path: str) -> str:
    """Path-only key: drop scheme, host, query and fragment; no trailing slash."""
    raw = (url_or_path or "").strip()
    if not raw:
        return ""
    raw = raw.split("#")[0].split("?")[0].strip()
    if not raw:
        return ""
    if "://" in raw:
        try:
            path = urlsplit(raw).path or "/"
        except ValueError:
            path = raw
    else:
        path = raw if raw.startswith("/") else "/" + raw
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    return path


_DONE_SCAN_STATUSES = frozenset({"done", "completed", "finished", "imported", "succeeded", "success"})
_SKIP_SCAN_STATUSES = frozenset({
    "queued", "running", "failed", "refused", "cancelled", "canceled", "error", "timeout",
})


def _scan_artifact_dir(run) -> "Path | None":
    from pathlib import Path

    raw = Path((getattr(run, "raw_artifact_uri", None) or "").strip())
    if raw.is_dir():
        return raw
    if raw.suffix and raw.parent.is_dir():
        return raw.parent
    try:
        from attestra import config

        data_dir = Path(getattr(config, "DATA_DIR", "data"))
        fallback = data_dir / "raw" / f"scan-{getattr(run, 'id', '')}"
        if fallback.is_dir():
            return fallback
    except Exception:  # noqa: BLE001 - inventory is best-effort
        return None
    return None


def _js_paths_from_cache(data: Any) -> set[str]:
    paths: set[str] = set()
    if isinstance(data, dict):
        eps = data.get("endpoints") or data.get("endpoints_list") or []
    elif isinstance(data, list):
        eps = data
    else:
        return paths
    for e in eps:
        if isinstance(e, str):
            key = _normalize_endpoint(e)
        elif isinstance(e, dict):
            key = _normalize_endpoint(str(e.get("path") or e.get("url") or ""))
        else:
            continue
        if key:
            paths.add(key)
    return paths


def _collect_scan_inventory(session: Session, engagement_id: int) -> tuple[set[str], set[str], bool]:
    """ZAP URL lists and JS API caches from finished ZAP scans on this engagement.

    Returns (zap_urls, js_paths, zap_authenticated). Failures return empty sets.
    """
    from pathlib import Path

    zap: set[str] = set()
    js: set[str] = set()
    zap_authenticated = False
    try:
        from attestra.models import ScanRun

        runs = list(
            session.scalars(
                select(ScanRun).where(
                    ScanRun.engagement_id == engagement_id,
                    ScanRun.tool == "zap",
                )
            ).all()
        )
    except Exception:  # noqa: BLE001 - snapshot must still return crawl/ledger counts
        return zap, js, False
    for run in runs:
        st = (getattr(run, "status", "") or "").strip().lower()
        if st in _SKIP_SCAN_STATUSES:
            continue
        if st and st not in _DONE_SCAN_STATUSES:
            continue
        folder = _scan_artifact_dir(run)
        if folder is None:
            continue
        urls_file = folder / "zap-urls.txt"
        if urls_file.is_file():
            try:
                for line in urls_file.read_text(encoding="utf-8", errors="replace").splitlines():
                    key = _normalize_endpoint(line)
                    if key:
                        zap.add(key)
            except OSError:
                pass
        js_file = folder / "js-api-endpoints.json"
        if js_file.is_file():
            try:
                data = json.loads(js_file.read_text(encoding="utf-8"))
                js |= _js_paths_from_cache(data)
            except (OSError, TypeError, ValueError):
                pass
        if zap and bool(getattr(run, "authenticated", False)):
            zap_authenticated = True
    return zap, js, zap_authenticated


def _endpoint_sets(
    routes: list,
    ledger_rows: list[dict[str, Any]],
    zap_urls: set[str],
    js_paths: set[str],
) -> tuple[set[str], set[str]]:
    """Union discovered/tested endpoint paths from crawl, ledger, ZAP, and JS discovery."""
    discovered: set[str] = set()
    tested: set[str] = set()
    for r in routes:
        key = _normalize_endpoint(getattr(r, "url", None) or "")
        if not key:
            continue
        discovered.add(key)
        if (getattr(r, "status", "") or "") == "visited":
            tested.add(key)
    for entry in ledger_rows:
        if not isinstance(entry, dict):
            continue
        key = _normalize_endpoint(str(entry.get("target_endpoint") or entry.get("url") or ""))
        if not key:
            continue
        discovered.add(key)
        if _ledger_status_tested(entry):
            tested.add(key)
    for key in zap_urls:
        if key:
            discovered.add(key)
            # ZAP requested and scanned these URLs.
            tested.add(key)
    for key in js_paths:
        if key:
            discovered.add(key)
            # JS discovery alone is not a test; ledger/ZAP may already have marked it tested.
    return discovered, tested


def _authenticated_endpoint_keys(
    routes: list,
    ledger_rows: list[dict[str, Any]],
    zap_urls: set[str],
    zap_authenticated: bool,
) -> set[str]:
    keys: set[str] = set()
    for r in routes:
        if _route_is_authenticated(r):
            key = _normalize_endpoint(getattr(r, "url", None) or "")
            if key:
                keys.add(key)
    for entry in ledger_rows:
        if not isinstance(entry, dict):
            continue
        key = _normalize_endpoint(str(entry.get("target_endpoint") or entry.get("url") or ""))
        if not key:
            continue
        auth = entry.get("auth_context")
        has_auth = False
        if isinstance(auth, dict):
            st = str(auth.get("status") or "").strip().lower()
            has_auth = st in {"ready", "ok"} or bool(auth.get("profile_id") or auth.get("enabled"))
        elif isinstance(auth, str) and auth.strip().lower() not in {"", "none", "anonymous", "unauthenticated"}:
            has_auth = True
        if has_auth:
            keys.add(key)
    if zap_authenticated:
        keys |= {k for k in zap_urls if k}
    return keys


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
    # Count endpoints from crawl inventory PLUS the automated-test ledger,
    # finished ZAP URL lists, and JS-discovered API paths. Auth-crawl routes
    # alone are often empty (SPA / no auth-web crawl), which used to leave
    # endpoints_tested=0 and block QA even after a real ZAP + automated run.
    ledger_rows = _collect_ledger_rows(session, engagement_id)
    snap.ledger_entry_count = len(ledger_rows)
    zap_urls, js_paths, zap_authenticated = _collect_scan_inventory(session, engagement_id)
    discovered, tested = _endpoint_sets(routes, ledger_rows, zap_urls, js_paths)
    snap.endpoints_discovered = len(discovered)
    snap.endpoints_tested = len(tested)
    snap.endpoints_untested = max(0, snap.endpoints_discovered - snap.endpoints_tested)
    snap.coverage_pct_endpoints = (
        round((snap.endpoints_tested / snap.endpoints_discovered) * 100.0, 1)
        if snap.endpoints_discovered
        else 0.0
    )

    auth_keys = _authenticated_endpoint_keys(routes, ledger_rows, zap_urls, zap_authenticated)
    snap.endpoints_authenticated = len(auth_keys & discovered)
    snap.endpoints_unauthenticated = max(0, snap.endpoints_discovered - snap.endpoints_authenticated)

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
