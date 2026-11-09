"""T22 body-level object manipulation (BOLA / mass-assignment on write methods).

OFF by default. Actual POST/PUT/PATCH sends require ATTESTRA_AUTOMATED_VAPT_MUTATION=1
and an allowlisted APP_ENV (local/test/development). Never DELETE. Cap + rate-limit.
Dry-run (mutation disabled or dry_run=True) only records what would be sent.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from attestra.automated_vapt.core import js_api_discovery as jsd
from attestra.automated_vapt.core.replay_checks import (
    CaptureResult,
    EndpointOutcome,
    DEFAULT_SLEEP_S,
    SKIP_APP_ENV_BLOCKED,
    SKIP_MUTATION_DISABLED,
    SKIP_NO_AUTH_SESSION,
    SKIP_NO_WRITE_TEMPLATES,
    _build_scope,
    _endpoints_from_ctx,
    _origin,
    harvest_ids,
    neighbour_ids,
    responses_similar,
)
from attestra.automated_vapt.core.session_auth import SessionAuth

DEFAULT_MUTATION_CAP = 20

# Fields we will swap in JSON bodies (id-like + common resource name keys).
_BODY_ID_KEY_RE = re.compile(
    r'"(?P<k>project_id|projectId|project_name|projectName|'
    r'client_id|clientId|client_name|clientName|'
    r'user_id|userId|user_name|userName|username|'
    r'tenant_id|tenantId|account_id|accountId|'
    r'stakeholder_id|stakeholderId|member_id|memberId|'
    r'org_id|orgId|workspace_id|workspaceId|'
    r'[A-Za-z][A-Za-z0-9_]*[Ii][Dd]|[A-Za-z][A-Za-z0-9_]*_id|'
    r'(?<![A-Za-z0-9_])id)"\s*:\s*'
    r'(?:"(?P<s>[^"]{0,128})"'
    r"|(?P<n>-?\d{1,18})"
    r"|(?P<null>null))",
    re.I,
)

# Path/action words that look create/delete/transfer — skip even when mutation on.
_SKIP_ACTION_RE = re.compile(
    r"(?i)(delete|remove|destroy|revoke|transfer|close|reset|create|register|"
    r"sign-?up|upload|import|execute|trigger|cancel|approve|reject|logout|"
    r"sign-?out|unsubscribe|disconnect|purge|drop|truncate)"
)

_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH"})


def mutation_flag_enabled() -> bool:
    from attestra import config

    return bool(getattr(config, "AUTOMATED_VAPT_MUTATION", False))


def mutation_sends_allowed() -> bool:
    """True only when mutation flag is on AND APP_ENV is local/test/development."""
    if not mutation_flag_enabled():
        return False
    from attestra import config

    env = config.parse_app_env() if hasattr(config, "parse_app_env") else getattr(config, "APP_ENV", None)
    allow = getattr(config, "_APP_ENV_BYPASS_ALLOWLIST", frozenset({"local", "test", "development"}))
    return env in allow


def find_body_id_fields(text: str) -> list[tuple[str, str, str]]:
    """Return list of (raw_key, canonical_key, value) for id-like JSON fields."""
    out: list[tuple[str, str, str]] = []
    for m in _BODY_ID_KEY_RE.finditer(text or ""):
        raw = m.group("k") or ""
        key = re.sub(r"([a-z])([A-Z])", r"\1_\2", raw).lower()
        if m.group("s") is not None:
            val = m.group("s")
        elif m.group("n") is not None:
            val = m.group("n")
        elif m.group("null") is not None:
            val = "null"
        else:
            val = ""
        # Keep empty/null keys: SPA often posts projectName:null before selection.
        out.append((raw, key, val))
    return out


def swap_body_ids(body: str, foreign_id: str, *, keys: set[str] | None = None) -> tuple[str, list[str]]:
    """Replace id-like field values with ``foreign_id``. Returns (new_body, changed_keys)."""
    changed: list[str] = []

    def repl(m: re.Match[str]) -> str:
        raw = m.group("k") or ""
        canon = re.sub(r"([a-z])([A-Z])", r"\1_\2", raw).lower()
        if keys is not None and canon not in keys and raw not in keys:
            return m.group(0)
        changed.append(raw)
        # Prefer quoted string for null/empty/name fields; numeric when both sides numeric.
        if m.group("n") is not None:
            try:
                int(foreign_id)
                return f'"{raw}": {foreign_id}'
            except ValueError:
                return f'"{raw}": "{foreign_id}"'
        return f'"{raw}": "{foreign_id}"'

    new = _BODY_ID_KEY_RE.sub(repl, body or "")
    return new, changed


def _looks_json(body: str) -> bool:
    s = (body or "").strip()
    return s.startswith("{") or s.startswith("[")


def _skip_url(url: str) -> bool:
    path = urlsplit(url).path or url
    return bool(_SKIP_ACTION_RE.search(path))


def collect_write_templates(ctx: Any) -> list[dict[str, Any]]:
    """Gather POST/PUT/PATCH templates from extras and captured http pairs."""
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(method: str, url: str, body: str, headers: dict | None = None) -> None:
        method_u = (method or "").upper()
        if method_u not in _WRITE_METHODS:
            return
        if not url or _skip_url(url):
            return
        if not _looks_json(body):
            return
        if not find_body_id_fields(body):
            return
        # same origin only
        root = ctx.target_base_url
        if _origin(url) != _origin(root):
            return
        key = (method_u, urlsplit(url).path)
        if key in seen:
            return
        seen.add(key)
        out.append(
            {
                "method": method_u,
                "url": url,
                "body": body,
                "headers": dict(headers or {}),
            }
        )

    # In-memory captures from T02 / tests
    for item in ctx.extra.get("_write_captures") or []:
        if isinstance(item, dict):
            add(
                str(item.get("method") or ""),
                str(item.get("url") or ""),
                str(item.get("body") or item.get("request_body") or ""),
                item.get("headers") or item.get("request_headers"),
            )

    # Persisted captures from this (or newest same-host) automated run
    try:
        from attestra.automated_vapt.capture import write_body_capture as wbc
        from urllib.parse import urlsplit as _urlsplit

        xid = int(ctx.extra.get("execution_id") or 0)
        host = _urlsplit(ctx.target_base_url).hostname or ""
        disk_items = wbc.load_newest_write_bodies_for_host(host, prefer_execution_id=xid or None)
        for item in disk_items:
            add(
                str(item.get("method") or ""),
                str(item.get("url") or ""),
                str(item.get("body") or item.get("request_body") or ""),
                item.get("headers") or item.get("request_headers"),
            )
    except Exception:  # noqa: BLE001
        pass

    for pair in ctx.extra.get("_http_pairs") or []:
        if hasattr(pair, "method"):
            add(pair.method, pair.url, getattr(pair, "request_body", "") or "", getattr(pair, "request_headers", None))
        elif isinstance(pair, dict):
            add(
                str(pair.get("method") or ""),
                str(pair.get("url") or ""),
                str(pair.get("request_body") or ""),
                pair.get("request_headers"),
            )

    return out


def _do_write(
    method: str,
    url: str,
    *,
    body: str,
    headers: dict[str, str] | None,
    scope: Any,
    profile: str,
    client: Any | None,
    check_dns: bool,
    auth: SessionAuth | None,
) -> CaptureResult:
    from attestra.automated_vapt.capture.http_capture import capture_request

    try:
        tx = capture_request(
            method,
            url,
            scope=scope,
            profile=profile,
            headers=headers or None,
            content=body.encode("utf-8") if isinstance(body, str) else body,
            client=client,
            check_dns=check_dns,
            allow_mutation_methods=True,
        )
    except Exception as exc:  # noqa: BLE001
        detail = str(exc)
        if auth is not None:
            detail = auth.scrub(detail)
        return CaptureResult(url=url, status=None, body="", error=detail)

    report = tx.report_pair or tx.pair.redacted()
    if auth is not None and auth.redact_values:
        report.response_body = auth.scrub(report.response_body)
        report.request_body = auth.scrub(report.request_body)
        report.request_headers = {k: auth.scrub(v) for k, v in report.request_headers.items()}
        report.response_headers = {k: auth.scrub(v) for k, v in report.response_headers.items()}
        tx.report_pair = report
    body_text = report.response_body or ""
    if len(body_text) > 8192:
        body_text = body_text[:8192]
    return CaptureResult(
        url=url,
        status=report.status,
        body=body_text,
        pair=tx.report_pair or tx.pair,
        error="",
    )


def _foreign_reflected(body: str, foreign_id: str) -> bool:
    if not foreign_id:
        return False
    return foreign_id in (body or "")


def _mutation_finding(orig: CaptureResult, probe: CaptureResult, foreign_id: str) -> tuple[bool, str]:
    """True when server appears to accept the modified object as owned."""
    if probe.status is None or probe.error:
        return False, "probe error"
    if probe.status < 200 or probe.status >= 300:
        return False, f"rejected HTTP {probe.status}"
    # 2xx with foreign id reflected, or response similar to successful original with changed id present
    if _foreign_reflected(probe.body, foreign_id):
        return True, f"HTTP {probe.status} reflected foreign id in body"
    if orig.substantive and responses_similar(orig, probe) and probe.status == orig.status:
        return True, f"HTTP {probe.status} accepted modified body (response similar to original)"
    return False, f"HTTP {probe.status} no clear accept signal"


def run_object_mutation(
    ctx: Any,
    *,
    cap: int = DEFAULT_MUTATION_CAP,
    sleep_s: float = DEFAULT_SLEEP_S,
    clock_sleep: Callable[[float], None] = time.sleep,
    dry_run: bool | None = None,
) -> dict[str, Any]:
    """T22: body-level object id swap on captured POST/PUT/PATCH (guarded)."""
    auth: SessionAuth | None = ctx.extra.get("_session_auth")
    auth_info = auth.public() if auth is not None else {"profile_id": None, "status": "none", "note": "", "injected": []}
    secondary: SessionAuth | None = ctx.extra.get("_secondary_session_auth")
    secondary_info = (
        secondary.public() if secondary is not None else {"profile_id": None, "status": "none", "note": "not configured"}
    )

    sends_ok = mutation_sends_allowed()
    if dry_run is None:
        dry_run = not sends_ok

    base_meta = {
        "mutation_flag": mutation_flag_enabled(),
        "mutation_sends_allowed": sends_ok,
        "dry_run": dry_run,
        "secondary_auth": secondary_info,
        "idor_confidence_note": (
            "secondary login profile in use for write probes"
            if secondary is not None and secondary.status == "ready"
            else "no secondary (non-admin) login profile configured; admin-only probes — confirm IDOR manually"
        ),
    }

    if auth is None or auth.status != "ready":
        return {
            "test_id": "T22",
            "status": "SKIPPED",
            "detail": f"login profile not ready ({auth_info.get('status')}: {auth_info.get('note')})",
            "skip_reason": SKIP_NO_AUTH_SESSION,
            "category": "authorization",
            "auth": auth_info,
            "mutation": base_meta,
            "endpoints": [],
            "validation": {},
        }

    templates = collect_write_templates(ctx)
    # Also note write methods from JS discovery (may lack bodies)
    write_eps = [
        e
        for e in _endpoints_from_ctx(ctx)
        if e.methods & _WRITE_METHODS and not _SKIP_ACTION_RE.search(e.path)
    ]

    if not templates:
        detail = (
            "no captured POST/PUT/PATCH JSON bodies with object-id fields to mutate"
        )
        if write_eps:
            detail += f"; JS discovery listed {len(write_eps)} write endpoint(s) but no request bodies were captured"
        if not mutation_flag_enabled():
            detail += (
                "; ATTESTRA_AUTOMATED_VAPT_MUTATION is disabled (default) — "
                "enable =1 with APP_ENV=local|test|development to allow sends"
            )
            reason = SKIP_MUTATION_DISABLED if not write_eps else SKIP_NO_WRITE_TEMPLATES
        elif not sends_ok:
            detail += "; APP_ENV is not in local/test/development allowlist"
            reason = SKIP_APP_ENV_BLOCKED
        else:
            reason = SKIP_NO_WRITE_TEMPLATES
        return {
            "test_id": "T22",
            "status": "SKIPPED",
            "detail": detail,
            "skip_reason": reason,
            "category": "authorization",
            "auth": auth_info,
            "mutation": {
                **base_meta,
                "write_endpoints_discovered": [e.path for e in write_eps[:30]],
                "templates": 0,
                "planned": [],
            },
            "endpoints": [],
            "validation": {},
        }

    # Harvest owned ids from shared T01 inventory, GET seed URLs, and template bodies
    owned: set[str] = set()
    harvested: dict[str, set[str]] = {}
    for k, vals in (ctx.extra.get("_harvested_ids") or {}).items():
        harvested.setdefault(str(k), set()).update(vals)
    for tmpl in templates:
        for _raw, canon, val in find_body_id_fields(tmpl["body"]):
            harvested.setdefault(canon, set()).add(val)
            owned.add(val)
    for vals in harvested.values():
        owned |= vals

    foreign = neighbour_ids(owned, span=3) if owned else []
    if not foreign:
        foreign = [f"attestra-mut-{i}" for i in range(1, 4)]

    # Prefer secondary auth for the mutated probe when available
    probe_auth = secondary if (secondary is not None and secondary.status == "ready") else auth

    planned: list[dict[str, Any]] = []
    outcomes: list[EndpointOutcome] = []
    evidence: list[Any] = []
    findings = 0
    requests_left = cap
    client = ctx.extra.get("httpx_client")

    for tmpl in templates:
        if requests_left <= 0:
            break
        method = tmpl["method"]
        url = tmpl["url"]
        body = tmpl["body"]
        fid = foreign[0]
        new_body, changed = swap_body_ids(body, fid)
        if not changed:
            continue
        plan = {
            "method": method,
            "url": url,
            "fields": changed,
            "foreign_id": fid,
            "body_bytes": len(new_body.encode("utf-8")),
            "would_send": True,
        }
        planned.append(plan)

        if dry_run or not sends_ok:
            outcomes.append(
                EndpointOutcome(
                    url=url,
                    check="object_mutation",
                    status="SKIPPED",
                    detail=(
                        f"dry-run: would {method} with {changed} -> {fid}"
                        + ("" if mutation_flag_enabled() else " (mutation disabled)")
                    ),
                    finding=False,
                    meta={"plan": plan, "dry_run": True},
                )
            )
            continue

        # Live send path (mutation enabled + allowlisted env)
        scope = _build_scope(ctx, [url])
        headers = dict(tmpl.get("headers") or {})
        # overlay session auth for target origin
        headers.update(auth.headers_for(url, ctx.target_base_url))
        if "content-type" not in {k.lower() for k in headers}:
            headers["Content-Type"] = "application/json"

        # baseline with original body (still a write — only when mutation on)
        orig = _do_write(
            method,
            url,
            body=body,
            headers=headers,
            scope=scope,
            profile=getattr(ctx, "profile", "baseline") or "baseline",
            client=client,
            check_dns=not getattr(ctx, "allow_private", False),
            auth=auth,
        )
        requests_left -= 1
        clock_sleep(sleep_s)
        if orig.pair is not None:
            evidence.append(orig.pair)

        if requests_left <= 0:
            break

        probe_headers = dict(headers)
        probe_headers.update(probe_auth.headers_for(url, ctx.target_base_url))
        probe = _do_write(
            method,
            url,
            body=new_body,
            headers=probe_headers,
            scope=scope,
            profile=getattr(ctx, "profile", "baseline") or "baseline",
            client=client,
            check_dns=not getattr(ctx, "allow_private", False),
            auth=probe_auth,
        )
        requests_left -= 1
        clock_sleep(sleep_s)
        if probe.pair is not None:
            evidence.append(probe.pair)

        is_find, why = _mutation_finding(orig, probe, fid)
        # Admin-only -> POTENTIAL; with secondary -> can be CONFIRMED-ish
        if is_find:
            findings += 1
            outcomes.append(
                EndpointOutcome(
                    url=url,
                    check="object_mutation",
                    status="FINDING",
                    detail=why,
                    auth_status=orig.status,
                    probe_status=probe.status,
                    finding=True,
                    evidence_pairs=[p for p in (orig.pair, probe.pair) if p is not None],
                    meta={
                        "method": method,
                        "fields": changed,
                        "foreign_id": fid,
                        "secondary_used": probe_auth is secondary,
                    },
                )
            )
        else:
            outcomes.append(
                EndpointOutcome(
                    url=url,
                    check="object_mutation",
                    status="PASSED",
                    detail=why,
                    auth_status=orig.status,
                    probe_status=probe.status,
                    finding=False,
                    evidence_pairs=[p for p in (orig.pair, probe.pair) if p is not None],
                    meta={"method": method, "fields": changed, "foreign_id": fid},
                )
            )

    skip_reason = ""
    if dry_run or not sends_ok:
        status = "SKIPPED"
        detail = (
            f"dry-run planned {len(planned)} mutation(s) across {len(templates)} template(s); "
            "no requests sent"
        )
        if not mutation_flag_enabled():
            detail += (
                ". ATTESTRA_AUTOMATED_VAPT_MUTATION is disabled — set to 1 with "
                "APP_ENV=local|test|development and restart serve/worker to enable sends"
            )
            skip_reason = SKIP_MUTATION_DISABLED
        elif not sends_ok:
            detail += ". mutation flag on but APP_ENV is not in local/test/development allowlist"
            skip_reason = SKIP_APP_ENV_BLOCKED
        else:
            skip_reason = SKIP_MUTATION_DISABLED
        validation: dict[str, Any] = {}
    elif findings:
        status = "FINDING"
        confidence = "medium" if (secondary is not None and secondary.status == "ready") else "low"
        detail = (
            f"object mutation: {findings} finding(s) across {len(outcomes)} probe(s); "
            f"auth: {auth_info['status']} (profile #{auth_info.get('profile_id')})"
        )
        validation = {
            "status": "POTENTIAL" if confidence == "low" else "CONFIRMED",
            "confidence": confidence,
            "reasons": [o.detail for o in outcomes if o.finding],
            "recommendation": (
                "Verify object-level authorization on write endpoints; "
                "reject foreign ids / cross-tenant body fields server-side."
            ),
        }
    else:
        status = "PASSED"
        detail = (
            f"object mutation: 0 finding(s) across {len(outcomes)} probe(s); "
            f"auth: {auth_info['status']} (profile #{auth_info.get('profile_id')})"
        )
        validation = {}

    finding_pairs = [p for o in outcomes if o.finding for p in o.evidence_pairs]
    out: dict[str, Any] = {
        "test_id": "T22",
        "status": status,
        "detail": detail,
        "category": "authorization",
        "auth": auth_info,
        "mutation": {**base_meta, "templates": len(templates), "planned": planned[:40]},
        "endpoints": [o.to_dict() for o in outcomes],
        "finding_count": findings,
        "validation": validation,
        "evidence_pairs": evidence,
        "finding_evidence_pairs": finding_pairs,
        "finding_title": "Body-level BOLA / object manipulation on API writes" if findings else "",
        "finding_location": next((o.url for o in outcomes if o.finding), ctx.target_base_url),
        "finding_cwe": 639,
        "finding_recommendation": validation.get("recommendation", ""),
    }
    if status == "SKIPPED":
        out["skip_reason"] = skip_reason if dry_run or not sends_ok else SKIP_NO_WRITE_TEMPLATES
    return out
