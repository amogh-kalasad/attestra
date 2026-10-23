"""Gated request-tampering / IDOR probes for authenticated website testing.

Plan-only by default. Execution is intrusive-profile only and heavily gated by
the scan scope policy (``intrusive_allowed``, signed authorization, ownership,
window). The default execute path issues read-only GET ID swaps — never exploit
payloads, brute force, or state-changing methods.
"""
# @lat: [[architecture#Authenticated website testing]]
# @lat: [[architecture#Phase 7 gated IDOR / request tampering]]

from __future__ import annotations

import re
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra import audit, config
from attestra.auth_web.roles import IntrusiveProbePlan, plan_object_access_probes
from attestra.auth_web.scope import origin_of
from attestra.fingerprint import fingerprint
from attestra.models import Asset, Finding, utcnow
from attestra.runner import gate, policy
from attestra.services import ServiceError

INTRUSIVE_PROFILES = frozenset({"active", "intrusive"})
MAX_EXECUTE_OBJECT_IDS = 5
DEFAULT_SENSITIVE_MARKERS: tuple[str, ...] = (
    "SENSITIVE",
    "ssn",
    "social security",
    "credit card",
    "card_number",
    "cvv",
    "passport",
    "bank_account",
)
_DENY_STATUSES = frozenset({401, 403, 404})
_REDACTED_BODY = "[REDACTED: sensitive response content withheld]"

FetchFn = Callable[[str], Any]


@dataclass
class TamperRunResult:
    """Plan plus optional execute outcomes for IDOR / object-access probes."""

    plan: IntrusiveProbePlan
    results: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    stopped_reason: str = ""


def _rate_delay_s() -> float:
    rate = float(getattr(config, "AUTH_WEB_RATE_PER_HOST", 2.0) or 2.0)
    return (1.0 / rate) if rate > 0 else 0.5


def assert_intrusive_allowed(
    session: Session,
    engagement_id: int,
    asset_id: int,
    *,
    profile: str,
    actor: str,
) -> None:
    """Refuse unless profile is active/intrusive and the scope policy allows intrusive work.

    Reuses [[attestra/runner/gate.py#policy_input]] / [[attestra/runner/policy.py#decide]]
    facts (``intrusive_allowed``, signed authorization environment, ownership,
    window, rate limit). Raises [[attestra/services.py#ServiceError]] with a clear
    reason otherwise.
    """
    # @lat: [[architecture#Phase 7 gated IDOR / request tampering#assert_intrusive_allowed]]
    prof = (profile or "").strip().lower()
    if prof not in INTRUSIVE_PROFILES:
        raise ServiceError(
            f"request tampering / IDOR probes require profile 'active' or 'intrusive', got {profile!r}"
        )

    # Force profile=active in policy input so intrusive_allowed is enforced for both
    # allowed caller profiles (policy treats only profile=="active" as intrusive for non-nuclei).
    inp = gate.policy_input(session, engagement_id, asset_id, tool="zap", profile="active")
    decision = policy.decide(inp)
    if not decision.allow:
        reason = decision.reason or "refused by scope policy"
        audit.record(session, actor, "scan.refused", "asset", asset_id, reason=reason)
        raise ServiceError(reason)


def _build_url(url_template: str, object_id: str) -> str:
    oid = quote(str(object_id), safe="")
    if "{id}" in url_template:
        return url_template.replace("{id}", oid)
    if "%s" in url_template:
        return url_template.replace("%s", oid)
    raise ValueError("url_template must contain {id} or %s placeholder")


def _normalize_response(resp: Any) -> tuple[int | None, str]:
    if isinstance(resp, tuple) and len(resp) >= 2:
        status = resp[0]
        body = resp[1]
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")
        return (int(status) if status is not None else None), str(body or "")
    status = getattr(resp, "status_code", None)
    body = getattr(resp, "text", None)
    if body is None:
        raw = getattr(resp, "content", b"")
        if isinstance(raw, bytes):
            body = raw.decode("utf-8", errors="replace")
        else:
            body = str(raw or "")
    return (int(status) if status is not None else None), str(body or "")


def _find_sensitive_marker(body: str, markers: Sequence[str]) -> str | None:
    if not body:
        return None
    low = body.lower()
    for marker in markers:
        m = (marker or "").strip()
        if m and m.lower() in low:
            return m
    return None


def _assert_probe_in_asset_origin(asset: Asset, url: str) -> None:
    try:
        asset_origin = origin_of(asset.identifier)
        probe_origin = origin_of(url)
    except Exception as exc:  # ScopeError / ValueError
        raise ServiceError(f"probe URL out of scope: {url!r}") from exc
    if asset_origin != probe_origin:
        raise ServiceError(
            f"probe URL origin {probe_origin!r} is outside asset origin {asset_origin!r}"
        )


def _maybe_finding(
    session: Session,
    engagement_id: int,
    asset_id: int,
    *,
    url: str,
    object_id: str,
    confidence: str,
    create: bool,
) -> Finding | None:
    if not create:
        return None
    title = "Broken object-level authorization (IDOR)"
    remediation = (
        "Enforce object-level authorization on every request; deny cross-user object "
        "IDs with 403/404; do not rely on ID obscurity. Retest after access-control fixes."
    )
    fp = fingerprint(
        location=url,
        cwe=639,
        cves=[],
        title=title,
        param="id",
        asset_id=asset_id,
        variant="idor",
    )
    existing = session.scalars(
        select(Finding).where(Finding.engagement_id == engagement_id, Finding.fingerprint == fp)
    ).first()
    if existing is not None:
        return existing
    finding = Finding(
        engagement_id=engagement_id,
        asset_id=asset_id,
        fingerprint=fp,
        title=title,
        description=(
            f"Authenticated read-only GET for object_id={object_id!r} at {url} returned "
            f"another principal's data (confidence={confidence}). Synthetic probe evidence only."
        ),
        recommendation=remediation,
        impact="Unauthorized access to another user's object may expose personal or confidential data.",
        affected_urls=[url],
        tools=["auth_web_tamper"],
        rule_ids=["idor-object-access"],
        cwe=639,
        location=url[:1000],
        severity="high",
        owasp_top10="A01:2021",
        asvs_ref="V4.1",
        wstg_ref="WSTG-ATHZ-04",
        first_seen=utcnow(),
        last_seen=utcnow(),
    )
    session.add(finding)
    session.flush()
    return finding


def plan_and_maybe_execute_probes(
    session: Session,
    engagement_id: int,
    asset_id: int,
    *,
    profile: str,
    actor: str,
    object_ids: list[str] | tuple[str, ...],
    url_template: str,
    execute: bool = False,
    fetch_fn: FetchFn | None = None,
    sensitive_markers: Sequence[str] | None = None,
    create_findings: bool = False,
    rate_delay_s: float | None = None,
) -> TamperRunResult:
    """Build an intrusive IDOR probe plan; optionally run bounded read-only GETs.

    Always builds via [[attestra/auth_web/roles.py#plan_object_access_probes]] with
    ``intrusive=True``. When ``execute`` is False (default), returns the plan only
    with zero network IO. When ``execute`` is True, calls
    [[attestra/auth_web/tamper.py#assert_intrusive_allowed]] first, caps at
    ``MAX_EXECUTE_OBJECT_IDS`` GETs with a rate delay, swaps object IDs into the
    template, and stops+redacts if another user's sensitive data appears.
    """
    # @lat: [[architecture#Phase 7 gated IDOR / request tampering#plan_and_maybe_execute_probes]]
    plan = plan_object_access_probes(url_template, object_ids, intrusive=True)
    out = TamperRunResult(plan=plan)
    if not execute:
        return out

    assert_intrusive_allowed(session, engagement_id, asset_id, profile=profile, actor=actor)
    if fetch_fn is None:
        raise ServiceError("execute=True requires a fetch_fn (no default network client)")

    asset = session.get(Asset, asset_id)
    if asset is None or asset.engagement_id != engagement_id:
        raise ServiceError("asset not found for engagement")

    markers = tuple(sensitive_markers) if sensitive_markers is not None else DEFAULT_SENSITIVE_MARKERS
    delay = _rate_delay_s() if rate_delay_s is None else max(0.0, float(rate_delay_s))
    ids = list(plan.object_ids)[:MAX_EXECUTE_OBJECT_IDS]

    for index, oid in enumerate(ids):
        url = _build_url(plan.url_template, oid)
        _assert_probe_in_asset_origin(asset, url)

        # Read-only GET probes only — never POST/PUT/PATCH/DELETE or exploit payloads.
        resp = fetch_fn(url)
        status, body = _normalize_response(resp)

        row: dict[str, Any] = {
            "object_id": oid,
            "url": url,
            "expected": "deny",
            "observed": status,
            "status": "unknown",
            "redacted": False,
        }

        marker = _find_sensitive_marker(body, markers)
        if marker:
            row["observed"] = status
            row["status"] = "sensitive_stop"
            row["redacted"] = True
            row["body_preview"] = _REDACTED_BODY
            row["sensitive_marker"] = marker
            out.results.append(row)
            finding = _maybe_finding(
                session,
                engagement_id,
                asset_id,
                url=url,
                object_id=oid,
                confidence="high",
                create=create_findings,
            )
            if finding is not None:
                out.findings.append(finding)
            out.stopped_reason = f"sensitive marker {marker!r} in response; remaining probes skipped"
            break

        if status in _DENY_STATUSES:
            row["status"] = "denied"
        elif status == 200:
            # Successful read of another object's resource under this session.
            row["status"] = "possible_idor"
            row["body_preview"] = re.sub(r"\s+", " ", body)[:120]
            finding = _maybe_finding(
                session,
                engagement_id,
                asset_id,
                url=url,
                object_id=oid,
                confidence="medium",
                create=create_findings,
            )
            if finding is not None:
                out.findings.append(finding)
        elif status is None:
            row["status"] = "error"
        else:
            row["status"] = "other"

        out.results.append(row)
        if index + 1 < len(ids) and delay > 0:
            time.sleep(delay)

    return out
