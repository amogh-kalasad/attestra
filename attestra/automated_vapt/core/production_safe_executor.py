"""Execute an approved production safe-mutation against a synthetic test record.

Consumes the one-time approval, captures before/after evidence, applies only
approved fields/values, restores via the approved cleanup plan semantics
(baseline values), and verifies restoration. Fail-closed: restoration failure
stops further mutations and records the failure on the approval.
"""
# @lat: [[run-validity-and-policy#Intrusive policy]]

from __future__ import annotations

import json
import logging
from typing import Any, Callable
from urllib.parse import urljoin

from attestra.automated_vapt.core import mutation_approval as ma

log = logging.getLogger(__name__)

HttpGet = Callable[[str, dict[str, str] | None], tuple[int, dict[str, Any] | None, str]]
HttpWrite = Callable[[str, str, dict[str, Any], dict[str, str] | None], tuple[int, dict[str, Any] | None, str]]


class ProductionSafeExecutionError(RuntimeError):
    """Mutation or restoration failed; workflow must stop."""


def _json_body(status: int, data: dict[str, Any] | None, text: str) -> dict[str, Any]:
    return {"status": status, "json": data, "text": (text or "")[:4000]}


def execute_approved_mutation(
    *,
    store: ma.ApprovalStore,
    engagement_id: int,
    tenant_id: int,
    asset_id: int,
    approval_id: str,
    nonce: str,
    headers: dict[str, str] | None = None,
    http_get: HttpGet | None = None,
    http_write: HttpWrite | None = None,
    baseline_values: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Full lifecycle for one approved synthetic mutation.

    ``baseline_values`` is the pre-approved restoration snapshot (required for
    verification). When omitted, before-state GET is used as baseline.
    """
    if not ma.production_safe_mutation_enabled():
        raise ProductionSafeExecutionError("production_safe_mutation_flag_off")

    row = store.get(engagement_id, approval_id)
    if row is None:
        raise ProductionSafeExecutionError("approval_not_found")
    if int(row.tenant_id) != int(tenant_id) or int(row.asset_id) != int(asset_id):
        raise ProductionSafeExecutionError("scope_mismatch")

    ok, reason = ma.validate_grant_for_execution(
        row,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        asset_id=asset_id,
        target_origin=row.target_origin,
        endpoint=row.endpoint_pattern,
        http_method=row.http_method,
        test_record_id=row.test_record_id,
        fields=list(row.approved_fields),
    )
    if not ok:
        raise ProductionSafeExecutionError(reason)

    # Atomic consume before any write
    consumed = ma.consume_approval(
        store,
        engagement_id=engagement_id,
        approval_id=approval_id,
        nonce=nonce or row.nonce,
        tenant_id=tenant_id,
    )

    url = urljoin(row.target_origin.rstrip("/") + "/", row.endpoint_pattern.lstrip("/"))
    evidence: dict[str, Any] = {
        "approval_id": consumed.id,
        "url": url,
        "method": row.http_method,
        "test_record_id": row.test_record_id,
        "approved_fields": list(row.approved_fields),
    }

    if http_get is None or http_write is None:
        raise ProductionSafeExecutionError("http_transport_required")

    # Before state
    st, before_json, before_text = http_get(url, headers)
    evidence["before"] = _json_body(st, before_json, before_text)
    if st >= 400 or before_json is None:
        raise ProductionSafeExecutionError("before_state_unavailable")

    baseline = dict(baseline_values) if baseline_values is not None else {
        k: before_json.get(k) for k in row.approved_fields if k in before_json
    }
    evidence["baseline"] = baseline

    # Ensure record id matches
    for key in ("id", "record_id", "test_record_id"):
        if key in before_json and str(before_json.get(key)) != row.test_record_id:
            if key in row.approved_fields or key == "id":
                raise ProductionSafeExecutionError("record_mismatch")

    mutation_body = ma.apply_approved_values(
        before_json if isinstance(before_json, dict) else {},
        approved_fields=list(row.approved_fields),
        approved_values=dict(row.approved_values or {}),
        test_record_id=row.test_record_id,
    )
    evidence["mutation_body"] = mutation_body

    st2, after_write_json, after_write_text = http_write(row.http_method, url, mutation_body, headers)
    evidence["mutation_response"] = _json_body(st2, after_write_json, after_write_text)

    # After-state GET
    st3, after_json, after_text = http_get(url, headers)
    evidence["after"] = _json_body(st3, after_json, after_text)

    # Restoration: write baseline back for approved fields only
    restore_body = {k: baseline.get(k) for k in row.approved_fields if k in baseline}
    for key in ("id", "record_id", "test_record_id"):
        if key in row.approved_fields:
            restore_body[key] = row.test_record_id
    evidence["restore_body"] = restore_body
    st4, restore_json, restore_text = http_write(row.http_method, url, restore_body, headers)
    evidence["restore_response"] = _json_body(st4, restore_json, restore_text)

    st5, verified_json, verified_text = http_get(url, headers)
    evidence["verified"] = _json_body(st5, verified_json, verified_text)

    verified = True
    notes = []
    if st5 >= 400 or verified_json is None:
        verified = False
        notes.append("verification GET failed")
    else:
        for k, expected in baseline.items():
            if verified_json.get(k) != expected:
                verified = False
                notes.append(f"field {k} not restored")

    ma.record_restore_result(
        store,
        engagement_id=engagement_id,
        approval_id=approval_id,
        verified=verified,
        notes="; ".join(notes) or ("restored" if verified else "restoration failed"),
    )
    evidence["restore_verified"] = verified
    evidence["restore_notes"] = "; ".join(notes)

    if not verified:
        raise ProductionSafeExecutionError("restoration_verification_failed")

    return {
        "status": "PASSED",
        "detail": "production safe-mutation executed and restored on synthetic record",
        "evidence": evidence,
        "approval_id": approval_id,
        "test_record_id": row.test_record_id,
    }


def build_httpx_transport(client: Any) -> tuple[HttpGet, HttpWrite]:
    """Adapt an httpx-like client into get/write callables."""

    def _get(url: str, headers: dict[str, str] | None):
        r = client.request("GET", url, headers=headers or {})
        try:
            data = r.json()
            if not isinstance(data, dict):
                data = None
        except Exception:
            data = None
        return int(r.status_code), data, getattr(r, "text", "") or ""

    def _write(method: str, url: str, body: dict[str, Any], headers: dict[str, str] | None):
        m = (method or "PATCH").upper()
        if m == "DELETE":
            raise ProductionSafeExecutionError("delete_forbidden")
        r = client.request(m, url, json=body, headers=headers or {})
        try:
            data = r.json()
            if not isinstance(data, dict):
                data = None
        except Exception:
            data = None
        return int(r.status_code), data, getattr(r, "text", "") or ""

    return _get, _write
