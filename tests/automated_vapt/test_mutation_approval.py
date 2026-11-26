"""Gap #3: supervised production safe-mutation approvals (isolated fixtures)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from attestra.automated_vapt.core import intrusive_policy as ip
from attestra.automated_vapt.core import mutation_approval as ma


@pytest.fixture
def store(tmp_path: Path):
    return ma.ApprovalStore(tmp_path / "approvals")


def _request(store, **over):
    kwargs = dict(
        tenant_id=1,
        engagement_id=7,
        asset_id=3,
        requester="alice.tester",
        requester_user_id=10,
        requester_role="tester",
        target_origin="https://app.example.com",
        endpoint_pattern="/api/test-records/demo-1",
        http_method="PATCH",
        test_record_id="demo-1",
        approved_fields=["display_name", "id"],
        approved_values={"display_name": "attestra-mut-safe"},
        cleanup_plan="PATCH display_name back to baseline; verify GET equals baseline",
        ttl_minutes=30,
    )
    kwargs.update(over)
    return ma.request_approval(store, **kwargs)


def _inp(env: str = "production", **over):
    doc = {
        "asset_environment": env,
        "authorized_environments": [env, "staging"],
        "intrusive_allowed": True,
        "engagement_status": "active",
        "profile": "active",
    }
    doc.update(over)
    return doc


def _allow(_inp):
    from types import SimpleNamespace

    return SimpleNamespace(allow=True, reason="")


# @lat: [[run-validity-and-policy#Intrusive policy]]
def test_production_safe_mutation_disabled_by_default(monkeypatch):
    monkeypatch.setattr(ma, "production_safe_mutation_enabled", lambda: False)
    d = ip.decide_from_policy_input(
        _inp(),
        test_id="T22",
        profile="active",
        env_flag_enabled=True,
        policy_decide=_allow,
        allowed=frozenset({"dev", "demo"}),
        production_grant={"ok": True, "reason": "allowed", "cleanup_plan": "restore", "approval_id": "x"},
    )
    assert d.allow is False
    assert d.reason == ip.R_PROD_SAFE_DENIED


def test_ordinary_production_still_forbidden_without_grant():
    d = ip.decide_from_policy_input(
        _inp(),
        test_id="T22",
        profile="active",
        env_flag_enabled=True,
        policy_decide=_allow,
        allowed=frozenset({"dev", "demo"}),
    )
    assert d.reason == ip.R_ENV_FORBIDDEN


def test_ssrf_production_forbidden_even_with_grant(monkeypatch):
    monkeypatch.setattr(ma, "production_safe_mutation_enabled", lambda: True)
    d = ip.decide_from_policy_input(
        _inp(),
        test_id="SSRF",
        profile="active",
        env_flag_enabled=True,
        policy_decide=_allow,
        allowed=frozenset({"dev", "demo"}),
        production_grant={"ok": True, "reason": "allowed", "cleanup_plan": "restore"},
    )
    assert d.reason == ip.R_ENV_FORBIDDEN


def test_dev_mutation_unaffected(monkeypatch):
    monkeypatch.setattr(ma, "production_safe_mutation_enabled", lambda: False)
    d = ip.decide_from_policy_input(
        _inp("dev"),
        test_id="T22",
        profile="active",
        env_flag_enabled=True,
        policy_decide=_allow,
        allowed=frozenset({"dev", "demo"}),
    )
    assert d.allow is True and d.reason == ip.R_ALLOWED


def test_requester_cannot_self_approve(store):
    row = _request(store)
    with pytest.raises(ma.MutationApprovalError, match="cannot approve"):
        ma.approve_approval(
            store,
            engagement_id=7,
            approval_id=row.id,
            approver="alice.tester",
            approver_user_id=10,
            approver_role="lead",
        )


def test_four_eyes_approve_and_consume(store, monkeypatch):
    monkeypatch.setattr(ma, "production_safe_mutation_enabled", lambda: True)
    row = _request(store)
    approved = ma.approve_approval(
        store,
        engagement_id=7,
        approval_id=row.id,
        approver="bob.lead",
        approver_user_id=20,
        approver_role="lead",
    )
    assert approved.status == ma.STATUS_APPROVED
    ok, reason = ma.validate_grant_for_execution(
        approved,
        tenant_id=1,
        engagement_id=7,
        asset_id=3,
        target_origin="https://app.example.com/x",
        endpoint="/api/test-records/demo-1",
        http_method="PATCH",
        test_record_id="demo-1",
        fields=["display_name"],
    )
    assert ok and reason == "allowed"
    consumed = ma.consume_approval(store, engagement_id=7, approval_id=row.id, nonce=approved.nonce)
    assert consumed.status == ma.STATUS_CONSUMED
    with pytest.raises(ma.MutationApprovalError, match="consumed"):
        ma.consume_approval(store, engagement_id=7, approval_id=row.id, nonce=approved.nonce)


def test_expired_approval_rejected(store, monkeypatch):
    monkeypatch.setattr(ma, "production_safe_mutation_enabled", lambda: True)
    row = _request(store, ttl_minutes=30)
    past = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
    store.update(7, row.id, expires_at=past)
    with pytest.raises(ma.MutationApprovalError, match="expired"):
        ma.approve_approval(
            store,
            engagement_id=7,
            approval_id=row.id,
            approver="bob.lead",
            approver_user_id=20,
            approver_role="lead",
        )


def test_asset_endpoint_record_field_mismatches(store, monkeypatch):
    monkeypatch.setattr(ma, "production_safe_mutation_enabled", lambda: True)
    row = _request(store)
    approved = ma.approve_approval(
        store,
        engagement_id=7,
        approval_id=row.id,
        approver="bob.lead",
        approver_user_id=20,
        approver_role="lead",
    )
    base = dict(
        tenant_id=1,
        engagement_id=7,
        asset_id=3,
        target_origin="https://app.example.com",
        endpoint="/api/test-records/demo-1",
        http_method="PATCH",
        test_record_id="demo-1",
    )
    assert ma.validate_grant_for_execution(approved, **{**base, "asset_id": 99})[1] == "asset_mismatch"
    assert ma.validate_grant_for_execution(approved, **{**base, "endpoint": "/api/other"})[1] == "endpoint_mismatch"
    assert ma.validate_grant_for_execution(approved, **{**base, "test_record_id": "other"})[1] == "record_mismatch"
    assert ma.validate_grant_for_execution(approved, **{**base, "fields": ["secret"]})[1] == "unapproved_fields"
    assert ma.validate_grant_for_execution(approved, **{**base, "http_method": "DELETE"})[1] == "delete_forbidden"


def test_delete_method_rejected_at_request(store):
    with pytest.raises(ma.MutationApprovalError, match="DELETE|POST"):
        _request(store, http_method="DELETE")


def test_cross_tenant_approve_denied(store):
    row = _request(store)
    with pytest.raises(ma.MutationApprovalError, match="cross-tenant"):
        ma.approve_approval(
            store,
            engagement_id=7,
            approval_id=row.id,
            approver="bob.lead",
            approver_user_id=20,
            approver_role="lead",
            tenant_id=999,
        )


def test_agent_boolean_is_not_an_approval():
    """AASI/scanner cannot manufacture approval — only ApprovalStore rows count."""
    d = ip.decide_from_policy_input(
        _inp(),
        test_id="T22",
        profile="active",
        env_flag_enabled=True,
        policy_decide=_allow,
        allowed=frozenset({"dev", "demo"}),
        production_grant=None,  # boolean True alone is ignored
    )
    assert d.reason == ip.R_ENV_FORBIDDEN


def test_valid_grant_allows_production_t22(monkeypatch):
    monkeypatch.setattr(ma, "production_safe_mutation_enabled", lambda: True)
    d = ip.decide_from_policy_input(
        _inp(),
        test_id="T22",
        profile="active",
        env_flag_enabled=True,
        policy_decide=_allow,
        allowed=frozenset({"dev", "demo"}),
        production_grant={
            "ok": True,
            "reason": "allowed",
            "approval_id": "abc",
            "cleanup_plan": "restore baseline fields via PATCH",
            "test_record_id": "demo-1",
            "approved_fields": ["display_name"],
        },
    )
    assert d.allow is True
    assert d.reason == ip.R_PROD_SAFE_ALLOWED


def test_apply_approved_values_no_arbitrary_injection():
    body = {"display_name": "x", "role": "admin", "id": "victim"}
    out = ma.apply_approved_values(
        body,
        approved_fields=["display_name", "id"],
        approved_values={"display_name": "safe"},
        test_record_id="demo-1",
    )
    assert out == {"display_name": "safe", "id": "demo-1"}
    assert "role" not in out


def test_restore_failure_is_recorded(store):
    row = _request(store)
    ma.approve_approval(
        store,
        engagement_id=7,
        approval_id=row.id,
        approver="bob.lead",
        approver_user_id=20,
        approver_role="lead",
    )
    updated = ma.record_restore_result(
        store, engagement_id=7, approval_id=row.id, verified=False, notes="GET != baseline"
    )
    assert updated.restore_verified is False
    assert "baseline" in updated.restore_notes
