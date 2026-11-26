"""Gap #3: synthetic production safe-mutation executor + lifecycle (isolated)."""
# @lat: [[run-validity-and-policy#Intrusive policy]]

from __future__ import annotations

from pathlib import Path

import pytest

from attestra.automated_vapt.core import mutation_approval as ma
from attestra.automated_vapt.core.production_safe_executor import (
    ProductionSafeExecutionError,
    execute_approved_mutation,
)


@pytest.fixture
def store(tmp_path: Path):
    return ma.ApprovalStore(tmp_path / "approvals")


def _approved(store, monkeypatch, **over):
    monkeypatch.setattr(ma, "production_safe_mutation_enabled", lambda: True)
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
    row = ma.request_approval(store, **kwargs)
    return ma.approve_approval(
        store,
        engagement_id=7,
        approval_id=row.id,
        approver="bob.lead",
        approver_user_id=20,
        approver_role="lead",
    )


class _FakeRecord:
    def __init__(self):
        self.data = {"id": "demo-1", "display_name": "baseline", "role": "user"}
        self.writes: list[tuple[str, dict]] = []

    def get(self, url, headers):
        return 200, dict(self.data), ""

    def write(self, method, url, body, headers):
        self.writes.append((method, dict(body)))
        self.data.update({k: v for k, v in body.items() if k in ("display_name", "id")})
        return 200, dict(self.data), ""


def test_reject_and_revoke_lifecycle(store, monkeypatch):
    monkeypatch.setattr(ma, "production_safe_mutation_enabled", lambda: True)
    row = ma.request_approval(
        store,
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
        approved_fields=["display_name"],
        cleanup_plan="restore baseline via PATCH",
    )
    denied = ma.reject_approval(
        store,
        engagement_id=7,
        approval_id=row.id,
        actor="bob.lead",
        actor_user_id=20,
        actor_role="lead",
        reason="out of window",
    )
    assert denied.status == ma.STATUS_DENIED

    row2 = ma.request_approval(
        store,
        tenant_id=1,
        engagement_id=7,
        asset_id=3,
        requester="alice.tester",
        requester_user_id=10,
        requester_role="tester",
        target_origin="https://app.example.com",
        endpoint_pattern="/api/test-records/demo-2",
        http_method="PATCH",
        test_record_id="demo-2",
        approved_fields=["display_name"],
        cleanup_plan="restore baseline via PATCH",
    )
    approved = ma.approve_approval(
        store,
        engagement_id=7,
        approval_id=row2.id,
        approver="bob.lead",
        approver_user_id=20,
        approver_role="lead",
    )
    revoked = ma.revoke_approval(
        store,
        engagement_id=7,
        approval_id=approved.id,
        actor="bob.lead",
        actor_user_id=20,
        actor_role="lead",
        reason="changed mind",
    )
    assert revoked.status == ma.STATUS_REVOKED
    ok, reason = ma.validate_grant_for_execution(
        revoked,
        tenant_id=1,
        engagement_id=7,
        asset_id=3,
        target_origin="https://app.example.com",
        endpoint="/api/test-records/demo-2",
        http_method="PATCH",
        test_record_id="demo-2",
    )
    assert ok is False
    assert "revoked" in reason or reason.startswith("approval_status_")


def test_synthetic_mutate_restore_success(store, monkeypatch):
    approved = _approved(store, monkeypatch)
    fake = _FakeRecord()
    result = execute_approved_mutation(
        store=store,
        engagement_id=7,
        tenant_id=1,
        asset_id=3,
        approval_id=approved.id,
        nonce=approved.nonce,
        headers={},
        http_get=fake.get,
        http_write=fake.write,
    )
    assert result["status"] == "PASSED"
    assert result["evidence"]["restore_verified"] is True
    assert fake.data["display_name"] == "baseline"
    assert len(fake.writes) == 2  # mutate + restore
    row = store.get(7, approved.id)
    assert row.status == ma.STATUS_CONSUMED
    assert row.restore_verified is True
    # Replay denied
    with pytest.raises(ProductionSafeExecutionError):
        execute_approved_mutation(
            store=store,
            engagement_id=7,
            tenant_id=1,
            asset_id=3,
            approval_id=approved.id,
            nonce=approved.nonce,
            headers={},
            http_get=fake.get,
            http_write=fake.write,
        )


def test_restoration_failure_stops_and_records(store, monkeypatch):
    approved = _approved(store, monkeypatch)

    state = {"id": "demo-1", "display_name": "baseline"}

    def http_get(url, headers):
        return 200, dict(state), ""

    def http_write(method, url, body, headers):
        # Mutate succeeds; restore "succeeds" HTTP-wise but leaves wrong value
        if body.get("display_name") == "attestra-mut-safe":
            state["display_name"] = "attestra-mut-safe"
        else:
            state["display_name"] = "CORRUPTED"  # not baseline
        return 200, dict(state), ""

    with pytest.raises(ProductionSafeExecutionError, match="restoration_verification_failed"):
        execute_approved_mutation(
            store=store,
            engagement_id=7,
            tenant_id=1,
            asset_id=3,
            approval_id=approved.id,
            nonce=approved.nonce,
            headers={},
            http_get=http_get,
            http_write=http_write,
        )
    row = store.get(7, approved.id)
    assert row.status == ma.STATUS_CONSUMED
    assert row.restore_verified is False


def test_flag_off_blocks_executor(store, monkeypatch):
    monkeypatch.setattr(ma, "production_safe_mutation_enabled", lambda: False)
    row = ma.request_approval(
        store,
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
        approved_fields=["display_name"],
        cleanup_plan="restore baseline via PATCH",
    )
    # Even if somehow approved while flag off, executor fails closed
    store.update(7, row.id, status=ma.STATUS_APPROVED, approver="bob", approver_role="lead")
    with pytest.raises(ProductionSafeExecutionError, match="flag_off"):
        execute_approved_mutation(
            store=store,
            engagement_id=7,
            tenant_id=1,
            asset_id=3,
            approval_id=row.id,
            nonce=row.nonce,
            headers={},
            http_get=lambda u, h: (200, {"id": "demo-1"}, ""),
            http_write=lambda m, u, b, h: (200, b, ""),
        )


def test_resolve_grant_for_ctx(store, monkeypatch):
    approved = _approved(store, monkeypatch)
    grant = ma.resolve_grant_for_ctx(
        engagement_id=7,
        tenant_id=1,
        asset_id=3,
        target_base_url="https://app.example.com",
        extra={"mutation_approval_id": approved.id},
        store=store,
    )
    assert grant is not None
    assert grant["ok"] is True
    assert grant["approval_id"] == approved.id
    assert grant["nonce"] == approved.nonce

    bad = ma.resolve_grant_for_ctx(
        engagement_id=7,
        tenant_id=1,
        asset_id=3,
        target_base_url="https://app.example.com",
        extra={"mutation_approval_id": approved.id, "mutation_endpoint": "/api/other"},
        store=store,
    )
    assert bad["ok"] is False
    assert bad["reason"] == "endpoint_mismatch"


def test_concurrent_consume_second_fails(store, monkeypatch):
    approved = _approved(store, monkeypatch)
    first = ma.consume_approval(
        store, engagement_id=7, approval_id=approved.id, nonce=approved.nonce, tenant_id=1
    )
    assert first.status == ma.STATUS_CONSUMED
    with pytest.raises(ma.MutationApprovalError, match="consumed"):
        ma.consume_approval(
            store, engagement_id=7, approval_id=approved.id, nonce=approved.nonce, tenant_id=1
        )
