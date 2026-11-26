"""Full confidence matrix for Gap #3 production safe-mutation (isolated fixtures).

Covers varied synthetic data, policy re-check, body_mutation executor path,
orchestrator grant hydration, restore-failure halt signal, and mismatch matrix.
Never targets a real customer production environment.
"""
# @lat: [[run-validity-and-policy#Intrusive policy#Production safe-mutation (Gap #3)]]

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from attestra.automated_vapt.core import body_mutation as bm
from attestra.automated_vapt.core import intrusive_policy as ip
from attestra.automated_vapt.core import mutation_approval as ma
from attestra.automated_vapt.core import orchestrator as orch
from attestra.automated_vapt.core.production_safe_executor import (
    ProductionSafeExecutionError,
    execute_approved_mutation,
)
from attestra.automated_vapt.core.session_auth import SessionAuth


@pytest.fixture
def store(tmp_path: Path):
    return ma.ApprovalStore(tmp_path / "approvals")


@pytest.fixture
def flag_on(monkeypatch):
    monkeypatch.setattr(ma, "production_safe_mutation_enabled", lambda: True)
    monkeypatch.setattr(ip, "env_flag_enabled", lambda tid: True)


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
        cleanup_plan="PATCH approved fields back to baseline; GET-verify equals baseline",
        ttl_minutes=30,
    )
    kwargs.update(over)
    return ma.request_approval(store, **kwargs)


def _approve(store, row):
    return ma.approve_approval(
        store,
        engagement_id=row.engagement_id,
        approval_id=row.id,
        approver="bob.lead",
        approver_user_id=20,
        approver_role="lead",
    )


class FakeRecord:
    """In-memory synthetic REST record with optional restore corruption."""

    def __init__(self, *, record_id="demo-1", corrupt_restore=False, get_fail_after=None):
        self.data = {"id": record_id, "display_name": "baseline", "role": "user", "note": "keep"}
        self.corrupt_restore = corrupt_restore
        self.get_fail_after = get_fail_after
        self.calls = 0
        self.writes: list[dict] = []

    def get(self, url, headers):
        self.calls += 1
        if self.get_fail_after is not None and self.calls > self.get_fail_after:
            return 500, None, "boom"
        return 200, dict(self.data), ""

    def write(self, method, url, body, headers):
        self.writes.append({"method": method, "body": dict(body)})
        if self.corrupt_restore and body.get("display_name") != "attestra-mut-safe":
            self.data["display_name"] = "CORRUPTED"
        else:
            for k, v in body.items():
                if k in ("display_name", "id", "note"):
                    self.data[k] = v
        return 200, dict(self.data), ""


# --------------------------------------------------------------------------- policy / decision_from_ctx


def test_decision_from_ctx_honors_prod_safe_grant(flag_on):
    """Regression: stored R_PROD_SAFE_ALLOWED must not be wiped on production env."""
    stored = ip.IntrusiveDecision(
        True,
        ip.R_PROD_SAFE_ALLOWED,
        {"asset_environment": "production", "test_id": "T22", "grant_id": "abc"},
    )
    ctx = SimpleNamespace(extra={ip.CTX_KEY: {"T22": stored.to_json()}})
    out = ip.decision_from_ctx(ctx, "T22")
    assert out.allow is True
    assert out.reason == ip.R_PROD_SAFE_ALLOWED


def test_decision_from_ctx_still_blocks_ssrf_on_production(flag_on):
    stored = ip.IntrusiveDecision(True, ip.R_ALLOWED, {"asset_environment": "production", "test_id": "SSRF"})
    ctx = SimpleNamespace(extra={ip.CTX_KEY: {"SSRF": stored.to_json()}})
    out = ip.decision_from_ctx(ctx, "SSRF")
    assert out.allow is False
    assert out.reason == ip.R_ENV_FORBIDDEN


def test_decision_from_ctx_prod_safe_requires_flag(monkeypatch):
    monkeypatch.setattr(ma, "production_safe_mutation_enabled", lambda: False)
    monkeypatch.setattr(ip, "env_flag_enabled", lambda tid: True)
    stored = ip.IntrusiveDecision(
        True, ip.R_PROD_SAFE_ALLOWED, {"asset_environment": "prod", "test_id": "T22"}
    )
    ctx = SimpleNamespace(extra={ip.CTX_KEY: {"T22": stored.to_json()}})
    out = ip.decision_from_ctx(ctx, "T22")
    assert out.allow is False
    assert out.reason == ip.R_PROD_SAFE_DENIED


# --------------------------------------------------------------------------- varied approval data


@pytest.mark.parametrize(
    "method,fields,values,record,endpoint",
    [
        ("PATCH", ["display_name", "id"], {"display_name": "safe-a"}, "rec-a", "/api/test-records/rec-a"),
        ("PUT", ["note", "id"], {"note": "safe-note"}, "rec-b", "/api/v1/synthetic/rec-b"),
        ("POST", ["display_name"], {"display_name": "x"}, "rec-c", "/api/test-records/rec-c"),
        ("PATCH", ["display_name", "note", "id"], {"display_name": "n1", "note": "n2"}, "uuid-9", "/records/uuid-9"),
    ],
)
def test_varied_methods_fields_records_succeed(store, flag_on, method, fields, values, record, endpoint):
    row = _request(
        store,
        http_method=method,
        approved_fields=fields,
        approved_values=values,
        test_record_id=record,
        endpoint_pattern=endpoint,
    )
    approved = _approve(store, row)
    fake = FakeRecord(record_id=record)
    # Seed baseline keys that will be mutated
    for k in fields:
        if k != "id" and k not in fake.data:
            fake.data[k] = f"baseline-{k}"
    result = execute_approved_mutation(
        store=store,
        engagement_id=7,
        tenant_id=1,
        asset_id=3,
        approval_id=approved.id,
        nonce=approved.nonce,
        http_get=fake.get,
        http_write=fake.write,
    )
    assert result["status"] == "PASSED"
    assert result["evidence"]["restore_verified"] is True
    # Unapproved fields untouched
    assert fake.data.get("role") == "user"
    # Replay denied
    with pytest.raises(ProductionSafeExecutionError):
        execute_approved_mutation(
            store=store,
            engagement_id=7,
            tenant_id=1,
            asset_id=3,
            approval_id=approved.id,
            nonce=approved.nonce,
            http_get=fake.get,
            http_write=fake.write,
        )


@pytest.mark.parametrize(
    "bad_kw,expected",
    [
        ({"asset_id": 99}, "asset_mismatch"),
        ({"endpoint": "/api/other"}, "endpoint_mismatch"),
        ({"test_record_id": "nope"}, "record_mismatch"),
        ({"http_method": "PUT"}, "method_mismatch"),
        ({"http_method": "DELETE"}, "delete_forbidden"),
        ({"fields": ["secret"]}, "unapproved_fields"),
        ({"target_origin": "https://evil.example.com"}, "origin_mismatch"),
        ({"tenant_id": 2}, "tenant_mismatch"),
        ({"engagement_id": 99}, "engagement_mismatch"),
    ],
)
def test_mismatch_matrix(store, flag_on, bad_kw, expected):
    approved = _approve(store, _request(store))
    base = dict(
        tenant_id=1,
        engagement_id=7,
        asset_id=3,
        target_origin="https://app.example.com",
        endpoint="/api/test-records/demo-1",
        http_method="PATCH",
        test_record_id="demo-1",
        fields=["display_name"],
    )
    base.update(bad_kw)
    ok, reason = ma.validate_grant_for_execution(approved, **base)
    assert ok is False
    assert reason == expected


def test_expired_revoked_denied_consumed_statuses(store, flag_on):
    # expired
    row = _request(store)
    past = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    store.update(7, row.id, expires_at=past, status=ma.STATUS_APPROVED, approver="bob", approver_role="lead")
    ok, reason = ma.validate_grant_for_execution(
        store.get(7, row.id),
        tenant_id=1,
        engagement_id=7,
        asset_id=3,
        target_origin="https://app.example.com",
        endpoint="/api/test-records/demo-1",
        http_method="PATCH",
        test_record_id="demo-1",
    )
    assert ok is False and reason == "approval_expired"

    # revoked
    row2 = _approve(store, _request(store, test_record_id="r2", endpoint_pattern="/api/test-records/r2"))
    ma.revoke_approval(
        store, engagement_id=7, approval_id=row2.id, actor="bob.lead", actor_user_id=20, actor_role="lead"
    )
    ok, reason = ma.validate_grant_for_execution(
        store.get(7, row2.id),
        tenant_id=1,
        engagement_id=7,
        asset_id=3,
        target_origin="https://app.example.com",
        endpoint="/api/test-records/r2",
        http_method="PATCH",
        test_record_id="r2",
    )
    assert ok is False and reason.startswith("approval_status_")

    # denied
    row3 = _request(store, test_record_id="r3", endpoint_pattern="/api/test-records/r3")
    ma.reject_approval(
        store, engagement_id=7, approval_id=row3.id, actor="bob.lead", actor_user_id=20, actor_role="lead"
    )
    ok, reason = ma.validate_grant_for_execution(
        store.get(7, row3.id),
        tenant_id=1,
        engagement_id=7,
        asset_id=3,
        target_origin="https://app.example.com",
        endpoint="/api/test-records/r3",
        http_method="PATCH",
        test_record_id="r3",
    )
    assert ok is False


# --------------------------------------------------------------------------- body_mutation integration


def _prod_ctx(*, grant, fake_client=None, auth_ready=True):
    auth = SessionAuth(
        profile_id=2,
        status="ready" if auth_ready else "failed",
        note="ok" if auth_ready else "fail",
        headers={"Authorization": "Bearer tok"},
    )
    decision = ip.IntrusiveDecision(
        True,
        ip.R_PROD_SAFE_ALLOWED,
        {"asset_environment": "production", "test_id": "T22", "grant_id": grant.get("approval_id")},
    )
    return SimpleNamespace(
        engagement_id=7,
        tenant_id=1,
        asset_id=3,
        target_base_url="https://app.example.com",
        profile="active",
        allow_private=False,
        extra={
            ip.CTX_KEY: {"T22": decision.to_json()},
            "production_safe_mutation": grant,
            "_production_safe_mutation": grant,
            "_session_auth": auth,
            "httpx_client": fake_client,
        },
    )


class _HttpxLike:
    def __init__(self, fake: FakeRecord):
        self.fake = fake

    def request(self, method, url, headers=None, json=None):
        if method.upper() == "GET":
            st, data, body_text = self.fake.get(url, headers)
        else:
            st, data, body_text = self.fake.write(method, url, json or {}, headers)

        class _Resp:
            status_code = st
            text = body_text or ""
            _data = data

            def json(self):
                if self._data is None:
                    raise ValueError("no json")
                return self._data

        return _Resp()


def test_body_mutation_runs_prod_safe_path(store, flag_on, monkeypatch):
    approved = _approve(store, _request(store))
    monkeypatch.setattr(ma, "ApprovalStore", lambda root=None: store)
    fake = FakeRecord()
    grant = {
        "ok": True,
        "reason": "allowed",
        "approval_id": approved.id,
        "nonce": approved.nonce,
        "cleanup_plan": approved.cleanup_plan,
        "test_record_id": approved.test_record_id,
        "approved_fields": list(approved.approved_fields),
        "approved_values": dict(approved.approved_values),
    }
    ctx = _prod_ctx(grant=grant, fake_client=_HttpxLike(fake))
    out = bm.run_object_mutation(ctx)
    assert out["status"] == "PASSED"
    assert out["mutation"]["production_safe"] is True
    assert fake.data["display_name"] == "baseline"
    assert store.get(7, approved.id).status == ma.STATUS_CONSUMED
    assert store.get(7, approved.id).restore_verified is True


def test_body_mutation_restore_failure_sets_stop(store, flag_on, monkeypatch):
    approved = _approve(store, _request(store))
    monkeypatch.setattr(ma, "ApprovalStore", lambda root=None: store)
    fake = FakeRecord(corrupt_restore=True)
    grant = {
        "ok": True,
        "reason": "allowed",
        "approval_id": approved.id,
        "nonce": approved.nonce,
        "cleanup_plan": approved.cleanup_plan,
        "test_record_id": approved.test_record_id,
        "approved_fields": list(approved.approved_fields),
        "approved_values": dict(approved.approved_values),
    }
    ctx = _prod_ctx(grant=grant, fake_client=_HttpxLike(fake))
    out = bm.run_object_mutation(ctx)
    assert out["status"] == "FAILED"
    assert ctx.extra.get("production_safe_mutation_stop") is True
    assert store.get(7, approved.id).restore_verified is False


def test_body_mutation_missing_auth_is_not_tested(store, flag_on):
    approved = _approve(store, _request(store))
    grant = {
        "ok": True,
        "reason": "allowed",
        "approval_id": approved.id,
        "nonce": approved.nonce,
        "cleanup_plan": "restore",
        "test_record_id": "demo-1",
        "approved_fields": ["display_name"],
    }
    ctx = _prod_ctx(grant=grant, auth_ready=False)
    out = bm.run_object_mutation(ctx)
    assert out["status"] == "NOT_TESTED"


# --------------------------------------------------------------------------- orchestrator hydration


def test_hydrate_mutation_approval_from_result_json(flag_on):
    ex = SimpleNamespace(
        result_json=json.dumps(
            {
                "auth_profile_id": 5,
                "mutation_approval_id": "abc123",
                "mutation_endpoint": "/api/x",
            }
        )
    )
    ctx = SimpleNamespace(extra={})
    orch._hydrate_auth_profile_ids(ctx, ex)
    orch._hydrate_mutation_approval(ctx, ex)
    assert ctx.extra["auth_profile_id"] == 5
    assert ctx.extra["mutation_approval_id"] == "abc123"
    assert ctx.extra["mutation_endpoint"] == "/api/x"


def test_resolve_grant_varied_overrides(store, flag_on):
    approved = _approve(store, _request(store))
    good = ma.resolve_grant_for_ctx(
        engagement_id=7,
        tenant_id=1,
        asset_id=3,
        target_base_url="https://app.example.com",
        extra={"mutation_approval_id": approved.id},
        store=store,
    )
    assert good["ok"] is True and good["nonce"]

    for extra_bad in (
        {"mutation_approval_id": approved.id, "mutation_method": "DELETE"},
        {"mutation_approval_id": approved.id, "mutation_test_record_id": "other"},
        {"mutation_approval_id": approved.id, "mutation_endpoint": "/nope"},
        {"mutation_approval_id": "missing-id"},
    ):
        g = ma.resolve_grant_for_ctx(
            engagement_id=7,
            tenant_id=1,
            asset_id=3,
            target_base_url="https://app.example.com",
            extra=extra_bad,
            store=store,
        )
        assert g is None or g.get("ok") is False


def test_no_arbitrary_injection_across_payloads(store, flag_on):
    payloads = [
        {"display_name": "ok", "role": "admin", "password": "x"},
        {"display_name": "ok", "id": "victim-99", "isAdmin": True},
        {"note": "ignored", "display_name": "ok"},
    ]
    for body in payloads:
        out = ma.apply_approved_values(
            body,
            approved_fields=["display_name", "id"],
            approved_values={"display_name": "safe"},
            test_record_id="demo-1",
        )
        assert set(out.keys()) <= {"display_name", "id"}
        assert out["display_name"] == "safe"
        assert out["id"] == "demo-1"
        assert "role" not in out and "password" not in out and "isAdmin" not in out


def test_delete_and_empty_fields_rejected(store):
    with pytest.raises(ma.MutationApprovalError):
        _request(store, http_method="DELETE")
    with pytest.raises(ma.MutationApprovalError):
        _request(store, approved_fields=[])
    with pytest.raises(ma.MutationApprovalError):
        _request(store, cleanup_plan="short")
    with pytest.raises(ma.MutationApprovalError):
        _request(store, test_record_id="")
