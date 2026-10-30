"""Elite Phase E3: orchestrator, scope validation, and execution status."""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from attestra import config, db, services
from attestra.automated_vapt.core import orchestrator as orch
from attestra.automated_vapt.core import scope_validator
from attestra.automated_vapt.core.test_registry import list_categories, list_test_cases
from attestra.services import ServiceError


@pytest.fixture
def elite_flag(monkeypatch):
    monkeypatch.setattr(config, "AUTOMATED_VAPT_ENABLED", True)


@pytest.fixture
def eng_with_asset(fresh_db, elite_flag):
    today = date.today()
    with db.session() as s:
        e = services.create_engagement(
            s,
            tenant="Elite E3 Client",
            name="Elite E3",
            type="vapt",
            frameworks=["pci_dss_4"],
            window_start=today - timedelta(days=1),
            window_end=today + timedelta(days=30),
            actor="tester",
        )
        services.add_authorization(
            s,
            e.id,
            filename="roe.txt",
            data=b"authorized for elite local testing",
            signer="Client",
            signed_on=today - timedelta(days=1),
            expires_on=today + timedelta(days=30),
            rules_of_engagement="Local mocks only.",
            environments=["dev", "staging"],
            actor="tester",
        )
        a = services.add_asset(
            s,
            e.id,
            kind="web_app",
            identifier="http://localhost:8765/",
            name="Local mock",
            environment="dev",
            actor="tester",
        )
        return {"engagement_id": e.id, "asset_id": a.id, "tenant_id": e.tenant_id}


# @lat: [[tests#Elite Phase E3 orchestrator#Feature flag off refuses]]
def test_feature_flag_off_refuses(fresh_db, monkeypatch, eng_with_asset):
    monkeypatch.setattr(config, "AUTOMATED_VAPT_ENABLED", False)
    with db.session() as s:
        with pytest.raises(ServiceError, match="disabled"):
            orch.create_execution(
                s,
                engagement_id=eng_with_asset["engagement_id"],
                asset_id=eng_with_asset["asset_id"],
                test_case_ids=["SCOPE_SMOKE"],
                actor="tester",
            )


# @lat: [[tests#Elite Phase E3 orchestrator#Registry lists cases]]
def test_registry_lists_cases(elite_flag):
    cats = list_categories()
    assert "authorization" in cats
    assert "scope" in cats
    ids = {c.id for c in list_test_cases()}
    assert "T04" in ids
    assert "SCOPE_SMOKE" in ids


# @lat: [[tests#Elite Phase E3 orchestrator#Scope rejects foreign host]]
def test_scope_rejects_foreign_host(elite_flag):
    scope = scope_validator.build_scope_from_asset(
        "http://localhost:8765/",
        allow_private=True,
    )
    with pytest.raises(ServiceError, match="out of scope"):
        scope_validator.validate_target_url(
            "https://evil.example/x",
            scope,
            check_dns=False,
        )


# @lat: [[tests#Elite Phase E3 orchestrator#Queue run complete scope smoke]]
def test_queue_run_complete_scope_smoke(eng_with_asset):
    with db.session() as s:
        ex = orch.create_execution(
            s,
            engagement_id=eng_with_asset["engagement_id"],
            asset_id=eng_with_asset["asset_id"],
            test_case_ids=["SCOPE_SMOKE"],
            actor="tester",
            allow_private=True,
        )
        assert ex.status == "QUEUED"
        xid = ex.id

    with db.session() as s:
        done = orch.run_execution(s, xid, actor="tester")
        assert done.status == "COMPLETED"
        assert done.started_at is not None
        assert done.ended_at is not None
        pub = orch.execution_public_dict(done)
        assert pub["result"]["cases"][0]["test_id"] == "SCOPE_SMOKE"
        assert pub["result"]["cases"][0]["status"] == "PASSED"


# @lat: [[tests#Elite Phase E3 orchestrator#Cancel queued execution]]
def test_cancel_queued_execution(eng_with_asset):
    with db.session() as s:
        ex = orch.create_execution(
            s,
            engagement_id=eng_with_asset["engagement_id"],
            asset_id=eng_with_asset["asset_id"],
            test_case_ids=["SCOPE_SMOKE"],
            actor="tester",
            allow_private=True,
        )
        xid = ex.id

    with db.session() as s:
        cancelled = orch.cancel_execution(s, xid, actor="tester")
        assert cancelled.status == "CANCELLED"


# @lat: [[tests#Elite Phase E3 orchestrator#Deferred cases stay honest]]
def test_deferred_cases_stay_honest(eng_with_asset):
    with db.session() as s:
        ex = orch.create_execution(
            s,
            engagement_id=eng_with_asset["engagement_id"],
            asset_id=eng_with_asset["asset_id"],
            test_case_ids=["SCOPE_SMOKE", "T15"],
            actor="tester",
            allow_private=True,
        )
        xid = ex.id
    with db.session() as s:
        done = orch.run_execution(s, xid, actor="tester")
        assert done.status == "COMPLETED"
        cases = {c["test_id"]: c for c in orch.execution_public_dict(done)["result"]["cases"]}
        assert cases["SCOPE_SMOKE"]["status"] == "PASSED"
        assert cases["T15"]["status"] == "DEFERRED"


# @lat: [[tests#Elite Phase E3 orchestrator#Out of scope asset fails run]]
def test_out_of_scope_asset_fails_create(fresh_db, elite_flag):
    today = date.today()
    with db.session() as s:
        e = services.create_engagement(
            s,
            tenant="Bad Scope Client",
            name="Bad scope",
            type="va",
            frameworks=["pci_dss_4"],
            window_start=today,
            window_end=today + timedelta(days=7),
            actor="tester",
        )
        services.add_authorization(
            s,
            e.id,
            filename="roe.txt",
            data=b"authorized",
            signer="Client",
            signed_on=today,
            expires_on=today + timedelta(days=7),
            rules_of_engagement="n/a",
            environments=["dev"],
            actor="tester",
        )
        # Metadata host is always refused by SSRF policy.
        a = services.add_asset(
            s,
            e.id,
            kind="web_app",
            identifier="http://metadata.google.internal/",
            name="Blocked",
            environment="dev",
            actor="tester",
        )
        with pytest.raises(ServiceError):
            orch.create_execution(
                s,
                engagement_id=e.id,
                asset_id=a.id,
                test_case_ids=["SCOPE_SMOKE"],
                actor="tester",
                allow_private=False,
            )
