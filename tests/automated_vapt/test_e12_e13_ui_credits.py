"""Elite E12/E13: engagement UI flag wiring and one-credit-per-run."""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from attestra import config, db, services
from attestra.automated_vapt.core import orchestrator as orch
from attestra.credits import balance_view, ensure_account


@pytest.fixture
def elite_flag(monkeypatch):
    monkeypatch.setattr(config, "AUTOMATED_VAPT_ENABLED", True)


def _eng(s):
    today = date.today()
    e = services.create_engagement(
        s,
        tenant="Elite Credits",
        name="Elite Credits",
        type="vapt",
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
        rules_of_engagement="local",
        environments=["dev"],
        actor="tester",
    )
    a = services.add_asset(
        s,
        e.id,
        kind="web_app",
        identifier="http://localhost:8765/",
        name="Mock",
        environment="dev",
        actor="tester",
    )
    return e, a


# @lat: [[tests#Elite Phase E13 subscription#One credit per elite run]]
def test_one_credit_per_elite_run(fresh_db, elite_flag, monkeypatch):
    monkeypatch.setenv("SUBSCRIPTION_SERVICE", "ON")
    monkeypatch.setattr(config, "get_subscription_service", lambda: "ON")
    monkeypatch.setattr(config, "subscription_enforcement_enabled", lambda: True)

    with db.session() as s:
        e, a = _eng(s)
        ensure_account(s, e.tenant_id, actor="admin")
        before = balance_view(s, e.tenant_id, actor="tester")["balance"]
        orch.create_execution(
            s,
            engagement_id=e.id,
            asset_id=a.id,
            test_case_ids=["SCOPE_SMOKE"],
            actor="tester",
            allow_private=True,
        )
        after = balance_view(s, e.tenant_id, actor="tester")["balance"]
        assert after == before - 1


# @lat: [[tests#Elite Phase E12 frontend#Elite helpers list cases]]
def test_elite_helpers_list_cases(elite_flag):
    from attestra.web.ui import _elite_test_cases

    cases = _elite_test_cases()
    assert any(c["id"] == "T04" for c in cases)
