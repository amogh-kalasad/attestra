"""Primary/secondary auth profile ids on Elite automated test executions."""

from __future__ import annotations

import json

import pytest

from datetime import date, timedelta

from attestra import config, db, services
from attestra.automated_vapt.core import orchestrator as orch
from attestra.models import AuthCredentialProfile
from attestra.services import ServiceError


@pytest.fixture
def elite_flag(monkeypatch):
    monkeypatch.setattr(config, 'AUTOMATED_VAPT_ENABLED', True)


@pytest.fixture
def eng_with_asset(fresh_db, elite_flag):
    today = date.today()
    with db.session() as s:
        e = services.create_engagement(
            s,
            tenant='Elite Sec Profile Client',
            name='Elite Sec Profile',
            type='vapt',
            frameworks=['pci_dss_4'],
            window_start=today - timedelta(days=1),
            window_end=today + timedelta(days=30),
            actor='tester',
        )
        services.add_authorization(
            s,
            e.id,
            filename='roe.txt',
            data=b'authorized for elite local testing',
            signer='Client',
            signed_on=today - timedelta(days=1),
            expires_on=today + timedelta(days=30),
            rules_of_engagement='Local mocks only.',
            environments=['dev', 'staging'],
            actor='tester',
        )
        a = services.add_asset(
            s,
            e.id,
            kind='web_app',
            identifier='http://localhost:8765/',
            name='Local mock',
            environment='dev',
            actor='tester',
        )
        return {'engagement_id': e.id, 'asset_id': a.id, 'tenant_id': e.tenant_id}


def _add_profile(s, *, tenant_id: int, engagement_id: int, asset_id: int | None, label: str, status: str = "valid"):
    row = AuthCredentialProfile(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        asset_id=asset_id,
        label=label,
        role_name=label,
        method="header",
        status=status,
    )
    s.add(row)
    s.flush()
    return row


def test_create_execution_blank_profiles_stays_compatible(eng_with_asset):
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
        assert json.loads(ex.result_json or "{}") == {}


def test_create_execution_rejects_unknown_and_same_profiles(eng_with_asset):
    with db.session() as s:
        primary = _add_profile(
            s,
            tenant_id=eng_with_asset["tenant_id"],
            engagement_id=eng_with_asset["engagement_id"],
            asset_id=eng_with_asset["asset_id"],
            label="role-a",
        )
        with pytest.raises(ServiceError, match="not found for this engagement"):
            orch.create_execution(
                s,
                engagement_id=eng_with_asset["engagement_id"],
                asset_id=eng_with_asset["asset_id"],
                test_case_ids=["SCOPE_SMOKE"],
                actor="tester",
                allow_private=True,
                auth_profile_id=999999,
            )
        with pytest.raises(ServiceError, match="must be different"):
            orch.create_execution(
                s,
                engagement_id=eng_with_asset["engagement_id"],
                asset_id=eng_with_asset["asset_id"],
                test_case_ids=["SCOPE_SMOKE"],
                actor="tester",
                allow_private=True,
                auth_profile_id=primary.id,
                secondary_auth_profile_id=primary.id,
            )


def test_create_execution_stores_ids_and_run_hydrates_extra(eng_with_asset, monkeypatch):
    seen: dict = {}

    def _fake_ensure(ctx):
        seen["auth_profile_id"] = ctx.extra.get("auth_profile_id")
        seen["secondary_auth_profile_id"] = ctx.extra.get("secondary_auth_profile_id")
        return False

    monkeypatch.setattr(orch, "_ensure_httpx_client", _fake_ensure)

    with db.session() as s:
        primary = _add_profile(
            s,
            tenant_id=eng_with_asset["tenant_id"],
            engagement_id=eng_with_asset["engagement_id"],
            asset_id=eng_with_asset["asset_id"],
            label="role-a",
        )
        secondary = _add_profile(
            s,
            tenant_id=eng_with_asset["tenant_id"],
            engagement_id=eng_with_asset["engagement_id"],
            asset_id=None,
            label="role-b",
        )
        ex = orch.create_execution(
            s,
            engagement_id=eng_with_asset["engagement_id"],
            asset_id=eng_with_asset["asset_id"],
            test_case_ids=["SCOPE_SMOKE"],
            actor="tester",
            allow_private=True,
            auth_profile_id=str(primary.id),
            secondary_auth_profile_id=secondary.id,
        )
        stored = json.loads(ex.result_json)
        assert stored["auth_profile_id"] == primary.id
        assert stored["secondary_auth_profile_id"] == secondary.id
        xid = ex.id
        primary_id, secondary_id = primary.id, secondary.id

    with db.session() as s:
        done = orch.run_execution(s, xid, actor="tester")
        assert done.status == "COMPLETED"
        result = json.loads(done.result_json)
        assert result["auth_profile_id"] == primary_id
        assert result["secondary_auth_profile_id"] == secondary_id
        assert result["cases"][0]["status"] == "PASSED"
    assert seen["auth_profile_id"] == primary_id
    assert seen["secondary_auth_profile_id"] == secondary_id

def _ctx(extra=None):
    from attestra.automated_vapt.core.test_context import TestContext

    return TestContext(
        engagement_id=1,
        tenant_id=1,
        asset_id=1,
        target_base_url='http://localhost:8765/',
        test_case_ids=['ROLEDIFF', 'T20'],
        extra=dict(extra or {}),
    )


def test_parse_optional_profile_id_accepts_blank_and_numeric():
    assert orch._parse_optional_profile_id(None, field='auth profile') is None
    assert orch._parse_optional_profile_id('', field='auth profile') is None
    assert orch._parse_optional_profile_id('  ', field='auth profile') is None
    assert orch._parse_optional_profile_id('12', field='auth profile') == 12
    assert orch._parse_optional_profile_id(12, field='auth profile') == 12
    with pytest.raises(ServiceError, match='must be a profile id'):
        orch._parse_optional_profile_id('abc', field='auth profile')
    with pytest.raises(ServiceError, match='must be a profile id'):
        orch._parse_optional_profile_id(0, field='auth profile')


def test_hydrate_auth_profile_ids_from_result_json_does_not_override_extra():
    from types import SimpleNamespace

    ex = SimpleNamespace(result_json='{"auth_profile_id": 3, "secondary_auth_profile_id": 7}')
    ctx = _ctx()
    stored = orch._hydrate_auth_profile_ids(ctx, ex)
    assert stored == {'auth_profile_id': 3, 'secondary_auth_profile_id': 7}
    assert ctx.extra['auth_profile_id'] == 3
    assert ctx.extra['secondary_auth_profile_id'] == 7
    ctx2 = _ctx({'auth_profile_id': 99, 'secondary_auth_profile_id': 8})
    orch._hydrate_auth_profile_ids(ctx2, ex)
    assert ctx2.extra['auth_profile_id'] == 99
    assert ctx2.extra['secondary_auth_profile_id'] == 8


def test_optional_form_id_parses_blank_and_numeric():
    from attestra.automated_vapt import routes

    assert routes._optional_form_id('', field='auth profile') is None
    assert routes._optional_form_id(None, field='auth profile') == None
    assert routes._optional_form_id('4', field='secondary auth profile') == 4
    with pytest.raises(ServiceError, match='must be a profile id'):
        routes._optional_form_id('nope', field='auth profile')
