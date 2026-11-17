"""FND-07: the automated-VAPT guard refuses what the scope policy refuses (no DB)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from types import SimpleNamespace

import pytest

from attestra.automated_vapt.core import authorization_guard as guard

TODAY = date(2026, 11, 17)


@dataclass
class _Auth:
    signed_on: date
    expires_on: date
    environments: list

    def is_valid(self, on=None):
        on = on or date.today()
        return self.signed_on <= on <= self.expires_on

    def covers(self, environment):
        return not self.environments or environment in self.environments


def _eng(status="active", envs=("staging",), expires=TODAY + timedelta(days=30), window_end=None, window_start=None):
    return SimpleNamespace(
        id=1, status=status, window_start=window_start, window_end=window_end,
        authorizations=[_Auth(TODAY - timedelta(days=5), expires, list(envs))],
    )


@pytest.fixture(autouse=True)
def _signed_auth_required(monkeypatch):
    monkeypatch.setattr(guard.config, "signed_authorization_required", lambda: True)


def _codes(eng, asset=None):
    return [c for c, _ in guard.readiness_problems(eng, asset, today=TODAY)]


# @lat: [[run-validity-and-policy#Engagement readiness]]
def test_halted_is_refused():
    with pytest.raises(guard.ReadinessError) as ei:
        guard.assert_engagement_ready(_eng(status="halted"), today=TODAY)
    assert ei.value.code == guard.REASON_HALTED
    assert guard.not_tested_reason(ei.value) == guard.REASON_HALTED


def test_unknown_status_is_refused():
    assert guard.REASON_STATUS in _codes(_eng(status="paused"))


def test_staging_authorization_does_not_cover_production_asset():
    asset = SimpleNamespace(id=1, environment="production")
    assert guard.REASON_ENV in _codes(_eng(envs=("staging",)), asset)
    assert _codes(_eng(envs=("staging",)), SimpleNamespace(id=1, environment="staging")) == []


def test_expired_authorization_and_window():
    assert guard.REASON_AUTH_EXPIRED in _codes(_eng(expires=TODAY - timedelta(days=1)))
    assert guard.REASON_WINDOW in _codes(_eng(window_end=TODAY - timedelta(days=1)))
    assert guard.REASON_WINDOW in _codes(_eng(window_start=TODAY + timedelta(days=1)))


def test_backward_compatible_without_asset():
    guard.assert_engagement_ready(_eng(), today=TODAY)


def test_per_case_recheck_sees_mid_run_halt():
    eng = _eng()

    class _S:
        def refresh(self, obj):
            obj.status = "halted"

    with pytest.raises(guard.ReadinessError) as ei:
        guard.assert_engagement_ready_for_case(_S(), eng, None, today=TODAY)
    assert ei.value.code == guard.REASON_HALTED


def test_per_case_policy_refusal_maps_code(monkeypatch):
    from attestra.runner import gate, policy

    monkeypatch.setattr(gate, "policy_input", lambda *a, **k: {"x": 1})
    monkeypatch.setattr(policy, "decide", lambda inp: SimpleNamespace(allow=False, reason="asset ownership not verified"))

    class _S:
        def refresh(self, obj):
            pass

    asset = SimpleNamespace(id=2, environment="staging")
    with pytest.raises(guard.ReadinessError) as ei:
        guard.assert_engagement_ready_for_case(_S(), _eng(), asset, today=TODAY)
    assert ei.value.code == guard.REASON_OWNERSHIP


def test_per_case_policy_unavailable_fails_closed(monkeypatch):
    from attestra.runner import gate

    def boom(*a, **k):
        raise RuntimeError("db gone")

    monkeypatch.setattr(gate, "policy_input", boom)
    with pytest.raises(guard.ReadinessError) as ei:
        guard.assert_engagement_ready_for_case(SimpleNamespace(refresh=lambda o: None), _eng(), SimpleNamespace(id=2, environment="staging"), today=TODAY)
    assert ei.value.code == guard.REASON_POLICY
