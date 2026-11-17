"""I-03: maintenance tick scheduler (flag-gated, due-ness, failures isolated)."""
# @lat: [[attack-surface-and-platform#Maintenance tick]]

from __future__ import annotations

import pytest

from attestra import observability as obs
from attestra.jobs import maintenance as M


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    saved = dict(M._TASKS)
    M._TASKS.clear()
    M.reset_state()
    obs.REGISTRY.reset()
    monkeypatch.delenv("ATTESTRA_MAINTENANCE_ENABLED", raising=False)
    yield
    M._TASKS.clear()
    M._TASKS.update(saved)
    M.reset_state()
    obs.REGISTRY.reset()


def test_off_by_default():
    ran = []
    M.register("t", lambda: ran.append(1), interval_s=10)
    assert M.maintenance_enabled() is False
    assert M.tick(now=0) == {} and ran == []


def test_runs_when_due_only(monkeypatch):
    monkeypatch.setenv("ATTESTRA_MAINTENANCE_ENABLED", "1")
    ran = []
    M.register("t", lambda: ran.append(1), interval_s=10)
    assert M.tick(now=100) == {"t": "ok"}
    assert M.tick(now=105) == {"t": "not_due"}
    assert M.tick(now=111) == {"t": "ok"}
    assert len(ran) == 2
    assert obs.REGISTRY.counter_value("attestra_maintenance_runs_total", {"task": "t", "outcome": "ok"}) == 2


def test_failure_isolated_and_logged():
    logs: list[str] = []
    M.register("a_bad", lambda: 1 / 0, interval_s=5)
    ran = []
    M.register("b_good", lambda: ran.append(1), interval_s=5)
    out = M.tick(now=0, log=logs.append, force=True)
    assert out == {"a_bad": "error", "b_good": "ok"} and ran == [1]
    assert "ZeroDivisionError" in logs[0]


def test_disabled_task_and_broken_enabled_callable():
    M.register("off", lambda: None, interval_s=5, enabled=lambda: False)
    M.register("weird", lambda: None, interval_s=5, enabled=lambda: 1 / 0)
    assert M.tick(now=0, force=True) == {"off": "disabled", "weird": "disabled"}


def test_unavailable_by_name():
    M.register("x", M.call_by_name("attestra.no_such_module_wp4", "run"), interval_s=5)
    assert M.tick(now=0, force=True) == {"x": "unavailable"}


def test_call_by_name_finds_first_attr(tmp_path, monkeypatch):
    mod = tmp_path / "wp4_fake_feed.py"
    mod.write_text("calls = []\ndef refresh():\n    calls.append(1)\n    return 'ok'\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    fn = M.call_by_name("wp4_fake_feed", "refresh_all", "refresh")
    assert fn() == "ok"


def test_register_validation_and_idempotent():
    with pytest.raises(ValueError):
        M.register("", lambda: None, interval_s=1)
    with pytest.raises(ValueError):
        M.register("x", lambda: None, interval_s=0)
    M.register("x", lambda: None, interval_s=1)
    M.register("x", lambda: None, interval_s=2)
    assert M.registered() == ["x"]
    M.unregister("x")
    assert M.registered() == []


def test_concurrent_tick_is_skipped():
    M.register("t", lambda: None, interval_s=1)
    assert M._TICK_LOCK.acquire(blocking=False)
    try:
        assert M.tick(now=0, force=True) == {}
    finally:
        M._TICK_LOCK.release()


def test_builtin_feed_refresh_registration(monkeypatch):
    M.register_builtin_tasks()
    assert "intel.feed_refresh" in M.registered()
    t = M._TASKS["intel.feed_refresh"]
    assert t.interval_s >= 600
