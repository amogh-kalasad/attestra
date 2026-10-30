"""Start Worker / Stop Worker buttons on the engagement page (subprocess.Popen is mocked)."""
from __future__ import annotations

import os
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from attestra import config, db
from attestra.api import app
from attestra.auth.keys import create_user
from attestra.jobs import launcher
from attestra.jobs.instance_lock import InstanceLock, pid_alive
from attestra.jobs.pool import WorkerPool
from attestra.models import Asset, Engagement


class _FakeProc:
    def __init__(self, pid: int):
        self.pid = pid


@pytest.fixture
def popen(monkeypatch):
    calls: list[tuple[list, dict]] = []

    def fake(cmd, **kw):
        calls.append((cmd, kw))
        return _FakeProc(os.getpid())  # a live PID, like a real child

    monkeypatch.setattr(launcher.subprocess, "Popen", fake)
    return calls


@pytest.fixture(autouse=True)
def _local_env(monkeypatch):
    monkeypatch.setenv("APP_ENV", "local")
    monkeypatch.delenv(launcher.ALLOW_FLAG, raising=False)
    monkeypatch.delenv("ATTESTRA_ORCHESTRATOR", raising=False)


def _client(engagement: int, role: str = "lead") -> TestClient:
    name = f"wb-{role}"
    with db.session() as s:
        tid = s.get(Engagement, engagement).tenant_id
        u = create_user(s, username=name, role=role, password="pw-1234567890", display_name=name)
        u.tenant_id = tid
    c = TestClient(app)
    c.post("/login", data={"username": name, "password": "pw-1234567890"}, follow_redirects=False)
    return c


def _queue_one(c: TestClient, engagement: int) -> None:
    with db.session() as s:
        aid = s.scalars(
            select(Asset).where(Asset.engagement_id == engagement, Asset.identifier == "services/payments")
        ).first().id
    r = c.post(
        f"/engagements/{engagement}/scans",
        data={"asset_id": str(aid), "tool": ["semgrep"], "profile": "baseline"},
        follow_redirects=False,
    )
    assert r.status_code == 303


def _flash(r) -> dict[str, str]:
    assert r.status_code == 303, r.text
    q = parse_qs(urlparse(r.headers["location"]).query)
    return {k: v[0] for k, v in q.items()}


def _hold_lock(pid: int | None = None) -> None:
    config.ensure_dirs()
    launcher.lock_path().write_text(str(pid or os.getpid()))


# ------------------------------------------------------------------ visibility


def test_button_hidden_without_queued_scans(engagement):
    c = _client(engagement)
    html = c.get(f"/engagements/{engagement}").text
    assert "Worker Not Running" in html
    assert 'id="start_worker"' not in html


def test_button_shown_when_scan_queued_and_no_worker(engagement):
    c = _client(engagement)
    _queue_one(c, engagement)
    html = c.get(f"/engagements/{engagement}").text
    assert 'id="start_worker"' in html
    assert "Start Worker" in html
    assert f'action="/engagements/{engagement}/worker/start"' in html


def test_button_hidden_and_running_shown_when_worker_alive(engagement):
    c = _client(engagement)
    _queue_one(c, engagement)
    _hold_lock()
    html = c.get(f"/engagements/{engagement}").text
    assert "Worker Running" in html
    assert 'id="start_worker"' not in html
    assert 'id="stop_worker"' in html


def test_button_hidden_for_tester_role(engagement):
    c = _client(engagement, role="tester")
    _queue_one(c, engagement)
    html = c.get(f"/engagements/{engagement}").text
    assert 'id="start_worker"' not in html
    assert "attestra worker" in html


def test_button_hidden_in_production(engagement, monkeypatch):
    c = _client(engagement)
    _queue_one(c, engagement)
    monkeypatch.setenv("APP_ENV", "production")
    html = c.get(f"/engagements/{engagement}").text
    assert 'id="start_worker"' not in html


# ------------------------------------------------------------------ start


def test_start_spawns_once(engagement, popen):
    c = _client(engagement)
    _queue_one(c, engagement)
    r = c.post(f"/engagements/{engagement}/worker/start", follow_redirects=False)
    flash = _flash(r)
    assert "Worker started" in flash["msg"], flash
    assert len(popen) == 1
    cmd, kw = popen[0]
    assert cmd[0] == os.sys.executable and cmd[-1] == "worker"
    assert kw["stdin"] is launcher.subprocess.DEVNULL
    assert kw["env"]["PYTHONUNBUFFERED"] == "1"
    if os.name == "nt":
        assert kw["creationflags"] & launcher.CREATE_NEW_PROCESS_GROUP
        assert kw["creationflags"] & launcher.CREATE_NO_WINDOW
    else:
        assert kw["start_new_session"] is True
    assert launcher.marker_path().exists()
    assert "started from the web page by wb-lead" in launcher.log_path().read_text()

    # Second click while the first worker is still starting: refused, no second spawn.
    r = c.post(f"/engagements/{engagement}/worker/start", follow_redirects=False)
    assert "already starting" in _flash(r)["error"]
    assert len(popen) == 1


def test_start_refused_when_worker_already_running(engagement, popen):
    c = _client(engagement)
    _queue_one(c, engagement)
    _hold_lock()
    r = c.post(f"/engagements/{engagement}/worker/start", follow_redirects=False)
    assert "already running" in _flash(r)["error"]
    assert popen == []


def test_start_refused_in_production(engagement, popen, monkeypatch):
    c = _client(engagement)
    _queue_one(c, engagement)
    monkeypatch.setenv("APP_ENV", "production")
    r = c.post(f"/engagements/{engagement}/worker/start", follow_redirects=False)
    err = _flash(r)["error"]
    assert "APP_ENV=production" in err and launcher.ALLOW_FLAG in err
    assert popen == []


def test_production_allowed_with_explicit_flag(engagement, popen, monkeypatch):
    c = _client(engagement)
    _queue_one(c, engagement)
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv(launcher.ALLOW_FLAG, "true")
    r = c.post(f"/engagements/{engagement}/worker/start", follow_redirects=False)
    assert "Worker started" in _flash(r)["msg"]
    assert len(popen) == 1


def test_start_refused_for_tester(engagement, popen):
    c = _client(engagement, role="tester")
    _queue_one(c, engagement)
    r = c.post(f"/engagements/{engagement}/worker/start", follow_redirects=False)
    assert "admin or lead" in _flash(r)["error"]
    assert popen == []


def test_start_refused_with_temporal(engagement, popen, monkeypatch):
    monkeypatch.setattr(config, "ORCHESTRATOR", "temporal", raising=False)
    allowed, why = launcher.ui_control_allowed()
    assert not allowed and "Temporal" in why
    with pytest.raises(launcher.WorkerControlError):
        launcher.start_worker(actor="t")
    assert popen == []


def test_dead_lock_holder_does_not_block_start(engagement, popen):
    _hold_lock(pid=2_000_000_000)  # no such process
    assert not launcher.worker_status().running
    launcher.start_worker(actor="t")
    assert len(popen) == 1


def test_unrefreshed_lock_of_live_process_counts_as_running(engagement, popen):
    _hold_lock()
    os.utime(launcher.lock_path(), (1, 1))
    st = launcher.worker_status()
    assert st.running and st.stale_lock
    with pytest.raises(launcher.WorkerControlError):
        launcher.start_worker(actor="t")
    assert popen == []


# ------------------------------------------------------------------ stop


def test_stop_writes_stop_file_and_pool_exits(engagement, popen):
    c = _client(engagement)
    r = c.post(f"/engagements/{engagement}/worker/stop", follow_redirects=False)
    assert "No worker is running" in _flash(r)["error"]
    _hold_lock()
    r = c.post(f"/engagements/{engagement}/worker/stop", follow_redirects=False)
    assert "Stop requested" in _flash(r)["msg"]
    stop = launcher.stop_path()
    assert stop.exists()

    pool = WorkerPool(worker_id="t", concurrency=1, poll=0.05, housekeeping=False, stop_file=stop, log=lambda m: None)
    pool.run_forever()  # returns at once because the stop file exists
    assert not stop.exists()


def test_pool_touches_lock_file(fresh_db, tmp_path):
    lock = tmp_path / ".lock-worker"
    lock.write_text(str(os.getpid()))
    os.utime(lock, (1, 1))
    pool = WorkerPool(worker_id="t", concurrency=1, housekeeping=False, lock_file=lock, log=lambda m: None)
    pool.tick()
    assert lock.stat().st_mtime > 1000


# ------------------------------------------------------------------ lock helpers


def test_pid_alive():
    assert pid_alive(os.getpid())
    assert not pid_alive(2_000_000_000)
    assert not pid_alive(0)


def test_instance_lock_refuses_while_holder_alive_and_frees_dead(fresh_db):
    _hold_lock()
    assert InstanceLock("worker").acquire(timeout=0.3) is False
    _hold_lock(pid=2_000_000_000)
    lk = InstanceLock("worker")
    assert lk.acquire(timeout=1.0) is True
    lk.release()