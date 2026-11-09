"""Phase 1: mid-scan session guard — detection, bounded re-login, blocked-never-passed.

Pure unit tests plus an offline round-trip against the session-expiry lab fixture.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from fastapi.testclient import TestClient

from attestra.auth_web import otp as otp_mod
from attestra.auth_web import scan_auth
from attestra.auth_web import session_guard as sg
from tests.automated_vapt.fixtures import create_session_expiry_app

from attestra.runner.dns_pin import PinnedTarget

BASE = "http://lab.example.test"
_PIN = PinnedTarget(host="h.example", ip="93.184.216.34", port=443, scheme="https")


# ------------------------------------------------------------------ detection


# @lat: [[tests#test_session_guard.py#Expired-response detection]]
def test_looks_expired_signals():
    assert sg.looks_expired(401)[0]
    assert sg.looks_expired(302, headers={"Location": "/login?expired=1"})[0]
    assert sg.looks_expired(303, headers={"location": "https://idp.example.com/oauth2/authorize?x=1"})[0]
    assert sg.looks_expired(200, body='{"error":"SESSION_EXPIRED"}')[0]
    assert sg.looks_expired(403, body='{"detail":"token expired"}')[0]
    assert sg.looks_expired(200, body="<p>Welcome back</p>", cfg={"logged_out_indicator": "Sign in"})[0] is False
    assert sg.looks_expired(200, body="<a>Sign in</a>", cfg={"logged_out_indicator": "Sign in"})[0]
    # Authorization-only 403 and ordinary pages/redirects are not auth loss.
    assert not sg.looks_expired(403, body='{"detail":"forbidden"}')[0]
    assert not sg.looks_expired(200, body="<html><body><h1>Dashboard</h1></body></html>")[0]
    assert not sg.looks_expired(302, headers={"Location": "/app/projects"})[0]
    assert not sg.looks_expired(None)[0]


def test_config_flags(monkeypatch):
    monkeypatch.delenv("ATTESTRA_AUTH_MIDSCAN_ENABLED", raising=False)
    assert sg.midscan_enabled()
    monkeypatch.setenv("ATTESTRA_AUTH_MIDSCAN_ENABLED", "0")
    assert not sg.midscan_enabled()
    monkeypatch.setenv("ATTESTRA_AUTH_RELOGIN_MAX", "99")
    assert sg.relogin_max() == 10
    monkeypatch.setenv("ATTESTRA_AUTH_RELOGIN_MAX", "bad")
    assert sg.relogin_max() == 2
    monkeypatch.setenv("ATTESTRA_AUTH_HEARTBEAT_S", "1")
    assert sg.heartbeat_s() == 10


# ------------------------------------------------------------------ guard state machine


def _guard(verify_results, relogin_results, **kw):
    v_iter = iter(verify_results)
    r_iter = iter(relogin_results)

    def _verify(h, c):
        return next(v_iter)

    def _relogin():
        return next(r_iter)

    kw.setdefault("min_interval_s", 0)
    return sg.SessionGuard(verify=_verify, relogin=_relogin, headers={"Cookie": "sid=OLD"}, method="form", **kw)


def _material(sid: str) -> sg.SessionMaterial:
    return sg.SessionMaterial(headers={}, cookies={"sid": sid}, note="form login ok", redact_values=(sid,))


# @lat: [[tests#test_session_guard.py#Guard re-login rotates material and notifies]]
def test_guard_recovers_and_notifies_renew():
    g = _guard([(False, "login check got HTTP 401"), (True, "ok")], [_material("NEWSESSION1")], max_relogins=2)
    renewed = []
    g.on_renew.append(lambda m: renewed.append(dict(m.cookies)))
    ok, note = g.check_and_recover()
    assert ok and "re-established" in note
    assert g.status == "recovered" and g.relogins == 1
    assert g.cookies == {"sid": "NEWSESSION1"} and renewed == [{"sid": "NEWSESSION1"}]
    assert "NEWSESSION1" in g.redact_values
    assert sg.AUTH_RECOVERED_MARKER in g.note()
    # Events never carry the secret value.
    assert "NEWSESSION1" not in json.dumps(g.public())
    assert g.alive() == (True, "ok")


# @lat: [[tests#test_session_guard.py#Guard marks lost after budget and never passes]]
def test_guard_budget_exhausted_is_lost():
    g = _guard([(False, "login check got HTTP 401")] * 5, [None, None, None], max_relogins=2)
    ok, note = g.check_and_recover()
    assert not ok and g.lost and g.failed_relogins == 2
    assert "re-login failed" in g.lost_reason
    assert g.note().startswith(sg.AUTH_LOSS_MARKER)
    # Once lost, no more checks or re-logins happen.
    assert g.alive()[0] is False and g.recover() is False and g.checks == 1
    kinds = [e["kind"] for e in g.events]
    assert kinds.count("relogin_failed") == 2 and kinds[-1] == "lost"


def test_guard_zero_budget_and_disabled():
    g = _guard([(False, "HTTP 401")], [], max_relogins=0)
    assert g.check_and_recover()[0] is False and "budget exhausted" in g.lost_reason
    d = sg.disabled_guard()
    assert d.alive() == (True, "mid-scan session guard disabled")
    assert d.recover("x") is False and d.lost


def test_guard_rate_limits_relogin_attempts():
    clock = {"t": 100.0}
    slept = []
    g = _guard([(False, "401"), (False, "401")], [None, _material("S2")], max_relogins=3,
               clock=lambda: clock["t"], sleep=lambda s: slept.append(s))
    g.min_interval_s = 5
    # First attempt fails; the retry inside the same recover() waits out the interval first.
    assert g.check_and_recover()[0] is True
    assert g.failed_relogins == 1 and g.relogins == 1 and not g.lost
    assert slept == [5.0]


def test_guard_relogin_exception_counts_as_failure():
    def _boom():
        raise RuntimeError("transport down")

    g = sg.SessionGuard(verify=lambda h, c: (False, "401"), relogin=_boom, max_relogins=1, min_interval_s=0)
    assert g.check_and_recover()[0] is False and g.lost
    assert any(e["kind"] == "relogin_error" for e in g.events)


# ------------------------------------------------------------------ attempt_relogin


def _reply(status=200, cookies=None):
    return otp_mod.HttpReply(status=status, body="", cookies=dict(cookies or {}), final_url="https://app.example.com/app")


# @lat: [[tests#test_session_guard.py#Re-login paths per auth method]]
def test_attempt_relogin_form_and_static_methods():
    cfg = {"login_url": "https://app.example.com/login", "username": "u", "verify_url": "https://app.example.com/me"}
    mat = sg.attempt_relogin(
        "form", cfg, "PW", http_post=lambda u, d, c: _reply(cookies={"sid": "FRESH"}),
        login_probe=lambda u, h: (200, "{}"), extra_cookies=[("extra", "E1")],
    )
    assert mat is not None and mat.cookies == {"sid": "FRESH", "extra": "E1"}
    assert "FRESH" in mat.redact_values and mat.request_headers()["Cookie"] == "sid=FRESH; extra=E1"
    # Verify failure after a login → None.
    assert sg.attempt_relogin(
        "form", cfg, "PW", http_post=lambda u, d, c: _reply(cookies={"sid": "X"}),
        login_probe=lambda u, h: (401, ""),
    ) is None
    # Login itself failing → None, no exception.
    assert sg.attempt_relogin(
        "form", cfg, "PW", http_post=lambda u, d, c: _reply(status=401), login_probe=lambda u, h: (200, ""),
    ) is None
    # Static header/cookie profiles cannot be renewed without an opt-in refresh_url.
    assert sg.attempt_relogin("header", {}, "TOKEN", http_post=lambda *a: _reply(), login_probe=lambda u, h: (200, "")) is None
    assert sg.attempt_relogin("sso_bootstrap", cfg, "x", http_post=None, login_probe=lambda u, h: (200, "")) is None
    refreshed = sg.attempt_relogin(
        "cookie", {"cookie_name": "sid", "refresh_url": "https://app.example.com/api/session/refresh"}, "OLD",
        http_post=lambda u, d, c: _reply(cookies={"sid": "ROTATED"}), login_probe=lambda u, h: (200, ""),
        current_cookies={"sid": "OLD"},
    )
    assert refreshed is not None and refreshed.cookies["sid"] == "ROTATED" and "refresh_url" in refreshed.note


# ------------------------------------------------------------------ lab round-trip


def _lab_guard(app, client: TestClient, *, password: str, max_requests: int):
    cfg = {"verify_url": f"{BASE}/api/me", "login_url": f"{BASE}/login", "username": "account_a"}

    def _probe(url, headers):
        r = client.get(url.replace(BASE, ""), headers={k: v for k, v in headers.items() if k.lower() != "cookie"},
                       cookies=_cookies_from(headers))
        return r.status_code, r.text

    def _post(url, data, cookies):
        r = client.post(url.replace(BASE, ""), data=data, follow_redirects=False)
        return otp_mod.HttpReply(status=r.status_code, body=r.text, cookies=dict(r.cookies), final_url=url)

    return sg.build_guard(
        method="form", cfg=cfg, secret=password, headers={}, cookies={},
        http_post=_post, login_probe=_probe, enabled=True, max_relogins=2,
    )


def _cookies_from(headers):
    raw = headers.get("Cookie") or ""
    return {k.strip(): v for k, v in (p.split("=", 1) for p in raw.split(";") if "=" in p)}


# @lat: [[tests#test_session_guard.py#Lab fixture round-trip]]
def test_lab_session_expires_then_relogin_succeeds():
    app = create_session_expiry_app(max_requests=2)
    client = TestClient(app, base_url=BASE)
    client.cookies.clear()
    g = _lab_guard(app, client, password="account-a-pass", max_requests=2)
    g.min_interval_s = 0
    # Fresh guard has no session yet: first check fails (401) and the re-login creates one.
    ok, _ = g.check_and_recover()
    assert ok and g.relogins == 1 and app.state.expiry.relogin_count == 1
    # Exhaust the session budget, then the guard must detect the loss and log in again.
    sid = g.cookies["mock_session"]
    client.cookies.clear()
    for _ in range(3):
        client.get("/api/me", cookies={"mock_session": sid})
    client.cookies.clear()
    ok, note = g.check_and_recover()
    assert ok and g.relogins == 2 and "re-established" in note
    assert g.cookies["mock_session"] != sid
    assert sg.AUTH_RECOVERED_MARKER in g.note()


def test_lab_relogin_with_bad_credentials_blocks():
    app = create_session_expiry_app(max_requests=1)
    client = TestClient(app, base_url=BASE)
    g = _lab_guard(app, client, password="wrong", max_requests=1)
    g.min_interval_s = 0
    ok, _ = g.check_and_recover()
    assert not ok and g.lost and g.failed_relogins == 2
    assert app.state.expiry.relogin_count == 0
    assert g.note().startswith(sg.AUTH_LOSS_MARKER)


# ------------------------------------------------------------------ prepare_for_run wiring


class _FakeSession:
    def __init__(self, profile):
        self._p = profile

    def get(self, _model, pid):
        return self._p if pid == self._p.id else None


def _profile(**kw):
    base = dict(
        id=7, engagement_id=1, status="valid", method="form", label="p", role_name="", secret_ref="ref-1",
        login_url="https://api.example.com/login", username_selector="", password_selector="", submit_selector="",
        success_url_contains="", config_json={"verify_url": "https://api.example.com/me", "username": "bob"},
        extra_headers="", extra_cookies_ref="", extra_cookie_names="",
    )
    base.update(kw)
    return SimpleNamespace(**base)


@pytest.fixture
def secrets(monkeypatch):
    from attestra import credentials

    monkeypatch.setattr(credentials, "get_secret", lambda ref: "PW1")


# @lat: [[tests#test_session_guard.py#Plan carries a guard that rewrites tool files]]
def test_prepare_for_run_attaches_guard_and_rewrites_nuclei_file(tmp_path, secrets, monkeypatch):
    monkeypatch.delenv("ATTESTRA_AUTH_MIDSCAN_ENABLED", raising=False)
    sids = iter(["SESSION1", "SESSION2"])
    post = lambda u, d, c: _reply(cookies={"sid": next(sids)})  # noqa: E731
    plan = scan_auth.prepare_for_run(
        _FakeSession(_profile()), SimpleNamespace(id=5, engagement_id=1, auth_profile_id=7), tmp_path / "raw",
        tool="nuclei", target_url="https://api.example.com/", http_post=post,
        login_probe=lambda u, h: (200, "{}"), secret_dir=tmp_path / "sec",
    )
    assert plan.guard is not None and plan.guard.enabled
    assert plan.nuclei_kwargs()["session_guard"] is plan.guard
    before = yaml.safe_load(Path(plan.nuclei_secret_file).read_text())["static"][0]["headers"]
    assert {"key": "Cookie", "value": "sid=SESSION1"} in before
    assert plan.guard.recover("forced") is True
    after = yaml.safe_load(Path(plan.nuclei_secret_file).read_text())["static"][0]["headers"]
    assert {"key": "Cookie", "value": "sid=SESSION2"} in after
    assert "SESSION2" in plan.guard.redact_values
    plan.cleanup()
    assert plan.guard is None


def test_prepare_for_run_guard_disabled_by_env(tmp_path, secrets, monkeypatch):
    monkeypatch.setenv("ATTESTRA_AUTH_MIDSCAN_ENABLED", "0")
    plan = scan_auth.prepare_for_run(
        _FakeSession(_profile()), SimpleNamespace(id=5, engagement_id=1, auth_profile_id=7), tmp_path / "raw",
        tool="zap", target_url="https://api.example.com/", http_post=lambda u, d, c: _reply(cookies={"sid": "S1"}),
        login_probe=lambda u, h: (200, "{}"), secret_dir=tmp_path / "sec",
    )
    assert plan.guard is not None and not plan.guard.enabled
    assert "session_guard" not in plan.zap_kwargs()
    plan.cleanup()


# ------------------------------------------------------------------ nuclei chunk loop


# @lat: [[tests#test_session_guard.py#Nuclei chunks re-verify between runs]]
def test_nuclei_chunk_loop_verifies_between_chunks_and_blocks_rest(tmp_path, monkeypatch):
    from attestra.runner.scanners import nuclei as nmod

    monkeypatch.setenv("ATTESTRA_AUTH_NUCLEI_CHUNK", "2")
    seen: list[list[str]] = []

    def _fake_scan_nuclei(self, pin, *, out_dir, target_urls=None, redact_values=(), **kw):
        from attestra.runner.scanners.base import ScannerResult

        seen.append(list(target_urls or []))
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / self.out_name).write_text(json.dumps({"chunk": len(seen)}) + "\n")
        (out_dir / self.tool_log_name).write_text("log\n")
        return ScannerResult(tool="nuclei", tool_version="t", raw_path=out_dir / self.out_name, extra={"returncode": 0})

    monkeypatch.setattr(nmod.NucleiAdapter, "_scan_nuclei", _fake_scan_nuclei)
    monkeypatch.setattr(nmod, "_discover_urls", lambda *a, **k: None)
    monkeypatch.setattr(nmod, "_target_urls", lambda t, c: [f"https://h.example/{i}" for i in range(6)])

    verify = iter([(True, "ok"), (False, "login check got HTTP 401")])
    guard = sg.SessionGuard(verify=lambda h, c: next(verify), relogin=lambda: None, max_relogins=1, min_interval_s=0)
    sr = nmod.NucleiAdapter().scan(
        _PIN, out_dir=tmp_path, crawl=SimpleNamespace(start_urls=[], discovered_urls=[], notes=[], url_source="x", scope=None),
        auth_secret_file=str(tmp_path / "sec" / "a.yaml"), session_guard=guard,
    )
    # Chunk 1 ran, check ok → chunk 2 ran, check failed + no relogin → chunk 3 blocked.
    assert [len(c) for c in seen] == [2, 2]
    assert sr.raw_path is not None and sr.raw_path.read_text().count("\n") == 2
    assert sr.extra["auth"]["status"] == "lost"
    assert sr.extra["auth_blocked_urls"] == ["https://h.example/4", "https://h.example/5"]
    assert [c["status"] for c in sr.extra["chunks"]] == ["done", "done", "blocked"]
    assert "blocked" in sr.extra["crawl"]["notes"][-1]
    assert sr.extra["crawl"]["urls_scanned"] == 4


def test_nuclei_chunk_loop_relogin_keeps_going(tmp_path, monkeypatch):
    from attestra.runner.scanners import nuclei as nmod

    monkeypatch.setenv("ATTESTRA_AUTH_NUCLEI_CHUNK", "3")
    seen: list[list[str]] = []

    def _fake(self, pin, *, out_dir, target_urls=None, **kw):
        from attestra.runner.scanners.base import ScannerResult

        seen.append(list(target_urls or []))
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / self.out_name).write_text("")
        return ScannerResult(tool="nuclei", raw_path=out_dir / self.out_name, extra={"returncode": 0})

    monkeypatch.setattr(nmod.NucleiAdapter, "_scan_nuclei", _fake)
    monkeypatch.setattr(nmod, "_discover_urls", lambda *a, **k: None)
    monkeypatch.setattr(nmod, "_target_urls", lambda t, c: [f"https://h.example/{i}" for i in range(7)])
    verify = iter([(False, "401"), (True, "ok"), (True, "ok")])
    renewed = []
    guard = sg.SessionGuard(verify=lambda h, c: next(verify), relogin=lambda: _material("N1"), max_relogins=2, min_interval_s=0)
    guard.on_renew.append(lambda m: renewed.append(m.cookies["sid"]))
    sr = nmod.NucleiAdapter().scan(
        _PIN, out_dir=tmp_path, crawl=SimpleNamespace(start_urls=[], discovered_urls=[], notes=[], url_source="x", scope=None),
        auth_secret_file="x.yaml", session_guard=guard,
    )
    assert [len(c) for c in seen] == [3, 3, 1]
    assert renewed == ["N1"] and sr.extra["auth"]["relogins"] == 1
    assert "auth_blocked_urls" not in sr.extra
    assert sr.extra["crawl"]["notes"][-1].startswith("authenticated session re-established")
    assert sg.auth_note_after_scan("form login ok", sr.extra).endswith("re-established 1x mid-scan")


def test_auth_note_after_scan_and_marker():
    lost = {"auth": {"status": "lost", "lost_reason": "401; re-login failed"}, "auth_blocked_urls": ["a", "b"]}
    note = sg.auth_note_after_scan("login check passed", lost)
    assert note.startswith("login check passed; " + sg.AUTH_LOSS_MARKER) and "2 URL(s)" in note
    assert sg.note_has_auth_loss(note) and not sg.note_has_auth_loss("login check passed")
    assert sg.auth_note_after_scan("x", {"auth": {"status": "ok", "relogins": 0}}) == "x"
    assert sg.auth_note_after_scan("x", None) == "x"


# ------------------------------------------------------------------ automated VAPT + checklist


# @lat: [[tests#test_session_guard.py#Automated cases are BLOCKED on unrecovered loss]]
def test_orchestrator_blocks_session_cases_after_loss(monkeypatch):
    from attestra.automated_vapt.core import orchestrator as orch
    from attestra.automated_vapt.core.session_auth import SessionAuth
    from attestra.automated_vapt.core.test_context import TestContext

    auth = SessionAuth(profile_id=1, status="ready", note="ok", headers={"Cookie": "sid=OLD"})
    auth.guard = sg.SessionGuard(verify=lambda h, c: (False, "login check got HTTP 401"), relogin=lambda: None,
                                 headers={}, cookies={"sid": "OLD"}, max_relogins=1, min_interval_s=0)
    ctx = TestContext(engagement_id=1, tenant_id=1, asset_id=1, target_base_url="https://app.example.com/",
                      test_case_ids=["T19", "T20"], profile="baseline", actor="t", allow_private=False,
                      extra={"_session_auth": auth})
    assert orch._ensure_session_for_case("T01", ctx) is None  # not session-dependent
    blocked = orch._ensure_session_for_case("T19", ctx)
    assert blocked["status"] == "BLOCKED" and blocked["skip_reason"] == "auth_lost"
    assert "re-login failed" in blocked["detail"] and auth.status == "lost" and auth.headers == {}
    assert ctx.extra["_auth_events"][-1]["kind"] == "lost"
    # Subsequent session cases stay blocked without more checks.
    again = orch._ensure_session_for_case("T20", ctx)
    assert again["status"] == "BLOCKED" and auth.guard.checks == 1
    # Public dict is value-free and reports the mid-scan state.
    pub = auth.public()
    assert pub["midscan"]["status"] == "lost" and "OLD" not in json.dumps(pub)


def test_orchestrator_relogin_updates_session_headers():
    from attestra.automated_vapt.core import orchestrator as orch
    from attestra.automated_vapt.core.session_auth import SessionAuth
    from attestra.automated_vapt.core.test_context import TestContext

    auth = SessionAuth(profile_id=1, status="ready", note="ok", headers={"Cookie": "sid=OLD"}, redact_values=("OLD1",))
    verify = iter([(False, "401"), (True, "ok")])
    auth.guard = sg.SessionGuard(verify=lambda h, c: next(verify), relogin=lambda: _material("NEWSID"),
                                 headers={}, cookies={"sid": "OLD"}, max_relogins=2, min_interval_s=0)
    ctx = TestContext(engagement_id=1, tenant_id=1, asset_id=1, target_base_url="https://app.example.com/",
                      test_case_ids=["SESSION"], profile="baseline", actor="t", allow_private=False,
                      extra={"_session_auth": auth})
    assert orch._ensure_session_for_case("SESSION", ctx) is None
    assert auth.status == "ready" and auth.headers == {"Cookie": "sid=NEWSID"}
    assert "NEWSID" in auth.redact_values and "OLD1" in auth.redact_values
    assert ctx.extra["_auth_events"][-1]["kind"] == "relogin_ok"


def test_session_auth_without_guard_is_assumed_alive():
    from attestra.automated_vapt.core.session_auth import SessionAuth

    assert SessionAuth(status="ready", headers={"Cookie": "x=y"}).ensure_alive() == (True, "no mid-scan guard")
    assert SessionAuth(status="none", note="n").ensure_alive() == (True, "n")
    assert SessionAuth(status="failed", note="bad").ensure_alive() == (False, "bad")


# @lat: [[tests#test_session_guard.py#Checklist maps BLOCKED and auth-lost scans to blocked]]
def test_checklist_blocked_status_and_auth_lost_import():
    from attestra.auth_web import checklist_auto as ca

    ex = SimpleNamespace(
        id=3, status="COMPLETED",
        result_json=json.dumps({"cases": [
            {"test_id": "T19", "status": "BLOCKED", "detail": "blocked: authenticated session lost mid-run"},
            {"test_id": "T20", "status": "BLOCKED", "detail": "blocked: auth lost"},
        ]}),
    )
    verdicts = ca.verdicts_for_automated(None, ex)
    assert {v.ref for v in verdicts} == {"WSTG-ATHN-04", "WSTG-ATHZ-04"}
    assert all(v.status == "blocked" and v.text.startswith("blocked:") for v in verdicts)

    # ZAP import on a scan whose session was lost: "no alerts" rows become blocked.
    rows = [{"id": f"zap/{r}", "status": "passed"} for spec in ca.ZAP_MAP.values() for r in spec.get("pass") or ()]
    run = SimpleNamespace(id=9, tool="zap", checks_json=json.dumps({"checks": rows}), scan_run_id=1)
    scan = SimpleNamespace(id=1, authenticated=True, auth_note=f"form login ok; {sg.AUTH_LOSS_MARKER} 401; re-login failed", profile="baseline")
    import attestra.auth_web.checklist_auto as mod

    orig = (mod._scan_for_import, mod._observations)
    mod._scan_for_import = lambda s, r: scan
    mod._observations = lambda s, rid: []
    try:
        out = ca.verdicts_for_import(None, run)
    finally:
        mod._scan_for_import, mod._observations = orig
    assert out, "expected pass-rule verdicts from the checks rows"
    assert all(v.status == "blocked" and "session lost mid-scan" in v.text for v in out)
