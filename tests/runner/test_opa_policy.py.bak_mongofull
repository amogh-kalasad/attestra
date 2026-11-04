"""Phase 6.3 - OPA/Rego scope policy.

* Parity table: the same cases as policy/scope_test.rego, run against the
  Python mirror and (when the ``opa`` binary exists) against real OPA.
* ``opa test policy/`` runs when OPA is installed, otherwise skipped.
* The HTTP client is tested with a mocked OPA server response.
* Every OPA failure mode must refuse (fail closed).
"""
from __future__ import annotations

import io
import json
import subprocess
import urllib.error
from pathlib import Path

import pytest

from attestra.runner import policy

POLICY_DIR = Path(__file__).resolve().parents[2] / "policy"
OPA = policy.opa_binary()
needs_opa = pytest.mark.skipif(not OPA, reason="opa CLI not installed (set ATTESTRA_OPA_BIN or put opa on PATH)")

BASE = {
    "asset_found": True,
    "engagement_status": "active",
    "asset_environment": "staging",
    "authorized_environments": ["staging"],
    "today": "2026-10-14",
    "window_start": "2026-10-10",
    "window_end": "2026-10-20",
    "tool": "zap",
    "profile": "baseline",
    "intrusive_allowed": False,
    "recent_scan_count": 0,
    "rate_limit": 10,
    "asset_kind": "web_app",
    "ownership_verified": True,
}

# (id, patch, expected reason; "" means allow)
CASES = [
    ("allow_baseline", {}, ""),
    ("missing_asset", {"asset_found": False}, "asset not found for engagement"),
    ("halted", {"engagement_status": "halted"}, "engagement is halted"),
    ("expired_auth", {"authorized_environments": []}, "no valid authorization for asset environment"),
    ("wrong_env", {"asset_environment": "production"}, "no valid authorization for asset environment"),
    ("before_window", {"today": "2026-10-01"}, "before engagement window"),
    ("after_window", {"today": "2026-11-30"}, "after engagement window"),
    ("open_window", {"window_start": None, "window_end": None, "today": "2030-01-01"}, ""),
    ("active_no_flag", {"profile": "active"}, "intrusive/active profile not allowed on asset"),
    ("nuclei_intrusive_no_flag", {"tool": "nuclei", "profile": "Intrusive"}, "intrusive/active profile not allowed on asset"),
    ("nuclei_active_flag", {"tool": "nuclei", "profile": "active", "intrusive_allowed": True}, ""),
    ("zap_intrusive_not_gated", {"tool": "zap", "profile": "intrusive"}, ""),
    ("rate_exceeded", {"recent_scan_count": 10}, "scan rate limit exceeded for asset"),
    ("rate_below", {"recent_scan_count": 9}, ""),
    ("unverified_owner", {"ownership_verified": False}, "asset ownership not verified"),
    ("repo_skips_owner", {"ownership_verified": False, "asset_kind": "repo"}, ""),
    ("order_halted_first", {"engagement_status": "halted", "today": "2026-11-30"}, "engagement is halted"),
    ("wrong_type", {"recent_scan_count": "0"}, policy.INVALID_INPUT),
]


def _inp(patch):
    d = dict(BASE)
    d.update(patch)
    return d


@pytest.mark.parametrize("patch,reason", [c[1:] for c in CASES], ids=[c[0] for c in CASES])
def test_python_mirror(patch, reason):
    d = policy.evaluate_python(_inp(patch))
    assert d.allow is (reason == "")
    assert d.reason == reason


def test_python_mirror_empty_and_missing_field_deny():
    assert policy.evaluate_python({}) == policy.Decision(False, policy.INVALID_INPUT)
    partial = dict(BASE)
    partial.pop("ownership_verified")
    assert policy.evaluate_python(partial).allow is False


@needs_opa
@pytest.mark.parametrize("patch,reason", [c[1:] for c in CASES], ids=[c[0] for c in CASES])
def test_opa_cli_matches_mirror(patch, reason):
    d = policy.evaluate_opa_cli(_inp(patch), pdir=POLICY_DIR)
    assert d == policy.evaluate_python(_inp(patch))
    assert d.reason == reason


@needs_opa
def test_opa_policy_suite():
    proc = subprocess.run([OPA, "test", str(POLICY_DIR), "-v"], capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr


# ------------------------------------------------------------------ HTTP client (mocked)


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _opener(payload, seen=None):
    def _open(req, timeout=None):
        if seen is not None:
            seen.append((req.full_url, json.loads(req.data), timeout))
        return _Resp(json.dumps(payload).encode())

    return _open


def test_http_allow_and_request_shape():
    seen = []
    d = policy.evaluate_opa_http(BASE, url="http://opa:8181", opener=_opener({"result": {"allow": True, "reason": ""}}, seen))
    assert d.allow
    url, body, _ = seen[0]
    assert url == "http://opa:8181/v1/data/attestra/scope/decision"
    assert body == {"input": BASE}


def test_http_refusal_reason_passed_through():
    d = policy.evaluate_opa_http(
        BASE, url="http://opa", opener=_opener({"result": {"allow": False, "reason": "engagement is halted"}})
    )
    assert d == policy.Decision(False, "engagement is halted")


@pytest.mark.parametrize("payload", [{}, {"result": None}, {"result": {"allow": "yes"}}, {"result": []}])
def test_http_malformed_raises(payload):
    with pytest.raises(policy.PolicyError):
        policy.evaluate_opa_http(BASE, url="http://opa", opener=_opener(payload))


def test_http_unreachable_raises():
    def _boom(req, timeout=None):
        raise urllib.error.URLError("connection refused")

    with pytest.raises(policy.PolicyError):
        policy.evaluate_opa_http(BASE, url="http://opa", opener=_boom)


def test_decide_fails_closed_when_opa_down(monkeypatch):
    monkeypatch.setenv("ATTESTRA_POLICY_ENGINE", "opa-http")
    monkeypatch.setenv("ATTESTRA_OPA_URL", "http://127.0.0.1:9")  # discard port, nothing listening
    monkeypatch.setenv("ATTESTRA_OPA_TIMEOUT_S", "0.5")
    d = policy.decide(BASE)
    assert d.allow is False and "policy engine error" in d.reason


def test_decide_fails_closed_without_opa_binary(monkeypatch):
    monkeypatch.setenv("ATTESTRA_POLICY_ENGINE", "opa-cli")
    monkeypatch.setenv("ATTESTRA_OPA_BIN", "")
    monkeypatch.setattr(policy.shutil, "which", lambda _: None)
    assert policy.decide(BASE).allow is False


def test_decide_unknown_engine_refuses(monkeypatch):
    monkeypatch.setenv("ATTESTRA_POLICY_ENGINE", "nope")
    assert policy.decide(BASE).allow is False


# ------------------------------------------------------------------ gate wiring


def _web_asset_id(engagement):
    from sqlalchemy import select

    from attestra import db
    from attestra.models import Asset

    with db.session() as s:
        return s.scalars(select(Asset).where(Asset.engagement_id == engagement, Asset.kind == "web_app")).first().id


def test_gate_uses_policy_decision_and_audits(engagement, monkeypatch):
    from sqlalchemy import select

    from attestra import db
    from attestra.models import AuditEvent
    from attestra.runner import gate

    asset_id = _web_asset_id(engagement)
    seen = []

    def fake_decide(inp):
        seen.append(inp)
        return policy.Decision(False, "refused by test policy")

    monkeypatch.setattr(gate.policy, "decide", fake_decide)
    with db.session() as s:
        with pytest.raises(gate.GateError, match="refused by test policy"):
            gate.check(s, engagement, asset_id, tool="zap", profile="baseline", actor="opa-test")
        events = list(s.scalars(select(AuditEvent).where(AuditEvent.action == "scan.refused")))
        assert any(e.actor == "opa-test" for e in events)
    assert set(seen[0]) == set(policy.REQUIRED_FIELDS)
    assert seen[0]["asset_found"] is True


def test_gate_input_is_valid_for_policy(engagement):
    from attestra import db
    from attestra.runner import gate

    asset_id = _web_asset_id(engagement)
    with db.session() as s:
        inp = gate.policy_input(s, engagement, asset_id, tool="zap", profile="baseline")
    assert policy.evaluate_python(inp).reason != policy.INVALID_INPUT


def test_gate_refuses_when_opa_unreachable(engagement, monkeypatch):
    from attestra import db
    from attestra.runner import gate

    monkeypatch.setenv("ATTESTRA_POLICY_ENGINE", "opa-http")
    monkeypatch.setenv("ATTESTRA_OPA_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("ATTESTRA_OPA_TIMEOUT_S", "0.5")
    asset_id = _web_asset_id(engagement)
    with db.session() as s:
        with pytest.raises(gate.GateError, match="policy engine error"):
            gate.check(s, engagement, asset_id, tool="zap", profile="baseline", actor="tester")
