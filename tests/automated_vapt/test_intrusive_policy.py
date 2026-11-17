"""FND-02: server-side intrusive decision (§3.4); APP_ENV no longer gates targets."""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from attestra.automated_vapt.core import intrusive_policy as ip
from attestra.automated_vapt.testing import file_upload_tests, ssrf_tests
from tests.automated_vapt.fixtures import create_vulnerable_app

BASE = "http://localhost:8765/"
ROOT = Path(__file__).resolve().parents[2]


def _inp(env: str = "dev", **over):
    doc = {
        "asset_environment": env,
        "authorized_environments": [env],
        "intrusive_allowed": True,
        "engagement_status": "active",
        "profile": "baseline",
    }
    doc.update(over)
    return doc


def _allow(_inp):
    return SimpleNamespace(allow=True, reason="")


def _refuse(_inp):
    return SimpleNamespace(allow=False, reason="intrusive profile not allowed")


def _decide(tid="SSRF", *, env="dev", flag=True, profile="active", ack=False, policy=_allow, allowed=None):
    return ip.decide_from_policy_input(
        _inp(env), test_id=tid, profile=profile, env_flag_enabled=flag,
        cleanup_plan_ack=ack, policy_decide=policy,
        allowed=frozenset({"dev", "demo"}) if allowed is None else allowed,
    )


# @lat: [[run-validity-and-policy#Intrusive policy]]
def test_a_flag_off_denies():
    assert _decide(flag=False).reason == ip.R_FLAG_OFF


def test_b_baseline_profile_denies():
    assert _decide(profile="baseline").reason == ip.R_PROFILE


def test_c_policy_refusal_denies():
    d = _decide(policy=_refuse)
    assert not d.allow and d.reason == ip.R_POLICY


def test_d_production_always_refused():
    assert _decide(env="production", allowed=frozenset({"dev", "demo", "production"})).reason == ip.R_ENV_FORBIDDEN
    with pytest.raises(ip.AllowlistError):
        ip.parse_allowed_environments("dev,production")


def test_e_env_outside_allowlist_denies():
    assert _decide(env="staging").reason == ip.R_ENV
    assert _decide(env="").reason == ip.R_ENV_UNKNOWN
    assert _decide(allowed=frozenset()).reason == ip.R_ALLOWLIST_INVALID


def test_f_dev_allowed_and_cleanup_needed_for_writes():
    assert _decide().allow is True
    assert _decide("UPLOAD").reason == ip.R_CLEANUP
    assert _decide("UPLOAD", ack=True).allow is True
    assert _decide("T03").reason == ip.R_NOT_INTRUSIVE


def test_policy_error_fails_closed():
    def boom(_):
        raise RuntimeError("opa down")

    d = _decide(policy=boom)
    assert not d.allow and d.reason == ip.R_POLICY_ERROR


def test_default_allowlist_is_dev_demo(monkeypatch):
    assert ip.parse_allowed_environments(None) == frozenset({"dev", "demo"})


def test_decision_from_ctx(monkeypatch):
    monkeypatch.setenv("ATTESTRA_AUTOMATED_VAPT_SSRF", "1")
    assert ip.decision_from_ctx(None, "SSRF").reason == ip.R_NO_DECISION
    good = SimpleNamespace(extra={ip.CTX_KEY: {"SSRF": _decide().to_json()}})
    assert ip.decision_from_ctx(good, "SSRF").allow is True
    forged = SimpleNamespace(extra={ip.CTX_KEY: {"SSRF": {"allow": True, "reason": "allowed", "facts": {"asset_environment": "production"}}}})
    assert ip.decision_from_ctx(forged, "SSRF").reason == ip.R_ENV_FORBIDDEN
    monkeypatch.setenv("ATTESTRA_AUTOMATED_VAPT_SSRF", "0")
    assert ip.decision_from_ctx(good, "SSRF").reason == ip.R_FLAG_OFF


def test_ssrf_runs_only_with_allowed_decision(monkeypatch):
    monkeypatch.setenv("ATTESTRA_AUTOMATED_VAPT_SSRF", "1")
    vuln = TestClient(create_vulnerable_app(), base_url=BASE)
    denied = ssrf_tests.run(vuln, BASE)
    assert denied["skip_reason"] == "policy_denied"
    assert denied["policy_decision"]["reason"] == ip.R_NO_DECISION
    ctx = SimpleNamespace(extra={ip.CTX_KEY: {"SSRF": _decide().to_json()}})
    ran = ssrf_tests.run(vuln, BASE, ctx=ctx)
    assert ran.get("skip_reason") is None
    assert ran["finding_candidate"] is True
    assert ran["policy_decision"]["allow"] is True


def test_force_hook_ignored_for_real_http_clients(monkeypatch):
    import httpx

    monkeypatch.setenv("ATTESTRA_AUTOMATED_VAPT_UPLOAD", "1")
    with httpx.Client() as raw:
        out = file_upload_tests.run(raw, "http://127.0.0.1:9/", force=True)
    assert out["status_hint"] == "SKIPPED" and out["skip_reason"] == "policy_denied"


def test_no_module_reads_app_env_for_target_gating():
    pat = re.compile(r"APP_ENV|parse_app_env|_APP_ENV_BYPASS_ALLOWLIST")
    files = list((ROOT / "attestra/automated_vapt/testing").glob("*.py")) + [
        ROOT / "attestra/automated_vapt/core/body_mutation.py"
    ]
    offenders = [f.name for f in files if pat.search(f.read_text(encoding="utf-8"))]
    assert offenders == []
