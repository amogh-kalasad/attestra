"""B-01 CORS validation matrix (mock apps only; no real target)."""

from __future__ import annotations

import pytest

from attestra.automated_vapt.testing import cors_tests
from tests.automated_vapt.fixtures.probes.helpers import BASE, ctx, probe_client, seen, waf_client


@pytest.fixture(autouse=True)
def _flags(monkeypatch):
    monkeypatch.setenv("ATTESTRA_PROBES_WEB_SAFE", "1")
    monkeypatch.setenv("ATTESTRA_PROBE_DELAY_MS", "0")


def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv("ATTESTRA_PROBES_WEB_SAFE", raising=False)
    c = probe_client()
    out = cors_tests.run(c, BASE, ctx=ctx())
    assert out["status_hint"] == "NOT_TESTED" and out["skip_reason"] == "disabled_by_flag"
    assert seen(c) == []


def test_reflected_origin_with_credentials_is_reproducible_finding():
    c = probe_client(vulnerable=True)
    out = cors_tests.run(c, BASE, ctx=ctx())
    assert out["finding_candidate"] is True
    assert out["finding_confidence"] == "confirmed"
    assert out["observations"]["reproduced"] is True
    assert out["evidence_pairs"]
    sent = seen(c)
    assert len(sent) <= cors_tests.META.request_budget
    assert {s["method"] for s in sent} <= {"GET", "OPTIONS"}
    # Only the Origin header varies; origins are non-routable markers.
    assert all(s["headers"].get("origin", "").endswith(".invalid") or s["headers"].get("origin") == "null" for s in sent)


def test_safe_app_no_finding_and_preflight_recorded_separately():
    c = probe_client(vulnerable=False)
    out = cors_tests.run(c, BASE, ctx=ctx())
    assert out["finding_candidate"] is False
    assert out["observations"]["preflight"]["kind"] == "preflight"
    assert out.get("status_hint") in (None,)


def test_wildcard_without_credentials_is_info_only():
    row = cors_tests.evaluate("https://attestra-cors-probe.invalid", {"Access-Control-Allow-Origin": "*"})
    assert row["wildcard"] and not row["credentialed_reflection"]


def test_null_origin_reflection_detected():
    row = cors_tests.evaluate("null", {"Access-Control-Allow-Origin": "null", "Access-Control-Allow-Credentials": "true"})
    assert row["credentialed_reflection"] is True


def test_waf_challenge_is_blocked_and_stops():
    c = waf_client()
    out = cors_tests.run(c, BASE, ctx=ctx())
    assert out["status_hint"] == "BLOCKED"
    assert out["finding_candidate"] is False
    assert out["observations"]["requests_sent"] == 1
    assert out["validity_samples"]
