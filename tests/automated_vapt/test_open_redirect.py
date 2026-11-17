"""B-03 Open redirect probe (mock apps only; the marker host is never contacted)."""

from __future__ import annotations

import pytest

from attestra.automated_vapt.testing import open_redirect_tests as orx
from tests.automated_vapt.fixtures.probes.helpers import BASE, ctx, probe_client, seen, waf_client


@pytest.fixture(autouse=True)
def _flags(monkeypatch):
    monkeypatch.setenv("ATTESTRA_PROBES_WEB_SAFE", "1")
    monkeypatch.setenv("ATTESTRA_PROBE_DELAY_MS", "0")


def test_location_to_marker_detected_without_following():
    c = probe_client(vulnerable=True)
    out = orx.run(c, BASE, ctx=ctx())
    assert out["finding_candidate"] is True
    assert out["finding_confidence"] == "confirmed"
    # Every request went to the target; none to the marker host.
    assert all(s["headers"].get("host") == "testserver" for s in seen(c))


def test_same_site_redirect_suppressed():
    c = probe_client(vulnerable=False)
    out = orx.run(c, BASE, ctx=ctx())
    assert out["finding_candidate"] is False


def test_encoded_variants_and_budget():
    c = probe_client(vulnerable=False)
    out = orx.run(c, BASE, ctx=ctx())
    names = {a["payload"] for a in out["observations"]["attempts"]}
    assert {"absolute", "scheme_relative", "backslash", "encoded"} <= names
    assert len(seen(c)) <= orx.META.request_budget


def test_chain_recorded_through_same_site_hop():
    c = probe_client(vulnerable=True)
    out = orx.run(c, BASE, ctx=ctx(_capture_urls=["http://testserver/go?url=/x"]), candidates=None)
    first = out["observations"]["attempts"][0]
    assert first["param"] == "url"
    assert len(first["chain"]) == 2 and first["marker_redirect"] is True


def test_points_at_marker_helper():
    assert orx.points_at_marker(f"/\\{orx.MARKER_HOST}/x", "http://testserver/login")
    assert not orx.points_at_marker("/dashboard", "http://testserver/login")


def test_waf_blocked():
    out = orx.run(waf_client(), BASE, ctx=ctx())
    assert out["status_hint"] == "BLOCKED"
