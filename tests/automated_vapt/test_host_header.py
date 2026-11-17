"""B-02 Host / X-Forwarded-Host probe (mock apps only)."""

from __future__ import annotations

import pytest

from attestra.automated_vapt.testing import host_header_tests as hh
from tests.automated_vapt.fixtures.probes.helpers import BASE, ctx, probe_client, seen, waf_client


@pytest.fixture(autouse=True)
def _flags(monkeypatch):
    monkeypatch.setenv("ATTESTRA_PROBES_WEB_SAFE", "1")
    monkeypatch.setenv("ATTESTRA_PROBE_DELAY_MS", "0")


def test_spoofed_host_used_in_links_is_flagged():
    c = probe_client(vulnerable=True)
    out = hh.run(c, BASE, ctx=ctx())
    assert out["finding_candidate"] is True
    assert "x-forwarded-host" in out["observations"]["suspected_variants"]


def test_destination_never_changes_and_only_headers_vary():
    c = probe_client(vulnerable=True)
    out = hh.run(c, BASE, ctx=ctx())
    sent = seen(c)
    assert len(sent) <= hh.META.request_budget
    assert {s["path"] for s in sent} == {"/"}
    assert all(v["destination_unchanged"] for v in out["observations"]["variants"])
    assert out["observations"]["pinned_destination"] == "testserver"


def test_benign_app_passes():
    c = probe_client(vulnerable=False)
    out = hh.run(c, BASE, ctx=ctx())
    assert out["finding_candidate"] is False
    assert "status_hint" not in out


def test_location_marker_detection():
    assert hh.marker_in_location({"Location": f"https://{hh.MARKER_HOST}/x"})
    assert hh.marker_in_location({"Location": f"//{hh.MARKER_HOST}/x"})
    assert not hh.marker_in_location({"Location": "/x"})


def test_waf_blocked():
    out = hh.run(waf_client(), BASE, ctx=ctx())
    assert out["status_hint"] == "BLOCKED"
