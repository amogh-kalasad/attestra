"""B-04 authenticated-response cache posture (mock apps only)."""

from __future__ import annotations

import pytest

from attestra.automated_vapt.testing import cache_posture_tests as cp
from tests.automated_vapt.fixtures.probes.helpers import BASE, ctx, probe_client, seen

PAGES = ["http://testserver/dashboard", "http://testserver/static/app.css", "http://testserver/api/v1/profile"]


@pytest.fixture(autouse=True)
def _flags(monkeypatch):
    monkeypatch.setenv("ATTESTRA_PROBES_WEB_SAFE", "1")
    monkeypatch.setenv("ATTESTRA_PROBE_DELAY_MS", "0")


def test_public_plus_cdn_hit_is_suspicious_then_confirmed():
    c = probe_client(vulnerable=True)
    out = cp.run(c, BASE, ctx=ctx(auth=True, _capture_urls=PAGES))
    assert out["finding_candidate"] is True
    assert "/dashboard" in " ".join(out["observations"]["confirmed"])
    # Evidence never keeps the session token.
    for pr in out["evidence_pairs"]:
        assert "probe-secret-token-value" not in str(pr.request_headers)
        assert len(pr.response_body) <= 1_000


def test_private_no_store_ok():
    c = probe_client(vulnerable=False)
    out = cp.run(c, BASE, ctx=ctx(auth=True, _capture_urls=PAGES))
    assert out["finding_candidate"] is False
    assert out["observations"]["assessed"] >= 1


def test_static_asset_excluded_and_no_poisoning_headers():
    c = probe_client(vulnerable=True)
    cp.run(c, BASE, ctx=ctx(auth=True, _capture_urls=PAGES))
    sent = seen(c)
    assert all(s["path"] != "/static/app.css" for s in sent)
    poison = {"x-forwarded-host", "x-original-url", "x-rewrite-url", "x-host"}
    assert not any(poison & set(s["headers"]) for s in sent)


def test_no_auth_is_not_tested_never_pass():
    out = cp.run(probe_client(), BASE, ctx=ctx(auth=False, _capture_urls=PAGES))
    assert out["status_hint"] == "NOT_TESTED"


def test_assess_headers_pure():
    assert cp.assess_headers({"Cache-Control": "private, no-store"})["verdict"] == "ok"
    v = cp.assess_headers({"Cache-Control": "public, max-age=60", "CF-Cache-Status": "HIT"})
    assert v["verdict"] == "suspicious" and v["cdn_hit"]
