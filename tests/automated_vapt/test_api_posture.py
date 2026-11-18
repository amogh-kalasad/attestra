"""C-06 passive rate-limit headers and API version inventory."""

from __future__ import annotations

import pytest

from attestra.automated_vapt.testing import api_posture_tests as ap
from attestra.proof.pair import HttpPair
from tests.automated_vapt.fixtures.probes.helpers import BASE, ctx, probe_client, seen


@pytest.fixture(autouse=True)
def _flags(monkeypatch):
    monkeypatch.setenv("ATTESTRA_PROBE_DELAY_MS", "0")


def test_headers_from_existing_traffic_only():
    c = probe_client()
    pairs = [
        HttpPair(method="GET", url="http://testserver/api/v1/a", status=200, response_headers={"X-RateLimit-Limit": "10", "X-RateLimit-Remaining": "9"}),
        HttpPair(method="GET", url="http://testserver/api/v2/b", status=200, response_headers={"Deprecation": "true"}),
    ]
    out = ap.run(c, BASE, ctx=ctx(_http_pairs=pairs))
    assert seen(c) == []
    obs = out["observations"]
    assert obs["rate_limit"]["with_headers"] == 1
    assert obs["versions"]["majors"] == ["v1", "v2"]
    assert "multiple_api_major_versions_live" in obs["informational"]
    assert "deprecated_api_version_advertised" in obs["informational"]
    assert out["finding_candidate"] is False
    assert "status_hint" not in out
    samples = out.get("validity_samples") or []
    assert samples, "captured traffic must populate validity_samples"
    classes = {(s["cls"] if isinstance(s, dict) else s.cls.value) for s in samples}
    assert "app_ok" in classes


def test_missing_headers_informational_only():
    pairs = [HttpPair(method="GET", url="http://testserver/x", status=200, response_headers={})]
    out = ap.run(probe_client(), BASE, ctx=ctx(_http_pairs=pairs))
    assert out["finding_candidate"] is False
    assert "no_rate_limit_headers_observed" in out["observations"]["informational"]


def test_bounded_gets_only_when_flag_on(monkeypatch):
    c = probe_client()
    out = ap.run(c, BASE, ctx=ctx())
    assert seen(c) == [] and out["status_hint"] == "NOT_TESTED"
    monkeypatch.setenv("ATTESTRA_PROBES_WEB_SAFE", "1")
    c2 = probe_client()
    out2 = ap.run(c2, BASE, ctx=ctx(_capture_api_urls=["http://testserver/api/v1/profile"]))
    assert 0 < len(seen(c2)) <= ap.META.request_budget
    assert out2["observations"]["source"] == "bounded_gets"


def test_version_parsing():
    assert ap.versions_in_url("https://x/api/v2/users?api-version=2024-01-01") == ["v2", "query:2024-01-01"]


def _sample_cls(s):
    return s["cls"] if isinstance(s, dict) else s.cls.value


def test_validity_samples_ignore_unauth_probes_and_html_pages():
    """T19 401s and HTML app pages must not drive APIPOST run validity."""
    spa = "<!doctype html><html><head><title>App</title></head><body>" + ("x" * 5000) + "Just a moment..." + ("y" * 2000)
    pairs = [
        HttpPair(
            method="GET",
            url="http://testserver/",
            status=200,
            response_headers={"content-type": "text/html"},
            response_body=spa,
        ),
        HttpPair(
            method="GET",
            url="http://testserver/api/v1/me",
            status=200,
            request_headers={"Authorization": "Bearer session-token"},
            response_headers={"X-RateLimit-Limit": "10", "content-type": "application/json"},
            response_body='{"ok":true}',
        ),
        HttpPair(
            method="GET",
            url="http://testserver/api/v1/me",
            status=401,
            request_headers={},
            response_headers={"content-type": "application/json"},
            response_body='{"detail":"unauthorized"}',
        ),
        HttpPair(
            method="GET",
            url="http://testserver/api/v1/me",
            status=401,
            request_headers={"Authorization": "Bearer INVALID_TOKEN_attestra_replay_check_do_not_use"},
            response_headers={"content-type": "application/json"},
            response_body="denied",
        ),
        HttpPair(
            method="GET",
            url="http://testserver/api/v1/me",
            status=401,
            request_headers={"Authorization": "[REDACTED]"},
            response_headers={"content-type": "application/json"},
            response_body="denied",
        ),
        HttpPair(
            method="GET",
            url="http://testserver/api/v1/other",
            status=400,
            request_headers={"Authorization": "Bearer session-token"},
            response_headers={"content-type": "application/json"},
            response_body='{"error":"bad"}',
        ),
    ]
    out = ap.run(probe_client(), BASE, ctx=ctx(_http_pairs=pairs))
    samples = out.get("validity_samples") or []
    classes = [_sample_cls(s) for s in samples]
    assert "auth_expired" not in classes
    assert "challenge" not in classes
    assert "app_ok" in classes
    assert len(samples) == 2


def test_validity_samples_include_inventoried_api_urls():
    pairs = [
        HttpPair(method="GET", url="http://testserver/users", status=200, request_headers={"Authorization": "Bearer t"}, response_body="[]"),
        HttpPair(method="GET", url="http://testserver/page", status=200, response_body="<html>ok</html>"),
    ]
    out = ap.run(
        probe_client(),
        BASE,
        ctx=ctx(_http_pairs=pairs, _capture_api_urls=["http://testserver/users"]),
    )
    classes = [_sample_cls(s) for s in (out.get("validity_samples") or [])]
    assert classes == ["app_ok"]

