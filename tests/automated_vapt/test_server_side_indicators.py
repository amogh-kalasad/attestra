"""B-07 passive server-side sink indicators: suspicions only, zero internal requests."""

from __future__ import annotations

import pytest

from attestra.automated_vapt.testing import server_side_indicators as ssi
from attestra.proof.pair import HttpPair
from tests.automated_vapt.fixtures.probes.helpers import BASE, ctx, probe_client, seen


@pytest.fixture(autouse=True)
def _flags(monkeypatch):
    monkeypatch.setenv("ATTESTRA_PROBE_DELAY_MS", "0")


def test_url_param_names_and_values_are_suspected_sinks():
    rows = ssi.url_param_suspicions(["http://testserver/fetch?url=x", "http://testserver/p?next=https://a.example/", "http://testserver/q?id=1"])
    assert {r["param"] for r in rows} == {"url", "next"}
    assert all(r["label"] == "suspected_sink" for r in rows)


def test_passive_run_uses_known_traffic_only():
    c = probe_client()
    pairs = [
        HttpPair(method="GET", url="http://testserver/tpl", status=500, response_headers={"content-type": "text/html"}, response_body="jinja2.exceptions.TemplateSyntaxError: x"),
        HttpPair(method="GET", url="http://testserver/feed.xml", status=200, response_headers={"content-type": "application/rss+xml"}, response_body="<rss/>"),
    ]
    out = ssi.run(c, BASE, ctx=ctx(_capture_urls=["http://testserver/img?image_url=a"], _http_pairs=pairs))
    kinds = out["observations"]["by_kind"]
    assert kinds["ssrf"] == 1 and kinds["ssti"] == 1 and kinds["xxe"] == 1
    assert out["finding_candidate"] is False
    assert out["status_hint"] == "INCONCLUSIVE"
    assert seen(c) == []  # zero requests


def test_inventory_uri_params_and_xml_bodies():
    ops = [{"method": "POST", "path": "/import", "params": [{"name": "source", "location": "body", "format": "uri"}], "request_content_types": ["application/xml"]}]
    rows = ssi.inventory_suspicions(ops)
    assert {r["kind"] for r in rows} == {"ssrf", "xxe"}


def test_bounded_gets_never_leave_target(monkeypatch):
    monkeypatch.setenv("ATTESTRA_PROBES_WEB_SAFE", "1")
    c = probe_client()
    ssi.run(c, BASE, ctx=ctx(_capture_urls=["http://testserver/tpl", "http://169.254.169.254/latest/meta-data", "http://testserver/"]))
    sent = seen(c)
    assert len(sent) <= ssi.META.request_budget
    assert all(s["headers"].get("host") == "testserver" for s in sent)


def test_disabled_without_traffic_is_not_tested(monkeypatch):
    monkeypatch.delenv("ATTESTRA_PROBES_WEB_SAFE", raising=False)
    out = ssi.run(probe_client(), BASE, ctx=ctx())
    assert out["status_hint"] == "NOT_TESTED"
