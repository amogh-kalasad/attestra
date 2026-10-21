"""Phase 6.6 observability: /metrics exposition, middleware, JSON logs, OTel no-op."""
from __future__ import annotations

import json
import logging

from attestra import observability as obs


def test_metrics_endpoint_exposes_request_counters(client, monkeypatch):
    # P0-5: anonymous scrape denied by default; use token for the suite.
    monkeypatch.setattr(obs, "METRICS_TOKEN", "test-metrics")
    monkeypatch.setattr(obs, "METRICS_ALLOW_ANON", False)
    obs.REGISTRY.reset()
    assert client.get("/api/health").status_code == 200
    r = client.get("/metrics", headers={"Authorization": "Bearer test-metrics"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    body = r.text
    assert "# TYPE attestra_http_requests_total counter" in body
    assert 'route="/api/health"' in body and 'status="200"' in body
    assert "attestra_http_request_duration_seconds_bucket" in body
    assert 'le="+Inf"' in body


def test_metrics_uses_route_template_not_raw_path(client, monkeypatch):
    monkeypatch.setattr(obs, "METRICS_TOKEN", "test-metrics")
    obs.REGISTRY.reset()
    client.get("/api/engagements/999999")
    body = client.get("/metrics", headers={"Authorization": "Bearer test-metrics"}).text
    assert "/api/engagements/999999" not in body


def test_metrics_token_enforced(client, monkeypatch):
    monkeypatch.setattr(obs, "METRICS_TOKEN", "s3cret")
    monkeypatch.setattr(obs, "METRICS_ALLOW_ANON", False)
    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics", headers={"Authorization": "Bearer s3cret"}).status_code == 200


def test_metrics_anon_denied_by_default(client, monkeypatch):
    monkeypatch.setattr(obs, "METRICS_TOKEN", "")
    monkeypatch.setattr(obs, "METRICS_ALLOW_ANON", False)
    assert client.get("/metrics").status_code == 401


def test_registry_render_and_events():
    reg = obs.Registry()
    reg.inc("x_total", {"a": 'q"uote'})
    reg.observe("lat_seconds", 0.02)
    text = reg.render()
    assert 'x_total{a="q\\"uote"} 1' in text
    assert 'lat_seconds_bucket{le="0.025"} 1' in text and 'lat_seconds_bucket{le="0.01"} 0' in text
    obs.record_event("import", tool="zap")
    assert 'kind="import"' in obs.REGISTRY.render()


def test_otel_disabled_is_noop(monkeypatch):
    monkeypatch.setattr(obs, "OTEL_ENABLED", False)
    assert obs.setup_otel(object()) is False
    assert obs.instrument_engine(object()) is False


def test_json_log_formatter():
    rec = logging.LogRecord("attestra.x", logging.INFO, __file__, 1, "hello %s", ("w",), None)
    data = json.loads(obs.JsonLogFormatter().format(rec))
    assert data["msg"] == "hello w" and data["level"] == "info" and data["logger"] == "attestra.x"


def test_grafana_dashboard_stub_is_valid():
    from pathlib import Path

    p = Path(__file__).resolve().parents[1] / "deploy/observability/grafana/dashboards/attestra-api.json"
    dash = json.loads(p.read_text(encoding="utf-8"))
    exprs = " ".join(t["expr"] for panel in dash["panels"] for t in panel["targets"])
    assert "attestra_http_requests_total" in exprs and "attestra_http_request_duration_seconds_bucket" in exprs
