# Observability (Phase 6.6)

Stubs only; Attestra does not install Prometheus, Grafana or Loki.

- **Metrics:** `GET /metrics` (Prometheus text). Disable with `ATTESTRA_METRICS_ENABLED=false`. By default anonymous scrape returns **401**; set `ATTESTRA_METRICS_TOKEN` for scrapers (preferred), or `ATTESTRA_METRICS_ALLOW_ANON=true` only for trusted cluster-internal networks. An authenticated **admin** session cookie also works.
- **Tracing:** `pip install -e .[observability]`, set `ATTESTRA_OTEL_ENABLED=1` and `OTEL_EXPORTER_OTLP_ENDPOINT`. Instruments FastAPI and SQLAlchemy.
- **Logs:** `ATTESTRA_LOG_JSON=1` emits one JSON object per line (with trace_id when tracing is on) for Promtail/Loki.
- `prometheus.yml`, `grafana/`, `promtail.yml`: config stubs; `grafana/dashboards/attestra-api.json`: request rate, 5xx ratio, p95 latency, domain events.
- OpenSearch: optional, not stubbed.
