"""Observability: Prometheus metrics and optional OpenTelemetry tracing (Phase 6.6).

Prometheus metrics need no extra package: a small in-process registry renders the
text exposition format at ``GET /metrics``. If ``prometheus_client`` is installed it
is not required. OpenTelemetry instrumentation for FastAPI and SQLAlchemy is enabled
only when ``ATTESTRA_OTEL_ENABLED`` is set and the ``observability`` extra is
installed; otherwise it is a no-op so the core package keeps zero new dependencies.
"""
# @lat: [[architecture#Observability]]

from __future__ import annotations

import logging
import os
import time
from collections import defaultdict
from threading import Lock

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

log = logging.getLogger("attestra.observability")

OTEL_ENABLED = os.environ.get("ATTESTRA_OTEL_ENABLED", "").lower() in ("1", "true", "yes")
OTEL_SERVICE_NAME = os.environ.get("ATTESTRA_OTEL_SERVICE_NAME", "attestra-api")
METRICS_ENABLED = os.environ.get("ATTESTRA_METRICS_ENABLED", "true").lower() in ("1", "true", "yes")
# Bearer token for /metrics scrapers. When empty, anonymous scrape is denied unless
# ATTESTRA_METRICS_ALLOW_ANON=true (cluster-internal opt-in) or an admin session is used.
METRICS_TOKEN = os.environ.get("ATTESTRA_METRICS_TOKEN", "")
METRICS_ALLOW_ANON = os.environ.get("ATTESTRA_METRICS_ALLOW_ANON", "").lower() in ("1", "true", "yes")

BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)


def _esc(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _labels(d: tuple[tuple[str, str], ...]) -> str:
    return "{" + ",".join(f'{k}="{_esc(v)}"' for k, v in d) + "}" if d else ""


class Registry:
    """Thread-safe counters and histograms rendered as Prometheus text format 0.0.4."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._counters: dict[str, dict[tuple, float]] = defaultdict(lambda: defaultdict(float))
        self._hist: dict[str, dict[tuple, list]] = defaultdict(dict)
        self._help: dict[str, tuple[str, str]] = {}

    def describe(self, name: str, kind: str, text: str) -> None:
        self._help[name] = (kind, text)

    def inc(self, name: str, labels: dict[str, str] | None = None, value: float = 1.0) -> None:
        key = tuple(sorted((labels or {}).items()))
        with self._lock:
            self._counters[name][key] += value

    def observe(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        key = tuple(sorted((labels or {}).items()))
        with self._lock:
            h = self._hist[name].setdefault(key, [[0] * len(BUCKETS), 0.0, 0])
            for i, b in enumerate(BUCKETS):
                if value <= b:
                    h[0][i] += 1
            h[1] += value
            h[2] += 1

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()
            self._hist.clear()

    def render(self) -> str:
        out: list[str] = []
        with self._lock:
            for name, series in sorted(self._counters.items()):
                kind, text = self._help.get(name, ("counter", name))
                out += [f"# HELP {name} {text}", f"# TYPE {name} {kind}"]
                for key, val in sorted(series.items()):
                    out.append(f"{name}{_labels(key)} {val:g}")
            for name, series in sorted(self._hist.items()):
                _, text = self._help.get(name, ("histogram", name))
                out += [f"# HELP {name} {text}", f"# TYPE {name} histogram"]
                for key, (counts, total, n) in sorted(series.items()):
                    for b, c in zip(BUCKETS, counts, strict=True):
                        out.append(f"{name}_bucket{_labels(key + (('le', f'{b:g}'),))} {c}")
                    out.append(f"{name}_bucket{_labels(key + (('le', '+Inf'),))} {n}")
                    out.append(f"{name}_sum{_labels(key)} {total:g}")
                    out.append(f"{name}_count{_labels(key)} {n}")
        return "\n".join(out) + "\n"


REGISTRY = Registry()
REGISTRY.describe("attestra_http_requests_total", "counter", "HTTP requests by method, route and status.")
REGISTRY.describe("attestra_http_request_duration_seconds", "histogram", "HTTP request latency in seconds.")
REGISTRY.describe("attestra_events_total", "counter", "Domain events (imports, reports, jobs) by kind.")


def record_event(kind: str, **labels: str) -> None:
    """Count a domain event, e.g. ``record_event("import", tool="zap")``."""
    REGISTRY.inc("attestra_events_total", {"kind": kind, **labels})


def _route_template(request: Request) -> str:
    """Use the route path template (``/api/engagements/{eid}``) to keep label cardinality low."""
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    return path or "unmatched"


class MetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path == "/metrics":
            return await call_next(request)
        start = time.perf_counter()
        status = "500"
        try:
            response = await call_next(request)
            status = str(response.status_code)
            return response
        finally:
            labels = {"method": request.method, "route": _route_template(request)}
            REGISTRY.inc("attestra_http_requests_total", {**labels, "status": status})
            REGISTRY.observe("attestra_http_request_duration_seconds", time.perf_counter() - start, labels)


def _metrics_admin_session(request: Request) -> bool:
    """True when the request carries an active admin session cookie (P0-5)."""
    try:
        from attestra.auth.session import COOKIE_NAME, read_session
        from attestra.db import session as db_session
        from attestra.models import User

        data = read_session(request.cookies.get(COOKIE_NAME))
        if not data or not data.get("uid"):
            return False
        with db_session() as s:
            user = s.get(User, int(data["uid"]))
            return bool(user and user.active and user.role == "admin")
    except Exception:
        return False


def metrics_response(request: Request) -> Response:
    """Serve Prometheus text. Requires token, admin session, or explicit anon opt-in."""
    auth = request.headers.get("authorization") or ""
    if METRICS_TOKEN:
        if auth != f"Bearer {METRICS_TOKEN}":
            return Response("unauthorized\n", status_code=401, media_type="text/plain")
    elif not METRICS_ALLOW_ANON and not _metrics_admin_session(request):
        return Response("unauthorized\n", status_code=401, media_type="text/plain")
    return Response(REGISTRY.render(), media_type="text/plain; version=0.0.4; charset=utf-8")


def setup_otel(app, engine=None) -> bool:
    """Instrument FastAPI (and SQLAlchemy when an engine is given). Returns True if active.

    Exports OTLP when ``OTEL_EXPORTER_OTLP_ENDPOINT`` is set (standard OTel env var),
    otherwise spans are created but not exported.
    """
    if not OTEL_ENABLED:
        return False
    try:
        from opentelemetry import trace
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        log.warning("ATTESTRA_OTEL_ENABLED set but the 'observability' extra is not installed")
        return False
    if not isinstance(trace.get_tracer_provider(), TracerProvider):
        provider = TracerProvider(resource=Resource.create({"service.name": OTEL_SERVICE_NAME}))
        if os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
            try:
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

                provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
            except ImportError:
                log.warning("OTLP exporter not installed; spans will not be exported")
        trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(app, excluded_urls="metrics,api/health")
    if engine is not None:
        instrument_engine(engine)
    return True


def instrument_engine(engine) -> bool:
    if not OTEL_ENABLED:
        return False
    try:
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
    except ImportError:
        return False
    SQLAlchemyInstrumentor().instrument(engine=engine)
    return True


class JsonLogFormatter(logging.Formatter):
    """One JSON object per line so Promtail/Loki can parse fields without regex."""

    def format(self, record: logging.LogRecord) -> str:
        import json

        data = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
            "service": OTEL_SERVICE_NAME,
        }
        if OTEL_ENABLED:
            try:
                from opentelemetry import trace

                ctx = trace.get_current_span().get_span_context()
                if ctx.is_valid:
                    data["trace_id"] = f"{ctx.trace_id:032x}"
                    data["span_id"] = f"{ctx.span_id:016x}"
            except ImportError:
                pass
        if record.exc_info:
            data["exc"] = self.formatException(record.exc_info)
        return json.dumps(data, default=str)


def configure_json_logging() -> None:
    """Enable JSON logs when ``ATTESTRA_LOG_JSON`` is set (Loki-friendly)."""
    if os.environ.get("ATTESTRA_LOG_JSON", "").lower() not in ("1", "true", "yes"):
        return
    handler = logging.StreamHandler()
    handler.setFormatter(JsonLogFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(os.environ.get("ATTESTRA_LOG_LEVEL", "INFO").upper())