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
        self._gauges: dict[str, dict[tuple, float]] = defaultdict(dict)
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

    def set_gauge(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        """Set a gauge to ``value`` (I-01: queue depth, active jobs, saturation)."""
        key = tuple(sorted((labels or {}).items()))
        with self._lock:
            self._gauges[name][key] = float(value)

    def counter_value(self, name: str, labels: dict[str, str] | None = None) -> float:
        key = tuple(sorted((labels or {}).items()))
        with self._lock:
            return float(self._counters.get(name, {}).get(key, 0.0))

    def gauge_value(self, name: str, labels: dict[str, str] | None = None) -> float | None:
        key = tuple(sorted((labels or {}).items()))
        with self._lock:
            return self._gauges.get(name, {}).get(key)

    def hist_count(self, name: str, labels: dict[str, str] | None = None) -> int:
        key = tuple(sorted((labels or {}).items()))
        with self._lock:
            h = self._hist.get(name, {}).get(key)
            return int(h[2]) if h else 0

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()
            self._hist.clear()
            self._gauges.clear()

    def render(self) -> str:
        out: list[str] = []
        with self._lock:
            for name, series in sorted(self._counters.items()):
                kind, text = self._help.get(name, ("counter", name))
                out += [f"# HELP {name} {text}", f"# TYPE {name} {kind}"]
                for key, val in sorted(series.items()):
                    out.append(f"{name}{_labels(key)} {val:g}")
            for name, series in sorted(self._gauges.items()):
                _, text = self._help.get(name, ("gauge", name))
                out += [f"# HELP {name} {text}", f"# TYPE {name} gauge"]
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
# I-01 queue and worker metrics (labels stay low-cardinality: tool / kind / outcome only).
REGISTRY.describe("attestra_job_queue_age_seconds", "histogram", "Seconds a job waited in the queue before a worker claimed it.")
REGISTRY.describe("attestra_job_duration_seconds", "histogram", "Seconds a claimed job ran, by tool and outcome.")
REGISTRY.describe("attestra_job_retries_total", "counter", "Jobs put back in the queue for another attempt, by tool.")
REGISTRY.describe("attestra_job_cancellations_total", "counter", "Jobs cancelled by a user, kill switch or worker stop, by tool.")
REGISTRY.describe("attestra_job_outcomes_total", "counter", "Finished jobs by tool and outcome.")
REGISTRY.describe("attestra_worker_active_jobs", "gauge", "Jobs running in this worker process, by kind.")
REGISTRY.describe("attestra_worker_saturation_ratio", "gauge", "Active jobs divided by worker concurrency (1 = every slot busy).")
REGISTRY.describe("attestra_jobs_stuck", "gauge", "Running jobs whose heartbeat is older than the stale threshold.")
REGISTRY.describe("attestra_maintenance_runs_total", "counter", "Maintenance tick task runs by task and outcome.")

_TOOL_LABEL_MAX = 40


def _label(v: object) -> str:
    """Bound label values so a bad tool name cannot explode series cardinality."""
    s = str(v or "unknown").strip().lower()[:_TOOL_LABEL_MAX]
    return "".join(ch if ch.isalnum() or ch in "_-." else "_" for ch in s) or "unknown"


def record_event(kind: str, **labels: str) -> None:
    """Count a domain event, e.g. ``record_event("import", tool="zap")``."""
    REGISTRY.inc("attestra_events_total", {"kind": kind, **labels})


def record_job_claimed(tool: str, queue_age_s: float | None) -> None:
    """I-01: a worker claimed a job; ``queue_age_s`` is created→claimed (None when unknown)."""
    record_event("job.claimed", tool=_label(tool))
    if queue_age_s is not None and queue_age_s >= 0:
        REGISTRY.observe("attestra_job_queue_age_seconds", float(queue_age_s), {"tool": _label(tool)})


def record_job_finished(tool: str, outcome: str, duration_s: float | None) -> None:
    """I-01: a job finished (done / failed / cancelled / quarantined / refused / requeued)."""
    labels = {"tool": _label(tool), "outcome": _label(outcome)}
    REGISTRY.inc("attestra_job_outcomes_total", labels)
    if duration_s is not None and duration_s >= 0:
        REGISTRY.observe("attestra_job_duration_seconds", float(duration_s), labels)
    if outcome == "cancelled":
        REGISTRY.inc("attestra_job_cancellations_total", {"tool": _label(tool)})


def record_job_retry(tool: str) -> None:
    REGISTRY.inc("attestra_job_retries_total", {"tool": _label(tool)})


def record_worker_load(active_by_kind: dict[str, int], concurrency: int) -> None:
    """I-01: gauges for the worker's busy slots (scan / automated) and saturation."""
    total = 0
    for kind in ("scan", "automated"):
        n = int(active_by_kind.get(kind, 0))
        total += n
        REGISTRY.set_gauge("attestra_worker_active_jobs", n, {"kind": kind})
    REGISTRY.set_gauge("attestra_worker_saturation_ratio", total / max(1, int(concurrency)))


def record_stuck_jobs(count: int) -> None:
    REGISTRY.set_gauge("attestra_jobs_stuck", max(0, int(count)))


def record_maintenance(task: str, outcome: str) -> None:
    REGISTRY.inc("attestra_maintenance_runs_total", {"task": _label(task), "outcome": _label(outcome)})


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
    """Instrument FastAPI. Returns True if active.

    Exports OTLP when ``OTEL_EXPORTER_OTLP_ENDPOINT`` is set (standard OTel env var),
    otherwise spans are created but not exported. ``engine`` is ignored (no SQL engine).
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
    return True


def instrument_engine(engine=None) -> bool:
    """Kept for the observability API (Phase 6.6): DB-driver instrumentation hook.

    Attestra's runtime store is MongoDB (no SQLAlchemy engine), so there is nothing to
    instrument unless OTel is enabled *and* the optional pymongo instrumentation is
    installed. Returns True only when instrumentation was actually activated; it is a
    no-op (False) when ``ATTESTRA_OTEL_ENABLED`` is off.
    """
    if not OTEL_ENABLED:
        return False
    try:
        from opentelemetry.instrumentation.pymongo import PymongoInstrumentor  # type: ignore[import-not-found]
    except ImportError:
        return False
    try:
        PymongoInstrumentor().instrument()
    except Exception:  # noqa: BLE001 - tracing must never break startup
        log.warning("pymongo instrumentation failed; continuing without DB spans")
        return False
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