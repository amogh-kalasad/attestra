"""Read-only access to legacy SQLite / PostgreSQL sources."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine

from attestra.db import normalize_url

# Dependency order for import (parents before children).
TABLE_ORDER: tuple[str, ...] = (
    "tenants",
    "users",
    "api_keys",
    "tenant_memberships",
    "tenant_ownership_hosts",
    "tenant_risk_weights",
    "tenant_credit_accounts",
    "certification_authority",
    "engagements",
    "user_invites",
    "authorizations",
    "assets",
    "scope_rules",
    "auth_credential_profiles",
    "import_runs",
    "scan_runs",
    "jobs",
    "findings",
    "finding_observations",
    "finding_comments",
    "evidence",
    "retention_policies",
    "control_assessments",
    "risk_acceptances",
    "asv_scans",
    "asv_scan_items",
    "segmentation_tests",
    "scan_schedules",
    "nonconformities",
    "soa_entries",
    "audit_samples",
    "retests",
    "reports",
    "audit_events",
    "suppression_rules",
    "library_entries",
    "report_templates",
    "proof_replays",
    "webhook_endpoints",
    "webhook_deliveries",
    "workflow_rules",
    "finding_assignments",
    "cert_expiry_alerts",
    "email_alert_settings",
    "email_alert_sent",
    "auth_route_inventory",
    "auth_element_inventory",
    "auth_checklist_items",
    "credit_renewal_requests",
    "credit_transactions",
    "automated_test_executions",
    "share_links",
    "trust_centers",
    "trust_items",
    "trust_access_requests",
)


def open_engine(url: str) -> Engine:
    return create_engine(normalize_url(url))


@contextmanager
def readonly_connection(url: str) -> Iterator[Any]:
    engine = open_engine(url)
    try:
        with engine.connect() as conn:
            # SQLite: avoid write locks from our side; Postgres: read-only transaction.
            if engine.dialect.name == "sqlite":
                try:
                    conn.execute(text("PRAGMA query_only = ON"))
                except Exception:  # noqa: BLE001 — older SQLite may lack query_only
                    pass
            elif engine.dialect.name == "postgresql":
                conn.execute(text("SET TRANSACTION READ ONLY"))
            yield conn
    finally:
        engine.dispose()


def list_tables(conn) -> list[str]:
    insp = inspect(conn)
    return sorted(insp.get_table_names())


def row_count(conn, table: str) -> int:
    return int(conn.execute(text(f'SELECT COUNT(*) FROM "{table}"')).scalar() or 0)


def iter_rows(conn, table: str, *, after_id: int = 0, batch: int = 500) -> Iterator[list[dict[str, Any]]]:
    """Yield batches of dict rows ordered by primary key ``id`` or ``tenant_id``."""
    insp = inspect(conn)
    cols = [c["name"] for c in insp.get_columns(table)]
    pk = "tenant_id" if table == "tenant_credit_accounts" else "id"
    if pk not in cols:
        # Fallback: dump whole table once.
        rows = conn.execute(text(f'SELECT * FROM "{table}"')).mappings().all()
        if rows:
            yield [dict(r) for r in rows]
        return
    last = int(after_id)
    while True:
        result = conn.execute(
            text(f'SELECT * FROM "{table}" WHERE "{pk}" > :last ORDER BY "{pk}" ASC LIMIT :lim'),
            {"last": last, "lim": batch},
        )
        batch_rows = [dict(r) for r in result.mappings().all()]
        if not batch_rows:
            break
        yield batch_rows
        last = int(batch_rows[-1][pk])


def assess(url: str) -> dict[str, Any]:
    with readonly_connection(url) as conn:
        tables = list_tables(conn)
        counts = {}
        for t in tables:
            if t == "alembic_version":
                ver = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
                counts[t] = {"count": 1, "version": ver}
                continue
            try:
                counts[t] = {"count": row_count(conn, t)}
            except Exception as exc:  # noqa: BLE001
                counts[t] = {"count": None, "error": type(exc).__name__}
        return {"url_scheme": url.split(":", 1)[0], "tables": counts, "table_list": tables}
