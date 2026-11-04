"""Phase 6.1 - PostgreSQL default path + row-level security.

Unit tests run everywhere. The live RLS test needs a Postgres 16 server and runs
when ``ATTESTRA_TEST_POSTGRES_URL`` is set (CI service container); otherwise skipped.
"""
from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import text

from attestra import db, rls
from attestra.models import Base

PG_URL = os.environ.get("ATTESTRA_TEST_POSTGRES_URL", "")


def test_normalize_url_uses_psycopg3():
    assert db.normalize_url("postgres://u:p@h/d") == "postgresql+psycopg://u:p@h/d"
    assert db.normalize_url("postgresql://u:p@h/d") == "postgresql+psycopg://u:p@h/d"
    assert db.normalize_url("postgresql+psycopg://u@h/d") == "postgresql+psycopg://u@h/d"
    assert db.normalize_url("sqlite:///x.db") == "sqlite:///x.db"
    assert db.is_postgres("postgres://h/d") and not db.is_postgres("sqlite://")


def test_every_tenant_bearing_table_has_policy():
    import attestra.models  # noqa: F401

    exempt = {"users", "api_keys", "jobs", "audit_events"}
    for table in Base.metadata.sorted_tables:
        cols = {c.name for c in table.columns}
        if table.name in exempt:
            continue
        if cols & {"tenant_id", "engagement_id", "finding_id"} or table.name == "tenants":
            assert table.name in rls.POLICIES, f"{table.name} missing RLS policy"
    assert set(rls.POLICIES) <= {t.name for t in Base.metadata.sorted_tables}


def test_rls_statements_force_and_policy():
    stmts = rls.rls_statements()
    for table in rls.POLICIES:
        assert f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY" in stmts
        assert any(s.startswith(f"CREATE POLICY {rls.POLICY_NAME} ON {table} ") for s in stmts)


def test_setting_value():
    assert rls.setting_value(None) == ""
    assert rls.setting_value(set()) == "0"
    assert rls.setting_value({3, 1}) == "1,3"


def test_session_records_tenant_scope_on_sqlite(fresh_db):
    with db.session(tenant_ids={7}) as s:
        assert s.info["tenant_ids"] == frozenset({7})
    with db.tenant_scope([2, 5]):
        with db.session() as s:
            assert s.info["tenant_ids"] == frozenset({2, 5})
    with db.session() as s:
        assert s.info["tenant_ids"] is None


def test_migration_is_noop_on_sqlite(tmp_path, monkeypatch):
    import attestra.config as cfg

    url = f"sqlite:///{tmp_path}/m.db"
    monkeypatch.setattr(cfg, "DATABASE_URL", url)
    db.upgrade(url)
    from sqlalchemy import create_engine

    eng = create_engine(url)
    with eng.connect() as c:
        assert c.execute(text("SELECT version_num FROM alembic_version")).scalar() == "0021_finding_fields_disclaimer"
    eng.dispose()


@pytest.mark.skipif(not PG_URL, reason="set ATTESTRA_TEST_POSTGRES_URL to run against Postgres")
def test_cross_tenant_raw_sql_returns_zero_rows_under_rls(monkeypatch):
    """Guide 6.1: cross-tenant raw SQL returns 0 rows under RLS."""
    from sqlalchemy import create_engine

    import attestra.config as cfg

    admin = create_engine(db.normalize_url(PG_URL), isolation_level="AUTOCOMMIT")
    schema = f"t_{uuid.uuid4().hex[:10]}"
    role = f"r_{uuid.uuid4().hex[:10]}"
    with admin.connect() as c:
        c.execute(text(f"CREATE SCHEMA {schema}"))
        c.execute(text(f"CREATE ROLE {role} LOGIN PASSWORD 'x' NOSUPERUSER NOBYPASSRLS"))
        c.execute(text(f"GRANT ALL ON SCHEMA {schema} TO {role}"))
    base = db.normalize_url(PG_URL)
    from sqlalchemy.engine import make_url

    u = make_url(base).set(username=role, password="x", query={"options": f"-csearch_path={schema}"})
    app_url = u.render_as_string(hide_password=False)
    try:
        monkeypatch.setattr(cfg, "DATABASE_URL", app_url)
        db._engine = None
        db._SessionLocal = None
        db.init(app_url, use_migrations=True)  # table owner = non-superuser app role; FORCE applies
        with db.session() as s:
            have = set(s.execute(text("SELECT tablename FROM pg_policies WHERE policyname = :p"),
                                 {"p": rls.POLICY_NAME}).scalars())
        assert set(rls.POLICIES) <= have, sorted(set(rls.POLICIES) - have)
        with db.session() as s:
            s.execute(text("INSERT INTO tenants (id, name, industry, contact_name, contact_email, data_region, plan) "
                           "VALUES (1,'A','','','','default','standard'),(2,'B','','','','default','standard')"))
        # cross-tenant raw SQL: tenant 1 asks for tenant 2
        with db.session(tenant_ids={1}) as s:
            assert s.execute(text("SELECT count(*) FROM tenants WHERE id = 2")).scalar() == 0
            assert s.execute(text("SELECT count(*) FROM tenants")).scalar() == 1
        with db.session(tenant_ids=set()) as s:
            assert s.execute(text("SELECT count(*) FROM tenants")).scalar() == 0
        with db.session(tenant_ids={1}) as s:
            with pytest.raises(Exception):
                s.execute(text("INSERT INTO tenants (id, name, industry, contact_name, contact_email, data_region, plan) "
                               "VALUES (3,'C','','','','default','standard')"))
        with db.session() as s:
            assert s.execute(text("SELECT count(*) FROM tenants")).scalar() == 2
    finally:
        if db._engine is not None:
            db._engine.dispose()
        db._engine = None
        db._SessionLocal = None
        with admin.connect() as c:
            c.execute(text(f"DROP SCHEMA {schema} CASCADE"))
            c.execute(text(f"DROP ROLE {role}"))
        admin.dispose()