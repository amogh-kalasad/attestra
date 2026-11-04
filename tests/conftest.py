"""Shared fixtures for all Attestra tests.

Each test gets a throwaway ``attestra_test_*`` MongoDB database and a temporary DATA_DIR so
tests never touch the developer's real data directory or the live ``attestra`` database.
"""
from __future__ import annotations

import contextlib
import os
import re
import socket
import uuid
from datetime import date, timedelta
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"

# ---------------------------------------------------------------- Mongo test harness
# MongoDB only: every ``fresh_db`` test points at a throwaway ``attestra_test_<hex>``
# database on the local replica set (ATTESTRA_TEST_MONGODB_URI, default
# mongodb://127.0.0.1:27017/?replicaSet=rs0) and drops it afterwards. The live
# ``attestra`` database is never used (names are guarded by _TEST_DB_PREFIX).
_TEST_DB_PREFIX = "attestra_test_"
_DEFAULT_TEST_MONGO_URI = "mongodb://127.0.0.1:27017/?replicaSet=rs0"
# Optional run tag (ATTESTRA_TEST_DB_TAG=w2 -> attestra_test_w2_<hex>) so parallel runs can
# tell their throwaway DBs apart; every DB this process creates is dropped again at session end
# (late writes from background threads can re-create a DB after the per-test drop).
_RUN_TAG = re.sub(r"[^a-z0-9]", "", (os.environ.get("ATTESTRA_TEST_DB_TAG") or "").lower())[:12]
_CREATED_TEST_DBS: list[str] = []
# Real resolver captured at import: tests monkeypatch socket.getaddrinfo (offline DNS) and the
# monkeypatch is only undone after mongo_test_db teardown, so the drop must not use the fake.
_REAL_GETADDRINFO = socket.getaddrinfo


@contextlib.contextmanager
def _real_dns():
    patched = socket.getaddrinfo
    socket.getaddrinfo = _REAL_GETADDRINFO
    try:
        yield
    finally:
        socket.getaddrinfo = patched


def pytest_configure(config):
    config.addinivalue_line("markers", "mongo: needs a reachable MongoDB replica set (throwaway test DB)")


def pytest_sessionfinish(session, exitstatus):
    if not _CREATED_TEST_DBS:
        return
    try:
        from pymongo import MongoClient

        c = MongoClient(test_mongo_uri(), serverSelectionTimeoutMS=1500)
        try:
            existing = set(c.list_database_names())
            for name in _CREATED_TEST_DBS:
                if name.startswith(_TEST_DB_PREFIX) and name in existing:
                    c.drop_database(name)
        finally:
            c.close()
    except Exception:  # noqa: BLE001 - cleanup is best effort
        pass


def test_mongo_uri() -> str:
    return os.environ.get("ATTESTRA_TEST_MONGODB_URI") or _DEFAULT_TEST_MONGO_URI


test_mongo_uri.__test__ = False  # not a test function


_MONGO_UP: bool | None = None


def mongo_available() -> bool:
    global _MONGO_UP
    if _MONGO_UP is None:
        try:
            from pymongo import MongoClient

            c = MongoClient(test_mongo_uri(), serverSelectionTimeoutMS=1500)
            c.admin.command("ping")
            c.close()
            _MONGO_UP = True
        except Exception:
            _MONGO_UP = False
    return _MONGO_UP


@pytest.fixture
def mongo_test_db(monkeypatch):
    """Throwaway Mongo database (``attestra_test_<hex>``), dropped after the test."""
    pytest.importorskip("pymongo")
    if not mongo_available():
        pytest.skip("MongoDB replica set not available")
    import attestra.config as cfg
    import attestra.persistence.mongo.config as mc
    from attestra.persistence.mongo import client as mongo_client

    name = f"{_TEST_DB_PREFIX}{_RUN_TAG + '_' if _RUN_TAG else ''}{uuid.uuid4().hex[:12]}"
    _CREATED_TEST_DBS.append(name)
    assert name.startswith(_TEST_DB_PREFIX) and name != "attestra"
    uri = test_mongo_uri()
    monkeypatch.setenv("ATTESTRA_MONGODB_URI", uri)
    monkeypatch.setenv("ATTESTRA_MONGODB_DB", name)
    monkeypatch.setattr(mc, "MONGODB_URI", uri)
    monkeypatch.setattr(mc, "MONGODB_DB", name)
    if hasattr(cfg, "MONGODB_URI"):
        monkeypatch.setattr(cfg, "MONGODB_URI", uri)
    if hasattr(cfg, "MONGODB_DB"):
        monkeypatch.setattr(cfg, "MONGODB_DB", name)
    mongo_client.close_client()
    db = mongo_client.init_mongo(uri, db_name=name, apply_migrations=True)
    try:
        yield db
    finally:
        mongo_client.close_client()
        with _real_dns():
            c = mongo_client._build_client(uri)
            try:
                if name.startswith(_TEST_DB_PREFIX):  # never drop anything else
                    c.drop_database(name)
            finally:
                c.close()


@pytest.fixture
def fresh_db(tmp_path, monkeypatch, request):
    """Isolated database + data directory for one test.

    Patches attestra.config globals and points persistence + storage at a throwaway
    ``attestra_test_*`` MongoDB database (see ``mongo_test_db``).
    """
    import attestra.config as cfg
    import attestra.db as adb

    data_dir = tmp_path / "data"
    monkeypatch.setattr(cfg, "DATA_DIR", data_dir)
    adb._engine = None
    adb._SessionLocal = None

    request.getfixturevalue("mongo_test_db")
    monkeypatch.setattr(cfg, "PERSISTENCE_BACKEND", "mongo")
    monkeypatch.setattr(cfg, "STORAGE_BACKEND", "mongo")
    monkeypatch.setenv("ATTESTRA_PERSISTENCE", "mongo")
    monkeypatch.setenv("ATTESTRA_STORAGE", "mongo")

    yield

    adb._engine = None
    adb._SessionLocal = None


@pytest.fixture
def api_credentials(fresh_db):
    """Lead user + raw API key for authenticated API tests."""
    from attestra import db
    from attestra.auth.keys import create_api_key, create_user

    with db.session() as s:
        user = create_user(s, username="lead", role="lead", password="test-pass-lead", display_name="Lead User")
        reviewer = create_user(
            s, username="reviewer", role="reviewer", password="test-pass-rev", display_name="Reviewer"
        )
        _, lead_key = create_api_key(s, user)
        _, rev_key = create_api_key(s, reviewer)
        return {
            "lead_user_id": user.id,
            "reviewer_user_id": reviewer.id,
            "lead_key": lead_key,
            "reviewer_key": rev_key,
        }


@pytest.fixture
def auth_headers(api_credentials):
    return {"Authorization": f"Bearer {api_credentials['lead_key']}"}


@pytest.fixture
def engagement(fresh_db):
    """An engagement with a valid authorization and four in-scope assets."""
    from attestra import db, services

    today = date.today()
    with db.session() as s:
        e = services.create_engagement(
            s,
            tenant="Test Client Ltd",
            name="Test VAPT Engagement",
            type="vapt",
            frameworks=["pci_dss_4", "iso_27001_2022"],
            window_start=today - timedelta(days=7),
            window_end=today + timedelta(days=7),
            actor="tester",
        )
        services.add_authorization(
            s,
            e.id,
            filename="authorization.txt",
            data=(FIXTURES / "authorization.txt").read_bytes(),
            signer="Test CISO",
            signed_on=today - timedelta(days=5),
            expires_on=today + timedelta(days=30),
            rules_of_engagement="Business hours only; no DoS; production non-intrusive.",
            environments=["production", "staging"],
            actor="tester",
        )
        # web_app â€” internet-facing, CDE (ownership pre-verified for runner gate tests)
        a = services.add_asset(
            s, e.id,
            kind="web_app",
            identifier="https://shop.example.com",
            name="Storefront",
            environment="production",
            criticality=5,
            exposure="internet",
            in_cde=True,
            actor="tester",
        )
        from attestra.models import utcnow

        a.ownership_verified_at = utcnow()
        # container image â€” CDE
        services.add_asset(
            s, e.id,
            kind="image",
            identifier="registry.example.com/shop/api",
            name="Shop API image",
            environment="production",
            criticality=4,
            exposure="internal",
            in_cde=True,
            actor="tester",
        )
        # source repo â€” CDE (payments)
        services.add_asset(
            s, e.id,
            kind="repo",
            identifier="services/payments",
            name="Payments service",
            environment="production",
            criticality=5,
            exposure="internal",
            in_cde=True,
            actor="tester",
        )
        # source repo â€” not CDE
        services.add_asset(
            s, e.id,
            kind="repo",
            identifier="web/src",
            name="Web frontend",
            environment="production",
            criticality=3,
            exposure="internal",
            in_cde=False,
            actor="tester",
        )
        eid = e.id

    return eid


@pytest.fixture
def loaded(engagement):
    """Engagement with all four fixture tool results imported and enriched."""
    from attestra import db, services

    eid = engagement
    with db.session() as s:
        for tool, fname in [
            ("zap", "zap.json"),
            ("nuclei", "nuclei.jsonl"),
            ("trivy", "trivy.json"),
            ("sarif", "semgrep.sarif"),
        ]:
            services.import_results(
                s, eid,
                tool=tool,
                filename=fname,
                data=(FIXTURES / fname).read_bytes(),
                actor="tester",
            )
        services.enrich(
            s,
            kev_json=(FIXTURES / "kev.json").read_bytes(),
            epss_csv=(FIXTURES / "epss.csv").read_bytes(),
            actor="tester",
        )

    return eid


@pytest.fixture
def client(fresh_db, auth_headers):
    """TestClient with a lead Bearer token attached by default."""
    from fastapi.testclient import TestClient

    from attestra.api import app

    with TestClient(app) as c:
        c.headers.update(auth_headers)
        yield c
