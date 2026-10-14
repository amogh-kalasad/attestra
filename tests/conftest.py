"""Shared fixtures for all Attestra tests.

Each test gets a fresh in-memory SQLite database and a temporary DATA_DIR so
tests never touch the developer's real data directory.
"""
from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    """Isolated database + data directory for one test.

    Patches attestra.config globals and resets the db module-level engine so
    every test starts with an empty SQLite database.
    """
    import attestra.config as cfg
    import attestra.db as adb

    data_dir = tmp_path / "data"
    db_url = f"sqlite:///{tmp_path}/test.db"

    monkeypatch.setattr(cfg, "DATA_DIR", data_dir)
    monkeypatch.setattr(cfg, "DATABASE_URL", db_url)

    # Force a fresh engine — db.init() bails early if _engine is already set.
    adb._engine = None
    adb._SessionLocal = None
    adb.init(db_url)

    yield

    # Dispose cleanly so the temp file can be removed on Windows.
    if adb._engine is not None:
        adb._engine.dispose()
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
        # web_app — internet-facing, CDE (ownership pre-verified for runner gate tests)
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
        # container image — CDE
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
        # source repo — CDE (payments)
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
        # source repo — not CDE
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
