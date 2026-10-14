"""REST API integration tests.

Uses `with TestClient(app) as client:` to avoid the httpx deprecation warning
about using a sync client outside an async context (FastAPI ≥ 0.110 / httpx ≥ 0.27).
"""
from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"

TODAY = date.today()


# ---------------------------------------------------------------- Health


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "version" in body


# ---------------------------------------------------------------- Catalog


def test_catalog_returns_expected_keys(client):
    r = client.get("/api/catalog")
    assert r.status_code == 200
    body = r.json()
    assert "environments" in body
    assert "asset_kinds" in body
    assert "test_types" in body


def test_frameworks_endpoint(client):
    r = client.get("/api/frameworks")
    assert r.status_code == 200
    body = r.json()
    assert "pci_dss_4" in body
    assert "iso_27001_2022" in body


# ---------------------------------------------------------------- Auth enforcement


def test_reject_engagement_creation_without_actor(client):
    """POST /api/engagements without a Bearer token must return 401."""
    client.headers.pop("Authorization", None)
    payload = {
        "tenant": "Test Client",
        "name": "Test Engagement",
        "type": "va",
        "frameworks": [],
    }
    r = client.post("/api/engagements", json=payload)
    assert r.status_code == 401


def test_reject_asset_creation_without_actor(client):
    """Write endpoints consistently enforce authentication."""
    from attestra import db, services

    with db.session() as s:
        e = services.create_engagement(
            s, tenant="T", name="E", type="va", frameworks=[],
            window_start=None, window_end=None, actor="seed",
        )
        eid = e.id

    client.headers.pop("Authorization", None)
    r = client.post(f"/api/engagements/{eid}/assets", json={
        "kind": "web_app", "identifier": "https://example.com"
    })
    assert r.status_code == 401


# ---------------------------------------------------------------- Create engagement via API


def test_create_engagement_with_actor(client):
    payload = {
        "tenant": "ACME Corp",
        "name": "API-created engagement",
        "type": "vapt",
        "frameworks": ["pci_dss_4"],
        "window_start": str(TODAY),
        "window_end": str(TODAY + timedelta(days=30)),
    }
    r = client.post("/api/engagements", json=payload)
    assert r.status_code == 201
    body = r.json()
    assert body["id"] > 0
    assert body["tenant"] == "ACME Corp"
    assert body["type"] == "vapt"


def test_create_engagement_invalid_type(client):
    payload = {
        "tenant": "X",
        "name": "Bad engagement",
        "type": "not_a_valid_type",
        "frameworks": [],
    }
    r = client.post("/api/engagements", json=payload)
    assert r.status_code == 409  # ServiceError → 409


def test_list_engagements(client):
    """GET /api/engagements lists engagements for the authenticated principal."""
    # Create one first
    client.post("/api/engagements", json={
        "tenant": "T", "name": "E", "type": "va", "frameworks": []
    })
    r = client.get("/api/engagements")
    assert r.status_code == 200
    assert isinstance(r.json(), list)
    assert len(r.json()) >= 1


def test_get_engagement(client):
    r = client.post("/api/engagements", json={
        "tenant": "Getme", "name": "Getme Eng", "type": "va", "frameworks": []
    })
    eid = r.json()["id"]

    r2 = client.get(f"/api/engagements/{eid}")
    assert r2.status_code == 200
    assert r2.json()["id"] == eid


def test_get_nonexistent_engagement(client):
    r = client.get("/api/engagements/99999")
    assert r.status_code == 404


# ---------------------------------------------------------------- Asset via API


def test_add_and_list_assets(client):
    r = client.post("/api/engagements", json={
        "tenant": "AssetTest", "name": "AssetEng", "type": "va", "frameworks": []
    })
    eid = r.json()["id"]

    r2 = client.post(f"/api/engagements/{eid}/assets", json={
        "kind": "web_app",
        "identifier": "https://shop.example.com",
        "environment": "production",
    })
    assert r2.status_code == 201
    assert r2.json()["identifier"] == "https://shop.example.com"

    r3 = client.get(f"/api/engagements/{eid}/assets")
    assert r3.status_code == 200
    assert len(r3.json()) == 1


# ---------------------------------------------------------------- Findings via API (uses pre-seeded data)


def test_list_findings_returns_list(client, loaded):
    """With loaded fixture data the findings endpoint returns a non-empty list."""
    r = client.get(f"/api/engagements/{loaded}/findings")
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, list)
    assert len(body) > 0


def test_findings_have_expected_shape(client, loaded):
    r = client.get(f"/api/engagements/{loaded}/findings")
    f = r.json()[0]
    for key in ("id", "title", "severity", "status", "risk_score", "location", "tools"):
        assert key in f, f"missing key {key!r} in finding dict"


def test_findings_filter_by_status(client, loaded):
    r = client.get(f"/api/engagements/{loaded}/findings", params={"status": "new"})
    assert r.status_code == 200
    body = r.json()
    assert all(f["status"] == "new" for f in body)


# ---------------------------------------------------------------- Transition via API


def test_transition_via_api(client, loaded):
    r = client.get(f"/api/engagements/{loaded}/findings")
    fid = r.json()[0]["id"]

    r2 = client.post(f"/api/findings/{fid}/transition",
                     json={"to": "triaged", "note": ""})
    assert r2.status_code == 200
    assert r2.json()["status"] == "triaged"


def test_transition_invalid_via_api(client, loaded):
    r = client.get(f"/api/engagements/{loaded}/findings")
    fid = r.json()[0]["id"]  # status is 'new'

    r2 = client.post(f"/api/findings/{fid}/transition",
                     json={"to": "retest_passed", "note": ""})
    assert r2.status_code == 409


# ---------------------------------------------------------------- Compliance smoke


def test_compliance_endpoint_returns_results(client, loaded):
    r = client.get(f"/api/engagements/{loaded}/compliance",
                   params={"framework": "pci_dss_4"})
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, list)
    assert len(body) > 0
    # Each result has required keys
    first = body[0]
    for key in ("ref", "title", "status", "proposed"):
        assert key in first


def test_compliance_invalid_framework(client, loaded):
    r = client.get(f"/api/engagements/{loaded}/compliance",
                   params={"framework": "nonexistent_fw"})
    assert r.status_code == 409


# ---------------------------------------------------------------- Audit chain via API


def test_audit_verify_via_api(client, loaded):
    r = client.get("/api/audit/verify")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["first_bad_event"] is None


# ---------------------------------------------------------------- Scan gate: refused → 403


def test_start_scan_refused_returns_403(client, engagement):
    """A scan on an asset with unverified ownership returns 403."""
    from sqlalchemy import select

    from attestra import db
    from attestra.models import Asset

    # Clear ownership verification on the existing storefront asset.
    with db.session() as s:
        a = s.scalars(
            select(Asset).where(Asset.engagement_id == engagement, Asset.kind == "web_app")
        ).first()
        a.ownership_verified_at = None
        a.ownership_token = ""
        a.notes = ""
        asset_id = a.id

    r = client.post(
        f"/api/engagements/{engagement}/scans",
        json={"asset_id": asset_id, "tool": "zap", "profile": "baseline"},
    )
    assert r.status_code == 403


# ---------------------------------------------------------------- Halt engagement → 200


def test_halt_engagement_returns_200(client, engagement):
    r = client.post(f"/api/engagements/{engagement}/halt")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "halted"


def test_halted_engagement_scan_refused(client, engagement):
    """Scan on halted engagement returns 403."""
    from sqlalchemy import select

    from attestra import db, services
    from attestra.models import Asset

    # Halt first
    with db.session() as s:
        services.halt_engagement(s, engagement, actor="tester")

    with db.session() as s:
        asset = s.scalars(
            select(Asset).where(Asset.engagement_id == engagement, Asset.kind == "web_app")
        ).first()
        asset_id = asset.id

    r = client.post(
        f"/api/engagements/{engagement}/scans",
        json={"asset_id": asset_id, "tool": "zap", "profile": "baseline"},
    )
    assert r.status_code == 403
