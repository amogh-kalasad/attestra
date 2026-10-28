"""Super Admin Certification Authority settings and report branding."""

from __future__ import annotations

from pathlib import Path

import pytest

# Minimal 1x1 PNG
_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00"
    b"\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
)


def _admin_principal(s, *, username: str = "ca-admin"):
    from attestra.auth.keys import Principal, create_user

    u = create_user(
        s, username=username, role="admin", password="pw-1234567890", display_name="CA Admin"
    )
    return Principal(
        user_id=u.id,
        username=u.username,
        display_name=u.display_name,
        role=u.role,
        tenant_id=u.tenant_id,
    )


def _lead_principal(s, *, username: str = "ca-lead"):
    from attestra.auth.keys import Principal, create_user

    u = create_user(
        s, username=username, role="lead", password="pw-1234567890", display_name="CA Lead"
    )
    return Principal(
        user_id=u.id,
        username=u.username,
        display_name=u.display_name,
        role=u.role,
        tenant_id=u.tenant_id,
    )


# @lat: [[tests#Certification Authority#Admin can save and retrieve settings]]
def test_admin_can_save_and_retrieve(fresh_db):
    from attestra import db
    from attestra.certification import service as ca

    with db.session() as s:
        admin = _admin_principal(s)
        row = ca.update_settings(
            s,
            admin,
            legal_name="Shieldbyte Labs",
            signer_name="Alex Rivera",
            signer_title="Principal",
            authorization_statement="Accredited testing under firm process.",
            address_line1="12 Example St",
            city="Austin",
            state="TX",
            postal_code="78701",
            country="US",
            contact_name="Security Desk",
            contact_email="vapt@shieldbyte.example",
            contact_phone="+1 555 0100",
            website="https://shieldbyte.example",
            logo=_PNG,
        )
        out = ca.settings_dict(row)
    assert out["legal_name"] == "Shieldbyte Labs"
    assert out["has_logo"] is True
    assert out["logo"].startswith("data:image/png;base64,")
    assert out["address_formatted"] == "12 Example St, Austin, TX 78701, US"
    assert out["contact_email"] == "vapt@shieldbyte.example"
    assert out["website"] == "https://shieldbyte.example"


# @lat: [[tests#Certification Authority#Non-admin cannot mutate]]
def test_non_admin_cannot_mutate(fresh_db):
    from attestra import db
    from attestra.certification import service as ca

    with db.session() as s:
        lead = _lead_principal(s)
        with pytest.raises(ca.CertificationError, match="Super Admin"):
            ca.update_settings(s, lead, legal_name="Nope")


# @lat: [[tests#Certification Authority#Invalid logo rejected]]
def test_invalid_logo_rejected(fresh_db):
    from attestra import db
    from attestra.certification import service as ca

    with db.session() as s:
        admin = _admin_principal(s)
        with pytest.raises(ca.CertificationError, match="logo must be"):
            ca.update_settings(s, admin, logo=b"not-an-image")


# @lat: [[tests#Certification Authority#Partial update preserves fields]]
def test_partial_update_preserves_fields(fresh_db):
    from attestra import db
    from attestra.certification import service as ca

    with db.session() as s:
        admin = _admin_principal(s)
        ca.update_settings(
            s,
            admin,
            legal_name="Keep Me",
            contact_email="keep@example.com",
            city="Austin",
        )
        ca.update_settings(s, admin, contact_phone="+1 555 9999")
        out = ca.settings_dict(ca.get_settings(s))
    assert out["legal_name"] == "Keep Me"
    assert out["contact_email"] == "keep@example.com"
    assert out["city"] == "Austin"
    assert out["contact_phone"] == "+1 555 9999"


# @lat: [[tests#Certification Authority#API enforces Super Admin]]
def test_api_enforces_super_admin(fresh_db):
    from attestra import db
    from attestra.auth.keys import create_api_key, create_user
    from fastapi.testclient import TestClient

    from attestra.api import app

    with db.session() as s:
        lead = create_user(s, username="ca-api-lead", role="lead", password="pw-1234567890")
        admin = create_user(s, username="ca-api-admin", role="admin", password="pw-1234567890")
        _, lead_key = create_api_key(s, lead)
        _, admin_key = create_api_key(s, admin)

    client = TestClient(app)
    denied = client.get("/api/certification-authority", headers={"Authorization": f"Bearer {lead_key}"})
    assert denied.status_code == 403

    ok = client.get("/api/certification-authority", headers={"Authorization": f"Bearer {admin_key}"})
    assert ok.status_code == 200
    assert ok.json()["legal_name"] == ""

    saved = client.put(
        "/api/certification-authority",
        headers={"Authorization": f"Bearer {admin_key}"},
        json={"legal_name": "API Firm", "contact_email": "api@firm.example"},
    )
    assert saved.status_code == 200
    assert saved.json()["legal_name"] == "API Firm"

    lead_put = client.put(
        "/api/certification-authority",
        headers={"Authorization": f"Bearer {lead_key}"},
        json={"legal_name": "Hijack"},
    )
    assert lead_put.status_code == 403


# @lat: [[tests#Certification Authority#UI page Super Admin only]]
def test_ui_page_super_admin_only(fresh_db):
    from attestra import db
    from attestra.auth.keys import create_user
    from attestra.auth.session import issue_session
    from fastapi.testclient import TestClient

    from attestra.api import app

    with db.session() as s:
        lead = create_user(s, username="ca-ui-lead", role="lead", password="pw-1234567890")
        admin = create_user(s, username="ca-ui-admin", role="admin", password="pw-1234567890")
        lead_cookie = issue_session(lead.id, lead.username)
        admin_cookie = issue_session(admin.id, admin.username)

    client = TestClient(app, follow_redirects=False)
    lead_resp = client.get(
        "/settings/certification-authority", cookies={"attestra_session": lead_cookie}
    )
    assert lead_resp.status_code in (302, 303)
    assert "Super Admin" in (lead_resp.headers.get("location") or "") or "error=" in (
        lead_resp.headers.get("location") or ""
    )

    admin_resp = client.get(
        "/settings/certification-authority", cookies={"attestra_session": admin_cookie}
    )
    assert admin_resp.status_code == 200
    assert b"Certification Authority" in admin_resp.content
    assert b"Brand Logo" in admin_resp.content
    assert b"Company Address" in admin_resp.content
    assert b"Company Contact" in admin_resp.content
    assert b"Signed Authorization" in admin_resp.content


# @lat: [[tests#Certification Authority#Reports use CA branding]]
def test_reports_use_ca_branding(loaded):
    from attestra import db
    from attestra.certification import service as ca
    from attestra.reports import generate_report

    with db.session() as s:
        admin = _admin_principal(s, username="ca-report-admin")
        ca.update_settings(
            s,
            admin,
            legal_name="Issuer Security Co",
            signer_name="Jamie Lee",
            signer_title="Lead Assessor",
            authorization_statement="Firm accredited process statement.",
            address_line1="100 Report Ave",
            city="Boston",
            country="US",
            contact_email="reports@issuer.example",
            contact_phone="+1 617 555 0100",
            website="issuer.example",
            logo=_PNG,
        )
        tech = generate_report(s, loaded, kind="technical", actor="tester")
        letter = generate_report(s, loaded, kind="attestation_letter", actor="tester")
        tech_body = Path(tech.path).read_text(encoding="utf-8")
        letter_body = Path(letter.path).read_text(encoding="utf-8")

    assert "Issuer Security Co" in tech_body
    assert "100 Report Ave" in tech_body
    assert "reports@issuer.example" in tech_body
    assert "data:image/png;base64," in tech_body
    assert "Jamie Lee" in tech_body
    assert "Firm accredited process statement." in tech_body

    assert "Issuer Security Co" in letter_body
    assert "Jamie Lee" in letter_body
    assert "reports@issuer.example" in letter_body
    assert "https://issuer.example" in letter_body


# @lat: [[tests#Certification Authority#Reports work without CA config]]
def test_reports_work_without_ca_config(loaded):
    from attestra import db
    from attestra.reports import generate_report

    with db.session() as s:
        r = generate_report(s, loaded, kind="technical", actor="tester")
        body = Path(r.path).read_text(encoding="utf-8")
    assert "ATTESTRA" in body
    assert r.sha256
