"""Phase 2 UI: labels, findings filter markup, evidence download, confirm dialog, ownership."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import select

from attestra import db, services
from attestra.api import app
from attestra.auth.keys import create_user
from attestra.models import DISPLAY_LABELS, TEST_TYPES, AuditEvent, Engagement
from attestra.web.ui import label

FIXTURES = Path(__file__).parent / "fixtures"


def _login_client(username: str = "p2-lead", password: str = "pw-1234567890", *, tenant_id: int | None = None):
    with db.session() as s:
        u = create_user(s, username=username, role="lead", password=password, display_name=username)
        if tenant_id is not None:
            u.tenant_id = tenant_id
    c = TestClient(app)
    c.post("/login", data={"username": username, "password": password}, follow_redirects=False)
    return c


def test_display_labels_secure_config_and_web_dast():
    assert TEST_TYPES["web_dast"]["label"] == "Web application scan"
    assert DISPLAY_LABELS["secure_config"] == "Secure configuration"
    assert label("secure_config") == "Secure configuration"
    assert label("web_dast") == "Web application scan"
    assert label("risk_accepted") == "Risk accepted"
    assert label("unknown_key_xyz") == "Unknown key xyz"


def test_confirm_dialog_markup_in_layout(fresh_db, engagement):
    with db.session() as s:
        tid = s.get(Engagement, engagement).tenant_id
    c = _login_client(tenant_id=tid)
    r = c.get(f"/engagements/{engagement}")
    assert r.status_code == 200
    assert 'id="confirm-backdrop"' in r.text
    assert 'id="confirm-message"' in r.text
    assert 'id="confirm-ok"' in r.text
    assert 'id="confirm-cancel"' in r.text
    assert "data-confirm=" in r.text
    assert "return confirm(" not in r.text


def test_findings_filter_markup_on_engagement(fresh_db, loaded):
    with db.session() as s:
        tid = s.get(Engagement, loaded).tenant_id
    c = _login_client(username="p2-ff", tenant_id=tid)
    r = c.get(f"/engagements/{loaded}")
    assert r.status_code == 200
    assert 'id="ff-severity"' in r.text
    assert 'id="ff-status"' in r.text
    assert 'id="ff-tool"' in r.text
    assert 'id="ff-asset"' in r.text
    assert "finding-row" in r.text
    assert "data-severity=" in r.text
    assert "Export findings CSV" in r.text


def test_evidence_download_ui_route(fresh_db, loaded):
    with db.session() as s:
        tid = s.get(Engagement, loaded).tenant_id
        findings = services.list_findings(s, loaded)
        ev = services.add_evidence(
            s,
            findings[0].id,
            kind="note",
            filename="p2-dl.txt",
            data=b"phase2 download body",
            note="",
            actor="tester",
        )
        evid, eid, fid = ev.id, loaded, findings[0].id

    c = _login_client(username="p2-ev", tenant_id=tid)
    r = c.get(f"/engagements/{eid}/evidence/{evid}/download")
    assert r.status_code == 200
    assert r.content == b"phase2 download body"

    page = c.get(f"/engagements/{eid}/findings/{fid}")
    assert page.status_code == 200
    assert f"/engagements/{eid}/evidence/{evid}/download" in page.text

    with db.session() as s:
        rows = list(
            s.scalars(
                select(AuditEvent).where(
                    AuditEvent.action == "evidence.download",
                    AuditEvent.entity_id == evid,
                )
            )
        )
        assert len(rows) >= 1


def test_evidence_download_requires_auth(fresh_db, loaded):
    with db.session() as s:
        findings = services.list_findings(s, loaded)
        ev = services.add_evidence(
            s,
            findings[0].id,
            kind="note",
            filename="p2-unauth.txt",
            data=b"secret",
            note="",
            actor="tester",
        )
        evid, eid = ev.id, loaded
    with TestClient(app) as c:
        r = c.get(f"/engagements/{eid}/evidence/{evid}/download", follow_redirects=False)
        assert r.status_code in (302, 303)
        assert "/login" in (r.headers.get("location") or "")


def test_ownership_fields_on_asset_page(fresh_db, engagement):
    with db.session() as s:
        e = services.get_engagement(s, engagement)
        tid = e.tenant_id
        asset = next(a for a in e.assets if a.kind == "web_app")
        services.ensure_ownership_tokens(e)
        aid, token = asset.id, asset.ownership_token
        assert token

    c = _login_client(username="p2-own", tenant_id=tid)
    r = c.get(f"/engagements/{engagement}/targets/{aid}")
    assert r.status_code == 200
    assert 'id="ownership"' in r.text
    assert f"attestra-verify={token}" in r.text
    assert 'data-copy="' in r.text
    assert "Ownership verification" in r.text


def test_api_findings_filter_tool_and_asset(client, loaded):
    with db.session() as s:
        rows = services.list_findings(s, loaded)
        assert rows
        tool = (rows[0].tools or ["zap"])[0]
        asset_id = rows[0].asset_id
    r = client.get(f"/api/engagements/{loaded}/findings", params={"tool": tool})
    assert r.status_code == 200
    body = r.json()
    assert body
    assert all(tool in (f.get("tools") or []) for f in body)
    if asset_id is not None:
        r2 = client.get(f"/api/engagements/{loaded}/findings", params={"asset_id": asset_id})
        assert r2.status_code == 200
        assert all(f.get("asset_id") == asset_id for f in r2.json())


# @lat: [[tests#Phase 2 bug fixes#Known emails skip revoked used invites]]
def test_known_emails_skip_revoked_and_used(fresh_db, engagement):
    from attestra.alerts import service as alerts
    from attestra.auth.keys import Principal
    from attestra.models import Engagement
    from attestra.users import service as users

    with db.session() as s:
        e = s.get(Engagement, engagement)
        tid = e.tenant_id
        admin = create_user(
            s, username="p2-admin", role="admin", password="pw-1234567890",
            display_name="P2 Admin", tenant_id=tid,
        )
        principal = Principal(
            user_id=admin.id, username=admin.username, display_name=admin.display_name,
            role=admin.role, tenant_id=tid,
        )
        open_inv, _ = users.create_invite(
            s, principal, email="open@example.com", role="tester", tenant_id=tid,
        )
        revoked_inv, _ = users.create_invite(
            s, principal, email="revoked@example.com", role="tester", tenant_id=tid,
        )
        users.revoke_invite(s, principal, revoked_inv.id)
        used_inv, _ = users.create_invite(
            s, principal, email="used@example.com", role="tester", tenant_id=tid,
        )
        used_inv.used_at = open_inv.created_at
        emails = alerts.known_tenant_emails(s, tid)
    assert "open@example.com" in emails
    assert "revoked@example.com" not in emails
    assert "used@example.com" not in emails


# @lat: [[tests#Phase 2 bug fixes#iso_soa framework display name]]
def test_iso_soa_uses_framework_display_name(loaded):
    from attestra.reports import generate_report

    with db.session() as s:
        r = generate_report(
            s, loaded, kind="iso_soa", actor="tester", framework="iso_27001_2022",
        )
        html = Path(r.path).read_text(encoding="utf-8")
    assert "iso_27001_2022" not in html or "ISO" in html
    assert "ISO" in html and "27001" in html


# @lat: [[tests#Phase 2 bug fixes#PDF human times use display TZ]]
def test_human_times_use_display_tz(monkeypatch):
    from attestra.reports import pdf as pdf_mod

    monkeypatch.setenv("ATTESTRA_DISPLAY_TZ", "Asia/Kolkata")
    out = pdf_mod._human_times("<html><body>on 2026-10-22 07:35:54+00:00.</body></html>")
    assert "22 Oct 2026" in out
    assert "IST" in out
    assert "07:35:54" not in out


# @lat: [[tests#Phase 2 bug fixes#Workflow rule deactivate]]
def test_workflow_rule_deactivate_stops_matching(client, engagement):
    from attestra.models import Engagement, Finding, WorkflowRule
    from attestra.webhooks import service as wh

    with db.session() as s:
        e = s.get(Engagement, engagement)
        tid = e.tenant_id
        rule = wh.create_rule(
            s, tid, action="assign", actor="lead", name="p2-assign",
            event="", min_severity="info", assignee="tester",
        )
        rid = rule.id
        f = Finding(
            engagement_id=engagement, title="p2 wf", severity="high", status="new",
            fingerprint="p2-wf-fp", risk_score=9.0,
        )
        s.add(f)
        s.flush()
        assert wh.rule_matches(rule, "finding.created", f) is True

    assert client.delete(f"/api/workflow-rules/{rid}").status_code == 200
    with db.session() as s:
        rule = s.get(WorkflowRule, rid)
        assert rule is not None and rule.active is False
        f = s.scalars(select(Finding).where(Finding.fingerprint == "p2-wf-fp")).first()
        assert f is not None
        assert wh.rule_matches(rule, "finding.created", f) is False

    r = client.post(f"/api/workflow-rules/{rid}/deactivate")
    assert r.status_code == 200
    assert r.json().get("active") is False
