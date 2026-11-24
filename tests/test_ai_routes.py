"""Step 8.5 wiring: API/UI routes and report gating for AI drafts."""

from __future__ import annotations

import pytest


class FakeProvider:
    name = "fake"

    def complete(self, system, prompt, *, max_tokens=None, timeout=None):
        return "FAKE-AI-NARRATIVE"


@pytest.fixture
def ai_on(monkeypatch):
    from attestra import ai_narratives as ai

    monkeypatch.setenv("ATTESTRA_AI_NARRATIVES", "on")
    ai.set_provider(FakeProvider())
    yield
    ai.set_provider(None)


def _report_html(eid, kind):
    from pathlib import Path

    from attestra import db
    from attestra.reports import generate_report

    with db.session() as s:
        return Path(generate_report(s, eid, kind=kind, actor="lead").path).read_text(encoding="utf-8")


def test_routes_404_when_off(client, engagement, monkeypatch):
    monkeypatch.delenv("ATTESTRA_AI_NARRATIVES", raising=False)
    assert client.get(f"/api/engagements/{engagement}/ai-drafts").status_code == 404
    r = client.post(f"/api/engagements/{engagement}/ai-drafts", json={"kind": "executive_summary"})
    assert r.status_code == 404


def test_unapproved_never_in_report_approved_is(client, loaded, ai_on):
    eid = loaded
    r = client.post(f"/api/engagements/{eid}/ai-drafts", json={"kind": "executive_summary"})
    assert r.status_code == 201 and r.json()["label"] == "AI draft" and r.json()["status"] == "draft"
    did = r.json()["id"]
    assert "FAKE-AI-NARRATIVE" not in _report_html(eid, "executive")
    r = client.post(f"/api/engagements/{eid}/ai-drafts/{did}/approve", json={"text": "Tester-edited summary."})
    assert r.status_code == 200 and r.json()["status"] == "approved"
    html = _report_html(eid, "executive")
    assert "Tester-edited summary." in html and "FAKE-AI-NARRATIVE" not in html


def test_finding_narrative_and_reject(client, loaded, ai_on):
    eid = loaded
    fid = client.get(f"/api/engagements/{eid}/findings").json()[0]["id"]
    a = client.post(f"/api/engagements/{eid}/ai-drafts", json={"kind": "finding", "finding_id": fid}).json()
    b = client.post(f"/api/engagements/{eid}/ai-drafts", json={"kind": "executive_summary"}).json()
    assert client.post(f"/api/engagements/{eid}/ai-drafts/{b['id']}/reject").json()["status"] == "rejected"
    assert "FAKE-AI-NARRATIVE" not in _report_html(eid, "technical")
    client.post(f"/api/engagements/{eid}/ai-drafts/{a['id']}/approve", json={})
    assert "FAKE-AI-NARRATIVE" in _report_html(eid, "technical")
    assert "FAKE-AI-NARRATIVE" not in _report_html(eid, "executive")
    assert (
        client.post(f"/api/engagements/{eid}/ai-drafts", json={"kind": "finding", "finding_id": 999999}).status_code
        == 404
    )


def test_multi_finding_per_and_combined_api(client, loaded, ai_on):
    eid = loaded
    findings = client.get(f"/api/engagements/{eid}/findings").json()
    ids = [f["id"] for f in findings[:2]]
    assert len(ids) >= 1
    batch = client.post(
        f"/api/engagements/{eid}/ai-drafts",
        json={"kind": "finding", "finding_ids": ids, "mode": "per_finding"},
    )
    assert batch.status_code == 201
    body = batch.json()
    if len(ids) == 1:
        assert isinstance(body, dict) and body["kind"] == "finding"
        drafts = [body]
    else:
        assert isinstance(body, list) and len(body) == len(ids)
        drafts = body
    assert all(d["kind"] == "finding" and "## Description" in d["text"] for d in drafts)

    if len(ids) >= 2:
        combined = client.post(
            f"/api/engagements/{eid}/ai-drafts",
            json={"kind": "finding", "finding_ids": ids, "mode": "combined"},
        )
        assert combined.status_code == 201
        c = combined.json()
        assert isinstance(c, dict) and c["kind"] == "finding_combined" and c["finding_id"] is None
        client.post(f"/api/engagements/{eid}/ai-drafts/{c['id']}/approve", json={})
        html = _report_html(eid, "technical")
        assert "AI combined finding writeup" in html
        assert "FAKE-AI-NARRATIVE" in html


def test_reviewer_cannot_use_drafts(client, engagement, api_credentials, ai_on):
    h = {"Authorization": f"Bearer {api_credentials['reviewer_key']}"}
    assert client.get(f"/api/engagements/{engagement}/ai-drafts", headers=h).status_code == 403
    assert client.post(f"/api/engagements/{engagement}/ai-drafts/x/approve", json={}, headers=h).status_code == 403


def test_off_reports_unchanged_even_with_approved_file(client, loaded, ai_on, monkeypatch):
    eid = loaded
    d = client.post(f"/api/engagements/{eid}/ai-drafts", json={"kind": "executive_summary"}).json()
    client.post(f"/api/engagements/{eid}/ai-drafts/{d['id']}/approve", json={})
    monkeypatch.setenv("ATTESTRA_AI_NARRATIVES", "off")
    assert "FAKE-AI-NARRATIVE" not in _report_html(eid, "executive")


def test_ui_pages(loaded, ai_on):
    from fastapi.testclient import TestClient

    from attestra import db
    from attestra.api import app
    from attestra.auth.keys import create_user
    from attestra.models import Engagement

    eid = loaded
    with db.session() as s:
        tid = s.get(Engagement, eid).tenant_id
        for name, role in (("t-ai", "tester"), ("c-ai", "client_viewer")):
            u = create_user(s, username=name, role=role, password="pw-123456", display_name=name)
            u.tenant_id = tid
    with TestClient(app) as c:
        c.post("/login", data={"username": "t-ai", "password": "pw-123456"}, follow_redirects=False)
        r = c.post(f"/engagements/{eid}/ai-drafts", data={"kind": "executive_summary"}, follow_redirects=False)
        assert r.status_code == 303
        page = c.get(f"/engagements/{eid}/ai-drafts")
        assert page.status_code == 200 and "AI draft" in page.text and "FAKE-AI-NARRATIVE" in page.text
        assert "Select needing writeup" in page.text
        assert "ai-finding-list" in page.text
        # No approved finding narrative yet → no In-report highlight on rows.
        assert "In report" not in page.text
        assert 'data-approved="1"' not in page.text
        assert 'class="ai-finding-row ai-finding-approved"' not in page.text
    with TestClient(app) as c:
        c.post("/login", data={"username": "c-ai", "password": "pw-123456"}, follow_redirects=False)
        assert c.get(f"/engagements/{eid}/ai-drafts").status_code == 403
        assert c.post(f"/engagements/{eid}/ai-drafts", data={"kind": "executive_summary"}).status_code == 403


def test_ui_highlights_approved_findings_in_create_picker(loaded, ai_on, client):
    """Create-draft checklist marks findings whose AI writeup is already approved for reports."""
    from fastapi.testclient import TestClient

    from attestra import db
    from attestra.api import app
    from attestra.auth.keys import create_user
    from attestra.models import Engagement

    eid = loaded
    findings = client.get(f"/api/engagements/{eid}/findings").json()
    assert findings
    fid = findings[0]["id"]
    draft = client.post(f"/api/engagements/{eid}/ai-drafts", json={"kind": "finding", "finding_id": fid}).json()
    client.post(f"/api/engagements/{eid}/ai-drafts/{draft['id']}/approve", json={})

    with db.session() as s:
        tid = s.get(Engagement, eid).tenant_id
        u = create_user(s, username="t-ai-hl", role="tester", password="pw-123456", display_name="t-ai-hl")
        u.tenant_id = tid
    with TestClient(app) as c:
        c.post("/login", data={"username": "t-ai-hl", "password": "pw-123456"}, follow_redirects=False)
        page = c.get(f"/engagements/{eid}/ai-drafts")
        assert page.status_code == 200
        html = page.text
        assert f'value="{fid}"' in html
        assert 'class="ai-finding-row ai-finding-approved"' in html
        assert "In report" in html
        assert 'data-approved="1"' in html
        assert 'id="ai_approved_legend"' in html
        assert "Select needing writeup" in html
