"""Phase 7.1 (client portal / auditor view) and 7.2 (ticket sync, SBOM importers)."""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------- 7.2 importers


def test_cyclonedx_parser_skips_not_affected():
    from attestra.importers import parse

    rows = parse("cyclonedx", (FIXTURES / "cyclonedx.json").read_bytes())
    ids = sorted(r.rule_id for r in rows)
    assert ids == ["CVE-2018-18074", "CVE-2021-23337"]
    lodash = next(r for r in rows if r.rule_id == "CVE-2021-23337")
    assert lodash.severity == "high" and lodash.cvss_score == 7.2 and lodash.cwe == 94
    assert lodash.package == "lodash@4.17.20"
    assert lodash.location.startswith("registry.example.com/shop/api::")


def test_cyclonedx_rejects_other_documents():
    from attestra.importers import parse

    with pytest.raises(ValueError):
        parse("cyclonedx", b'{"bomFormat": "SPDX"}')


def test_dependency_track_parser_skips_suppressed():
    from attestra.importers import parse

    rows = parse("dependency_track", (FIXTURES / "dependency_track.json").read_bytes())
    assert len(rows) == 1
    r = rows[0]
    assert r.rule_id == "CVE-2019-12384" and r.severity == "high" and r.cwe == 502
    assert r.location.startswith("services/payments::")


def test_dependency_track_fpf_wrapper():
    from attestra.importers import parse

    items = json.loads((FIXTURES / "dependency_track.json").read_text())
    doc = {"project": {"name": "services/payments"}, "findings": items}
    assert len(parse("dependency_track", json.dumps(doc).encode())) == 1


def test_sbom_import_matches_targets(engagement):
    from attestra import db, services

    with db.session() as s:
        run = services.import_results(
            s, engagement, tool="cyclonedx", filename="bom.json",
            data=(FIXTURES / "cyclonedx.json").read_bytes(), actor="tester",
        )
        assert run.new_findings == 2 and run.unmatched_findings == 0


# ---------------------------------------------------------------- 7.2 ticket sync


class _FakeHttp:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, headers, body))
        return self.response


def _finding(eid):
    from attestra import db, services

    with db.session() as s:
        services.import_results(s, eid, tool="cyclonedx", filename="bom.json",
                                data=(FIXTURES / "cyclonedx.json").read_bytes(), actor="tester")
        return services.list_findings(s, eid)[0].id


def test_ticket_sync_disabled_by_default(engagement, monkeypatch):
    from attestra import db
    from attestra.integrations import tickets

    monkeypatch.delenv("ATTESTRA_TICKETS_BACKEND", raising=False)
    assert tickets.client_from_env({}) is None
    fid = _finding(engagement)
    with db.session() as s, pytest.raises(tickets.TicketError):
        tickets.sync_ticket(s, fid, actor="lead")


def test_jira_sync_sets_ticket_ref_once(engagement):
    from attestra import db
    from attestra.integrations import tickets

    http = _FakeHttp({"key": "SEC-12"})
    client = tickets.client_from_env({
        "ATTESTRA_TICKETS_BACKEND": "jira", "ATTESTRA_JIRA_URL": "https://jira.example.com",
        "ATTESTRA_JIRA_PROJECT": "SEC", "ATTESTRA_JIRA_USER": "bot", "ATTESTRA_JIRA_TOKEN": "t",
    }, http=http)
    fid = _finding(engagement)
    with db.session() as s:
        f = tickets.sync_ticket(s, fid, actor="lead", client=client)
        assert f.ticket_ref == "jira:SEC-12"
        tickets.sync_ticket(s, fid, actor="lead", client=client)
    assert len(http.calls) == 1
    method, url, headers, body = http.calls[0]
    assert method == "POST" and url == "https://jira.example.com/rest/api/2/issue"
    assert body["fields"]["project"]["key"] == "SEC" and headers["Authorization"].startswith("Basic ")


def test_github_sync_and_webhook_back_sync(engagement):
    from attestra import db, services
    from attestra.integrations import tickets

    http = _FakeHttp({"number": 34})
    client = tickets.client_from_env({
        "ATTESTRA_TICKETS_BACKEND": "github", "ATTESTRA_GITHUB_REPO": "acme/app", "ATTESTRA_GITHUB_TOKEN": "t",
    }, http=http)
    fid = _finding(engagement)
    with db.session() as s:
        assert tickets.sync_ticket(s, fid, actor="lead", client=client).ticket_ref == "github:acme/app#34"
        # 'new' cannot jump to 'fixed': only audited, status unchanged
        payload = {"action": "closed", "issue": {"number": 34, "state": "closed"}, "repository": {"full_name": "acme/app"}}
        ref, state = tickets.parse_webhook("github", payload)
        assert tickets.apply_ticket_state(s, ref, state, actor="webhook").status == "new"
        services.transition(s, fid, to="triaged", actor="lead")
        services.transition(s, fid, to="validated", actor="lead")
        assert tickets.apply_ticket_state(s, ref, state, actor="webhook").status == "fixed"


def test_https_required_for_ticket_http():
    from attestra.integrations import tickets

    with pytest.raises(tickets.TicketError):
        tickets.http_json("POST", "http://jira.example.com/x", {}, {})


def test_webhook_endpoint_signature(client, monkeypatch):
    body = json.dumps({"issue": {"key": "SEC-1", "fields": {"status": {"name": "Done"}}}}).encode()
    r = client.post("/api/integrations/tickets/jira/webhook", content=body)
    assert r.status_code == 404  # disabled without a secret
    monkeypatch.setenv("ATTESTRA_TICKETS_WEBHOOK_SECRET", "s3cret")
    r = client.post("/api/integrations/tickets/jira/webhook", content=body, headers={"X-Attestra-Signature": "bad"})
    assert r.status_code == 401
    sig = hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
    r = client.post("/api/integrations/tickets/jira/webhook", content=body, headers={"X-Attestra-Signature": sig})
    assert r.status_code == 200 and r.json()["applied"] is False


def test_ticket_endpoint_disabled_returns_409(client, engagement, monkeypatch):
    monkeypatch.delenv("ATTESTRA_TICKETS_BACKEND", raising=False)
    fid = _finding(engagement)
    r = client.post(f"/api/findings/{fid}/ticket")
    assert r.status_code == 409


# ---------------------------------------------------------------- 7.1 portal / auditor


def _login(c, username, role, tenant_id=None):
    from attestra import db
    from attestra.auth.keys import create_user

    with db.session() as s:
        u = create_user(s, username=username, role=role, password="pw-123456", display_name=username)
        if tenant_id is not None:
            u.tenant_id = tenant_id
    r = c.post("/login", data={"username": username, "password": "pw-123456"}, follow_redirects=False)
    assert r.status_code in (302, 303)


def _tenant_of(eid):
    from attestra import db
    from attestra.models import Engagement

    with db.session() as s:
        return s.get(Engagement, eid).tenant_id


def test_client_portal_hides_untriaged(engagement):
    from fastapi.testclient import TestClient

    from attestra import db, services
    from attestra.api import app

    fid = _finding(engagement)
    with db.session() as s:
        services.transition(s, fid, to="triaged", actor="lead")
    with TestClient(app) as c:
        _login(c, "client1", "client_viewer", _tenant_of(engagement))
        home = c.get("/portal")
        assert home.status_code == 200 and "Test VAPT Engagement" in home.text
        page = c.get(f"/portal/engagements/{engagement}")
        assert page.status_code == 200
        assert page.text.count("<span class=\"pill") >= 1
        assert "CVE-2021-23337" in page.text or "CVE-2018-18074" in page.text
        # one finding triaged, the other still 'new' and hidden
        assert not ("CVE-2021-23337" in page.text and "CVE-2018-18074" in page.text)
        assert c.get(f"/auditor/engagements/{engagement}").status_code == 403


def test_read_only_roles_cannot_post_ui_writes(engagement):
    from fastapi.testclient import TestClient

    from attestra.api import app

    with TestClient(app) as c:
        _login(c, "aud1", "auditor", _tenant_of(engagement))
        r = c.post(f"/engagements/{engagement}/halt", follow_redirects=False)
        assert r.status_code == 403
        r = c.get("/", follow_redirects=False)
        assert r.status_code in (302, 303) and r.headers["location"].startswith("/portal")


def test_auditor_view_shows_chain_and_events(engagement):
    from fastapi.testclient import TestClient

    from attestra.api import app

    with TestClient(app) as c:
        _login(c, "aud2", "auditor", _tenant_of(engagement))
        page = c.get(f"/auditor/engagements/{engagement}")
        assert page.status_code == 200
        assert "Hash chain verified" in page.text and "engagement.create" in page.text
