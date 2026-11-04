"""Phase 5 ticket sync: two-way status, retest on fixed, pluggable backends."""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


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
        services.import_results(
            s,
            eid,
            tool="cyclonedx",
            filename="bom.json",
            data=(FIXTURES / "cyclonedx.json").read_bytes(),
            actor="tester",
        )
        return services.list_findings(s, eid)[0].id


def _validate(s, fid):
    from attestra import services

    services.transition(s, fid, to="triaged", actor="lead")
    services.transition(s, fid, to="validated", actor="lead")


# @lat: [[tests#Phase 5 workflow#Jira create via mock HTTP]]
def test_jira_create_via_mock_http(engagement):
    from attestra import db
    from attestra.integrations import tickets

    http = _FakeHttp({"key": "SEC-99"})
    client = tickets.client_from_env(
        {
            "ATTESTRA_TICKETS_BACKEND": "jira",
            "ATTESTRA_JIRA_URL": "https://jira.example.com",
            "ATTESTRA_JIRA_PROJECT": "SEC",
            "ATTESTRA_JIRA_USER": "bot",
            "ATTESTRA_JIRA_TOKEN": "t",
        },
        http=http,
    )
    fid = _finding(engagement)
    with db.session() as s:
        f = tickets.sync_ticket(s, fid, actor="lead", client=client)
        assert f.ticket_ref == "jira:SEC-99"
    assert len(http.calls) == 1
    method, url, headers, body = http.calls[0]
    assert method == "POST" and url.endswith("/rest/api/2/issue")
    assert body["fields"]["project"]["key"] == "SEC"
    assert headers["Authorization"].startswith("Basic ")


# @lat: [[tests#Phase 5 workflow#GitHub create via mock HTTP]]
def test_github_create_via_mock_http(engagement):
    from attestra import db
    from attestra.integrations import tickets

    http = _FakeHttp({"number": 42})
    client = tickets.client_from_env(
        {
            "ATTESTRA_TICKETS_BACKEND": "github",
            "ATTESTRA_GITHUB_REPO": "acme/app",
            "ATTESTRA_GITHUB_TOKEN": "t",
        },
        http=http,
    )
    fid = _finding(engagement)
    with db.session() as s:
        f = tickets.sync_ticket(s, fid, actor="lead", client=client)
        assert f.ticket_ref == "github:acme/app#42"
    assert http.calls[0][0] == "POST"
    assert "/repos/acme/app/issues" in http.calls[0][1]


# @lat: [[tests#Phase 5 workflow#Webhook closed fixes and requests retest]]
def test_webhook_closed_fixes_and_requests_retest(engagement):
    from sqlalchemy import select

    from attestra import db
    from attestra.integrations import tickets
    from attestra.models import AuditEvent, Retest
    from attestra.retest import open_retests

    fid = _finding(engagement)
    ref = "github:acme/app#7"
    with db.session() as s:
        from attestra.models import Finding

        f = s.get(Finding, fid)
        f.ticket_ref = ref
        _validate(s, fid)
        assert open_retests(s, fid) == []

        payload = {
            "action": "closed",
            "issue": {"number": 7, "state": "closed"},
            "repository": {"full_name": "acme/app"},
        }
        parsed_ref, state = tickets.parse_webhook("github", payload)
        assert parsed_ref == ref and state == "closed"
        out = tickets.apply_ticket_state(s, parsed_ref, state, actor="webhook:github")
        assert out is not None and out.status == "fixed"
        pending = open_retests(s, fid)
        assert len(pending) == 1 and pending[0].result == ""
        assert pending[0].finalized_at is None

        retest_ev = s.scalars(
            select(AuditEvent).where(AuditEvent.action == "finding.ticket_retest")
        ).first()
        assert retest_ev is not None
        assert retest_ev.details["ticket_ref"] == ref
        assert retest_ev.details["retest_id"] == pending[0].id
        req_ev = s.scalars(select(AuditEvent).where(AuditEvent.action == "retest.request")).first()
        assert req_ev is not None and req_ev.entity_id == pending[0].id

        # Second closed event: already fixed -> audit only, no duplicate retest
        tickets.apply_ticket_state(s, ref, "closed", actor="webhook:github")
        assert len(open_retests(s, fid)) == 1
        assert s.scalars(select(Retest).where(Retest.finding_id == fid)).all().__len__() == 1


# @lat: [[tests#Phase 5 workflow#Disallowed transition stays audit only]]
def test_disallowed_transition_stays_audit_only(engagement):
    from sqlalchemy import select

    from attestra import db
    from attestra.integrations import tickets
    from attestra.models import AuditEvent, Finding
    from attestra.retest import open_retests

    fid = _finding(engagement)
    ref = "jira:SEC-1"
    with db.session() as s:
        f = s.get(Finding, fid)
        f.ticket_ref = ref
        # still 'new' — cannot jump to fixed
        out = tickets.apply_ticket_state(s, ref, "closed", actor="webhook:jira")
        assert out.status == "new"
        assert open_retests(s, fid) == []
        skipped = s.scalars(
            select(AuditEvent).where(AuditEvent.action == "finding.ticket_state")
        ).first()
        assert skipped is not None and skipped.details.get("applied") is False
        assert (
            s.scalars(select(AuditEvent).where(AuditEvent.action == "finding.ticket_retest")).first()
            is None
        )


# @lat: [[tests#Phase 5 workflow#Webhook signature still required]]
def test_webhook_signature_still_required(client, monkeypatch):
    body = json.dumps(
        {"issue": {"key": "SEC-1", "fields": {"status": {"name": "Done"}}}}
    ).encode()
    r = client.post("/api/integrations/tickets/jira/webhook", content=body)
    assert r.status_code == 404  # disabled without secret

    monkeypatch.setenv("ATTESTRA_TICKETS_WEBHOOK_SECRET", "s3cret")
    r = client.post(
        "/api/integrations/tickets/jira/webhook",
        content=body,
        headers={"X-Attestra-Signature": "bad"},
    )
    assert r.status_code == 401

    sig = hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
    r = client.post(
        "/api/integrations/tickets/jira/webhook",
        content=body,
        headers={"X-Attestra-Signature": sig},
    )
    assert r.status_code == 200 and r.json()["applied"] is False


# @lat: [[tests#Phase 5 workflow#Unknown backend and disabled stay safe]]
def test_unknown_backend_and_disabled_stay_safe(client, engagement, monkeypatch):
    from attestra import db
    from attestra.integrations import tickets

    monkeypatch.delenv("ATTESTRA_TICKETS_BACKEND", raising=False)
    assert tickets.client_from_env({}) is None

    with pytest.raises(tickets.TicketError, match="unknown ticket backend"):
        tickets.client_from_env({"ATTESTRA_TICKETS_BACKEND": "linear"})

    fid = _finding(engagement)
    with db.session() as s, pytest.raises(tickets.TicketError, match="disabled"):
        tickets.sync_ticket(s, fid, actor="lead")

    r = client.post("/api/integrations/tickets/linear/webhook", content=b"{}")
    assert r.status_code == 404

    monkeypatch.delenv("ATTESTRA_TICKETS_WEBHOOK_SECRET", raising=False)
    r = client.post("/api/integrations/tickets/jira/webhook", content=b"{}")
    assert r.status_code == 404


# @lat: [[tests#Phase 5 workflow#ServiceNow and Azure DevOps stubs]]
def test_servicenow_and_azure_devops_stubs(engagement):
    from attestra import db
    from attestra.integrations import tickets

    assert "servicenow" in tickets.BACKENDS and "azure_devops" in tickets.BACKENDS

    with pytest.raises(tickets.TicketError, match="not configured"):
        tickets.client_from_env({"ATTESTRA_TICKETS_BACKEND": "servicenow"})
    with pytest.raises(tickets.TicketError, match="not configured"):
        tickets.client_from_env({"ATTESTRA_TICKETS_BACKEND": "azure_devops"})

    sn_http = _FakeHttp({"result": {"number": "INC0012345", "sys_id": "abc"}})
    sn = tickets.client_from_env(
        {
            "ATTESTRA_TICKETS_BACKEND": "servicenow",
            "ATTESTRA_SERVICENOW_INSTANCE": "example.service-now.com",
            "ATTESTRA_SERVICENOW_USER": "bot",
            "ATTESTRA_SERVICENOW_TOKEN": "t",
        },
        http=sn_http,
    )
    assert sn.name == "servicenow"

    az_http = _FakeHttp({"id": 88})
    az = tickets.client_from_env(
        {
            "ATTESTRA_TICKETS_BACKEND": "azure_devops",
            "ATTESTRA_AZDO_ORG": "acme",
            "ATTESTRA_AZDO_PROJECT": "sec",
            "ATTESTRA_AZDO_PAT": "t",
        },
        http=az_http,
    )
    assert az.name == "azure_devops"

    fid = _finding(engagement)
    with db.session() as s:
        from attestra import services

        f = tickets.sync_ticket(s, fid, actor="lead", client=sn)
        assert f.ticket_ref == "servicenow:INC0012345"
        other = next(x for x in services.list_findings(s, engagement) if not x.ticket_ref)
        f2 = tickets.sync_ticket(s, other.id, actor="lead", client=az)
        assert f2.ticket_ref == "azure_devops:sec#88"
    assert sn_http.calls[0][1].startswith("https://example.service-now.com/api/now/table/incident")
    assert "workitems/$Issue" in az_http.calls[0][1]
    assert isinstance(az_http.calls[0][3], list)


# @lat: [[tests#Phase 5 workflow#Existing open retest is not duplicated]]
def test_existing_open_retest_not_duplicated(engagement):
    from attestra import db
    from attestra.integrations import tickets
    from attestra.models import Finding
    from attestra.retest import open_retests, request_retest

    fid = _finding(engagement)
    ref = "jira:SEC-55"
    with db.session() as s:
        f = s.get(Finding, fid)
        f.ticket_ref = ref
        _validate(s, fid)
        existing = request_retest(s, fid, actor="lead", note="manual")
        assert len(open_retests(s, fid)) == 1

        out = tickets.apply_ticket_state(s, ref, "Done", actor="webhook:jira")
        assert out.status == "fixed"
        pending = open_retests(s, fid)
        assert len(pending) == 1 and pending[0].id == existing.id
