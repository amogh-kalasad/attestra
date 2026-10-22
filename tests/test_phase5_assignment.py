"""Finding assignment: assign/unassign, current assignee, assigned-to-me filter."""
from __future__ import annotations

from sqlalchemy import select

from attestra import db
from attestra.auth.keys import create_user
from attestra.models import AuditEvent, Engagement, Finding, FindingAssignment, Tenant, TenantMembership
from attestra.services import ServiceError


def _finding(s, engagement_id: int, *, title: str = "assign-me", fp: str = "assign-fp-1") -> Finding:
    f = Finding(
        engagement_id=engagement_id,
        title=title,
        severity="high",
        status="new",
        fingerprint=fp,
        risk_score=8.0,
    )
    s.add(f)
    s.flush()
    return f


# @lat: [[tests#Phase 5 workflow#Assign and audit]]
def test_assign_finding_and_audit(engagement):
    from attestra import assignments

    with db.session() as s:
        e = s.get(Engagement, engagement)
        create_user(
            s,
            username="alice",
            role="tester",
            password="pw-alice-01",
            tenant_id=e.tenant_id,
        )
        f = _finding(s, engagement)
        fid = f.id
        row = assignments.assign_finding(s, fid, assignee="alice", actor="lead", user_id=1)
        assert row.assignee == "alice"
        assert row.assigned_by == "lead"
        assert row.rule_id is None
        assert assignments.current_assignee(s, fid) == "alice"
        ev = s.scalars(
            select(AuditEvent).where(AuditEvent.action == "finding.assigned", AuditEvent.entity_id == fid)
        ).first()
        assert ev is not None
        assert ev.details.get("assignee") == "alice"
        assert ev.details.get("user_id") == 1


# @lat: [[tests#Phase 5 workflow#Unassign and audit]]
def test_unassign_finding_and_audit(engagement):
    from attestra import assignments

    with db.session() as s:
        e = s.get(Engagement, engagement)
        create_user(
            s,
            username="bob",
            role="tester",
            password="pw-bob-01",
            tenant_id=e.tenant_id,
        )
        f = _finding(s, engagement, fp="unassign-fp")
        fid = f.id
        assignments.assign_finding(s, fid, assignee="bob", actor="lead")
        assert assignments.current_assignee(s, fid) == "bob"
        assignments.unassign_finding(s, fid, actor="lead")
        assert assignments.current_assignee(s, fid) is None
        last = s.scalars(
            select(FindingAssignment)
            .where(FindingAssignment.finding_id == fid)
            .order_by(FindingAssignment.id.desc())
        ).first()
        assert last is not None and last.assignee == ""
        ev = s.scalars(
            select(AuditEvent).where(AuditEvent.action == "finding.unassigned", AuditEvent.entity_id == fid)
        ).first()
        assert ev is not None
        assert ev.actor == "lead"


# @lat: [[tests#Phase 5 workflow#Assigned-to-me filter]]
def test_findings_assigned_to_filter(engagement):
    from attestra import assignments

    with db.session() as s:
        e = s.get(Engagement, engagement)
        create_user(
            s,
            username="carol",
            role="tester",
            password="pw-carol-01",
            tenant_id=e.tenant_id,
        )
        create_user(
            s,
            username="dave",
            role="tester",
            password="pw-dave-01",
            tenant_id=e.tenant_id,
        )
        mine = _finding(s, engagement, title="mine", fp="filter-mine")
        other = _finding(s, engagement, title="other", fp="filter-other")
        cleared = _finding(s, engagement, title="cleared", fp="filter-cleared")
        assignments.assign_finding(s, mine.id, assignee="carol", actor="lead")
        assignments.assign_finding(s, other.id, assignee="dave", actor="lead")
        assignments.assign_finding(s, cleared.id, assignee="carol", actor="lead")
        assignments.unassign_finding(s, cleared.id, actor="lead")
        rows = assignments.findings_assigned_to(s, engagement, "carol")
        assert [r.id for r in rows] == [mine.id]


# @lat: [[tests#Phase 5 workflow#Reject cross-tenant or unknown user]]
def test_assign_rejects_cross_tenant_and_unknown(engagement):
    from attestra import assignments

    with db.session() as s:
        e = s.get(Engagement, engagement)
        create_user(
            s,
            username="local",
            role="tester",
            password="pw-local-01",
            tenant_id=e.tenant_id,
        )
        other = Tenant(name="Other Client")
        s.add(other)
        s.flush()
        create_user(
            s,
            username="outsider",
            role="tester",
            password="pw-out-01",
            tenant_id=other.id,
        )
        create_user(
            s,
            username="platadmin",
            role="admin",
            password="pw-admin-01",
            tenant_id=None,
        )
        f = _finding(s, engagement, fp="reject-fp")
        fid = f.id

        try:
            assignments.assign_finding(s, fid, assignee="nobody", actor="lead")
            assert False, "expected ServiceError for unknown user"
        except ServiceError as err:
            assert "unknown" in str(err).lower()

        try:
            assignments.assign_finding(s, fid, assignee="outsider", actor="lead")
            assert False, "expected ServiceError for cross-tenant"
        except ServiceError as err:
            assert "tenant" in str(err).lower()

        # Platform admin may be assigned across tenants.
        row = assignments.assign_finding(s, fid, assignee="platadmin", actor="lead")
        assert row.assignee == "platadmin"

        # Membership in the finding tenant also counts.
        member = create_user(
            s,
            username="member",
            role="tester",
            password="pw-mem-01",
            tenant_id=None,
        )
        s.add(TenantMembership(user_id=member.id, tenant_id=e.tenant_id, role="tester"))
        s.flush()
        row2 = assignments.assign_finding(s, fid, assignee="member", actor="lead")
        assert row2.assignee == "member"

def test_assign_api_and_ui_filter(client, loaded, auth_headers):
    from attestra import db, services
    from attestra.assignments import current_assignee
    from attestra.auth.keys import create_user
    from attestra.models import Engagement

    with db.session() as s:
        eng = s.get(Engagement, loaded)
        create_user(
            s,
            username="assignee1",
            role="tester",
            password="pw-assignee-01",
            tenant_id=eng.tenant_id,
        )
        fid = services.list_findings(s, loaded)[0].id

    r = client.post(
        f"/api/findings/{fid}/assign", headers=auth_headers, json={"assignee": "assignee1"}
    )
    assert r.status_code == 200, r.text
    assert r.json()["assignee"] == "assignee1"
    assert client.get(f"/api/findings/{fid}/assignee", headers=auth_headers).json()["assignee"] == "assignee1"

    client.headers.pop("Authorization", None)
    assert client.post(
        "/login", data={"username": "lead", "password": "test-pass-lead"}, follow_redirects=False
    ).status_code == 303
    page = client.get(f"/engagements/{loaded}")
    assert 'id="ff-assigned"' in page.text
    assert 'data-assignee="assignee1"' in page.text
    detail = client.get(f"/engagements/{loaded}/findings/{fid}")
    assert detail.status_code == 200
    assert 'id="assign"' in detail.text
    assert client.post(
        f"/engagements/{loaded}/findings/{fid}/assign",
        data={"assignee": ""},
        follow_redirects=False,
    ).status_code in (302, 303)
    with db.session() as s:
        assert current_assignee(s, fid) is None
