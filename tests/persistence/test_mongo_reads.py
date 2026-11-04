"""Mongo read models (``DocView``) over data seeded through MongoSession + services.

Throwaway ``attestra_test_*`` DBs only; no SQL engine and no SQL-vs-Mongo parity.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.persistence.test_mongo_jobflow import _mongo_available, _runs, mdb, mongo_mode  # noqa: F401

pytestmark = pytest.mark.skipif(not _mongo_available(), reason="MongoDB replica set not available")

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture
def seeded(mongo_mode, mdb):
    """Import findings through the services layer and queue two scan runs (all on MongoSession)."""
    from attestra import db, services

    with db.session() as s:
        services.import_results(s, mongo_mode, tool="cyclonedx", filename="bom.json",
                                data=(FIXTURES / "cyclonedx.json").read_bytes(), actor="tester")
    _runs(mongo_mode, 2)
    return mongo_mode


def test_list_findings_returns_docviews(seeded):
    from attestra import db, services
    from attestra.persistence.mongo.read_models import DocView

    with db.session() as s:
        assert type(s).__name__ == "MongoSession"
        rows = services.list_findings(s, seeded)
        assert rows
        assert all(isinstance(r, DocView) for r in rows)
        first = rows[0]
        assert first.engagement_id == seeded and first.title and first.severity and first.status
        # relationship walk used by templates
        assert first.asset is not None and first.asset.id == first.asset_id
        assert first.engagement.id == seeded
        with pytest.raises(AttributeError):
            first.status = "fixed"

        sev = first.severity
        filtered = services.list_findings(s, seeded, severity=sev)
        assert filtered and all(r.severity == sev for r in filtered)
        assert {r.id for r in filtered} <= {r.id for r in rows}


def test_list_scans_and_passed_checks(seeded):
    from attestra import db, services

    with db.session() as s:
        scans = services.list_scans(s, seeded)
        assert len(scans) >= 2
        assert all(sc.engagement_id is None or sc.engagement_id == seeded for sc in scans)
        assert scans[0].asset.engagement_id == seeded
        assert scans[0].tool and scans[0].status and scans[0].profile
        checks = services.list_passed_checks(s, seeded)
        assert isinstance(list(checks), list)


def test_engagements_comments_assignments_collapse(seeded):
    from types import SimpleNamespace

    from attestra import assignments, comments, crossmerge, db, services
    from attestra.models import Engagement, User

    with db.session() as s:
        tid = s.get(Engagement, seeded).tenant_id
        u = User(username="alice", role="tester", tenant_id=tid, password_hash="x", active=True)
        s.add(u)
        s.flush()
        uid = u.id
    p = SimpleNamespace(role="tester", tenant_id=tid, user_id=uid, actor="alice", username="alice")
    admin = SimpleNamespace(role="admin", tenant_id=None, user_id=None, actor="admin")
    with db.session() as s:
        fids = [f.id for f in services.list_findings(s, seeded)]
        comments.add_comment(s, fids[0], body="first", principal=p)
        comments.add_comment(s, fids[0], body="second", principal=p)
        assignments.assign_finding(s, fids[0], assignee="alice", actor="lead")

    with db.session() as s:
        admin_ids = [e.id for e in services.list_engagements(s, admin)]
        member_ids = [e.id for e in services.list_engagements(s, p)]
        bodies = [(c["body"] if isinstance(c, dict) else c.body) for c in comments.list_comments(s, fids[0], p)]
        grouped = {k: [c.body for c in v] for k, v in comments.comments_for_findings(s, fids).items()}
        assignees = assignments.assignees_for_engagement(s, seeded)
        collapsed = crossmerge.collapse(s, services.list_findings(s, seeded))
    assert seeded in admin_ids and seeded in member_ids
    assert bodies == ["first", "second"]
    assert grouped[fids[0]] == ["first", "second"]
    assert assignees == {fids[0]: "alice"}
    assert collapsed and all(getattr(f, "cross_sources", None) is not None for f in collapsed)
