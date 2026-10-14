"""Phase 4 three-step report workflow."""
# @lat: [[tests#Phase 4 report tests#tests/test_report_workflow.py]]

from __future__ import annotations

import pytest


def test_reject_loop(loaded):
    from attestra import db
    from attestra.auth.keys import create_user
    from attestra.reports import generate_report, qa_reject, submit_report

    with db.session() as s:
        author = create_user(s, username="wf_author", role="tester", password="pw-wf-a1")
        qa = create_user(s, username="wf_qa", role="reviewer", password="pw-wf-q1")
        r = generate_report(s, loaded, kind="technical", actor=author.username, user_id=author.id)
        rid = r.id
        submit_report(s, rid, actor=author.username, user_id=author.id)
        qa_reject(s, rid, actor=qa.username, note="Missing executive summary section", user_id=qa.id)
        s.refresh(r)
        assert r.status == "rejected"
        assert "executive" in r.rejection_note.lower()
        # resubmit after reject
        submit_report(s, rid, actor=author.username, user_id=author.id)
        assert r.status == "submitted"


def test_same_user_cannot_do_two_steps(loaded):
    from attestra import db
    from attestra.auth.keys import create_user
    from attestra.reports import generate_report, qa_approve, submit_report
    from attestra.services import ServiceError

    with db.session() as s:
        author = create_user(s, username="wf_same", role="lead", password="pw-wf-s1")
        r = generate_report(s, loaded, kind="executive", actor=author.username, user_id=author.id)
        rid = r.id
        submit_report(s, rid, actor=author.username, user_id=author.id)
        with pytest.raises(ServiceError, match="four-eyes"):
            qa_approve(s, rid, actor=author.username, user_id=author.id)


def test_full_workflow_three_actors(loaded):
    from attestra import db
    from attestra.auth.keys import create_user
    from attestra.reports import generate_report, qa_approve, sign_report, submit_report, verify_report
    from attestra.services import ServiceError

    with db.session() as s:
        author = create_user(s, username="wf_t", role="tester", password="pw-wf-t1")
        qa = create_user(s, username="wf_r", role="reviewer", password="pw-wf-r1")
        lead = create_user(s, username="wf_l", role="lead", password="pw-wf-l1")
        r = generate_report(s, loaded, kind="technical", actor=author.username, user_id=author.id)
        rid = r.id
        submit_report(s, rid, actor=author.username, user_id=author.id)
        qa_approve(s, rid, actor=qa.username, user_id=qa.id)
        with pytest.raises(ServiceError, match="only lead or admin"):
            sign_report(s, rid, actor=author.username, user_id=author.id, role="tester")
        signed = sign_report(s, rid, actor=lead.username, user_id=lead.id, role="lead")
        assert signed.status == "signed"
        assert signed.algorithm in ("ed25519", "hmac-sha256")
        v = verify_report(s, rid)
        assert v["hash_matches"] and v["signature_valid"]
