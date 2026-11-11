"""Phase 10: real PoC evidence in reproduction steps + QA gates for the review process.

Covers the "make it genuine" gaps: generic "Navigate to X / reproduce with scanner
evidence" text must give way to real captured HTTP request/response steps when
evidence exists, QA must block sign-off while a background scan is still running,
and QA must surface (without hard-blocking) when multi-role IDOR/BOLA or
state-changing write-path probes were skipped or blocked.
"""

from __future__ import annotations


# @lat: [[tests#Phase 10 report genuineness#Reproduction steps use real HTTP evidence]]
def test_reproduction_steps_prefer_real_http_pair(fresh_db, loaded):
    from attestra import db, services
    from attestra.proof.pair import HttpPair
    from attestra.proof.store import attach_http_pair
    from attestra.reports.render import _reproduction_steps_for_finding

    pair = HttpPair(
        method="POST",
        url="https://app.example/api/projects/42",
        request_headers={"Content-Type": "application/json"},
        request_body='{"project_id": 42}',
        status=200,
        response_headers={"Content-Type": "application/json"},
        response_body='{"ok": true}',
        source="test",
    )
    with db.session() as s:
        f = services.list_findings(s, loaded)[0]
        fid = f.id
        attach_http_pair(s, fid, pair, actor="tester", note="manual PoC")

    with db.session() as s:
        from attestra.models import Finding

        f2 = s.get(Finding, fid)
        steps = _reproduction_steps_for_finding(f2)

    assert "Send POST https://app.example/api/projects/42" in steps
    assert "server responded 200" in steps
    assert "attached" in steps.lower()
    assert "Reproduce with" not in steps  # no leftover generic boilerplate
    assert "Navigate to" not in steps


# @lat: [[tests#Phase 10 report genuineness#Honest fallback without evidence]]
def test_reproduction_steps_honest_when_unvalidated_and_no_evidence(fresh_db, loaded):
    from attestra import db, services
    from attestra.reports.render import _reproduction_steps_for_finding, _validation_status_of

    with db.session() as s:
        f = services.list_findings(s, loaded)[0]
        # Freshly imported scanner findings default to unvalidated (never auto-confirmed).
        assert _validation_status_of(f) == "unvalidated"
        steps = _reproduction_steps_for_finding(f)

    assert "automated scanner/import observation only" in steps
    assert "no manual proof-of-concept" in steps


# @lat: [[tests#Phase 10 report genuineness#QA blocks sign-off while a scan is running]]
def test_qa_blocks_while_background_scan_running(fresh_db, engagement):
    from sqlalchemy import select

    from attestra import db
    from attestra.models import Asset, AutomatedTestExecution, Engagement
    from attestra.reports import generate_report
    from attestra.reports.qa import run_report_qa

    with db.session() as s:
        eng = s.get(Engagement, engagement)
        asset = s.scalars(select(Asset).where(Asset.engagement_id == eng.id)).first()
        ex = AutomatedTestExecution(
            engagement_id=eng.id,
            tenant_id=eng.tenant_id,
            asset_id=asset.id if asset else None,
            target_base_url="https://lab.example.test/",
            status="RUNNING",
            profile="baseline",
            test_case_ids=["T20"],
            requested_by="tester",
        )
        s.add(ex)
        s.commit()
        r = generate_report(s, engagement, kind="technical", actor="tester")
        result = run_report_qa(s, r.id)

    codes = {i.code for i in result.issues}
    assert "background_scan_in_progress" in codes
    assert result.ok is False


# @lat: [[tests#Phase 10 report genuineness#QA warns on skipped IDOR BOLA probes]]
def test_qa_warns_on_authz_manual_testing_gap(fresh_db, engagement):
    from sqlalchemy import select

    from attestra import db
    from attestra.models import Asset, AutomatedTestExecution, Engagement
    from attestra.reports import generate_report
    from attestra.reports.qa import run_report_qa

    with db.session() as s:
        eng = s.get(Engagement, engagement)
        asset = s.scalars(select(Asset).where(Asset.engagement_id == eng.id)).first()
        ex = AutomatedTestExecution(
            engagement_id=eng.id,
            tenant_id=eng.tenant_id,
            asset_id=asset.id if asset else None,
            target_base_url="https://lab.example.test/",
            status="COMPLETED",
            profile="baseline",
            test_case_ids=["T22"],
            result_json=(
                '{"cases":['
                '{"test_id":"T22","status":"SKIPPED","skip_reason":"no_write_templates",'
                '"detail":"no captured POST/PUT/PATCH JSON bodies"}'
                "]}"
            ),
            requested_by="tester",
        )
        s.add(ex)
        s.commit()
        r = generate_report(s, engagement, kind="technical", actor="tester")
        result = run_report_qa(s, r.id)

    gap_issues = [i for i in result.issues if i.code == "authz_manual_testing_gap"]
    assert gap_issues
    assert gap_issues[0].severity == "warning"
    assert "T22" in gap_issues[0].message
    # Warnings alone never block sign-off.
    assert all(i.severity != "critical" for i in gap_issues)


# @lat: [[tests#Phase 10 report genuineness#Live HTML view drops DRAFT mark once signed]]
def test_html_view_drops_draft_mark_once_signed(client, loaded, monkeypatch):
    """The sealed file is frozen with is_draft=True, but the served /reports/{rid}
    page must not still show the background "DRAFT" watermark once the report is
    actually signed — only the sign-off banner (added at view time) should remain.
    """
    from attestra import db
    from attestra.reports import approve_report, generate_report

    # This test is about the watermark, not QA data-consistency gates; the fixture
    # has no endpoint coverage recorded, which would otherwise block approval here.
    monkeypatch.setattr("attestra.reports.qa.assert_qa_allows_approval", lambda result: None)

    with db.session() as s:
        r = generate_report(s, loaded, kind="technical", actor="author@x")
        rid = r.id

    client.headers.pop("Authorization", None)
    assert client.post(
        "/login", data={"username": "lead", "password": "test-pass-lead"}, follow_redirects=False
    ).status_code == 303

    draft_page = client.get(f"/reports/{rid}")
    assert draft_page.status_code == 200
    assert 'class="draft-mark"' in draft_page.text

    with db.session() as s:
        approve_report(s, rid, actor="approver@x")

    signed_page = client.get(f"/reports/{rid}")
    assert signed_page.status_code == 200
    assert 'class="draft-mark"' not in signed_page.text
    assert "Signed by approver@x" in signed_page.text  # sign-off banner still present


# @lat: [[tests#Phase 10 report genuineness#Sealed download drops mark and stays verifiable]]
def test_sealed_download_resealed_without_draft_mark(client, loaded, monkeypatch):
    """The raw sealed-file download (byte for byte, what was hashed and signed) must
    not still carry the DRAFT watermark once signed; re-sealing with a fresh hash at
    sign time must keep the file hash-matching and signature-valid afterward.
    """
    from attestra import db
    from attestra.models import Report
    from attestra.reports import approve_report, generate_report, verify_report

    monkeypatch.setattr("attestra.reports.qa.assert_qa_allows_approval", lambda result: None)

    with db.session() as s:
        r = generate_report(s, loaded, kind="technical", actor="author@x")
        rid, original_sha = r.id, r.sha256

    client.headers.pop("Authorization", None)
    assert client.post(
        "/login", data={"username": "lead", "password": "test-pass-lead"}, follow_redirects=False
    ).status_code == 303

    draft_sealed = client.get(f"/reports/{rid}/sealed")
    assert draft_sealed.status_code == 200
    assert b"DRAFT" in draft_sealed.content

    with db.session() as s:
        signed = approve_report(s, rid, actor="approver@x")
        assert signed.sha256 != original_sha  # re-sealed to a fresh hash

    signed_sealed = client.get(f"/reports/{rid}/sealed")
    assert signed_sealed.status_code == 200
    # The rotated background watermark div is gone, and the "this generation" row's
    # own DRAFT/pending placeholder text has been resolved to the real reviewer/signer.
    assert b'class="draft-mark"' not in signed_sealed.content
    assert b"Pending QA (DRAFT)" not in signed_sealed.content
    assert b"Pending approval (DRAFT)" not in signed_sealed.content
    assert b"Generated (DRAFT)" not in signed_sealed.content

    with db.session() as s:
        r = s.get(Report, rid)
        check = verify_report(s, rid)
    assert check["hash_matches"] is True
    assert check["signature_valid"] is True
    assert check["sha256"] == r.sha256 != original_sha


# @lat: [[tests#Phase 10 report genuineness#Signed report resolves DRAFT placeholder text]]
def test_signed_report_resolves_draft_placeholder_text(client, loaded, monkeypatch):
    """Once signed, the Document control "this generation" row and Sign-off Author/QA
    reviewer rows show the real names instead of "Pending QA (DRAFT)" / "Pending
    approval (DRAFT)" / "Generated (DRAFT)". A prior, still-unsigned report's own
    document-control history row is left untouched by the narrowly-bounded
    substitutions, even though it is baked into this same signed report's HTML.
    """
    from attestra import db
    from attestra.reports import approve_report, generate_report

    monkeypatch.setattr("attestra.reports.qa.assert_qa_allows_approval", lambda result: None)

    with db.session() as s:
        # Left in draft on purpose: generated first, so it is baked into the next
        # report's Document control history as a still-unsigned "other" row.
        other = generate_report(s, loaded, kind="technical", actor="author@x")
        other_version = other.version
        r = generate_report(s, loaded, kind="technical", actor="author@x")
        rid = r.id

    client.headers.pop("Authorization", None)
    assert client.post(
        "/login", data={"username": "lead", "password": "test-pass-lead"}, follow_redirects=False
    ).status_code == 303

    with db.session() as s:
        approve_report(s, rid, actor="approver@x")

    signed_view = client.get(f"/reports/{rid}").text
    assert "Signed (this generation)" in signed_view
    assert ">approver@x<" in signed_view  # Approved cell / sign-off row show the real signer
    assert ">Generated<" in signed_view  # Author row mark no longer says "(DRAFT)"
    assert "Draft (this generation)" not in signed_view
    assert "Generated (DRAFT)" not in signed_view

    # The OTHER, still-draft report's own document-control history row (baked into
    # this signed report's HTML) keeps its honest "still pending" placeholder text,
    # proving the narrowly-bounded substitutions never touch it.
    other_row_start = signed_view.index(f">v{other_version}<")
    other_row_end = signed_view.index("</tr>", other_row_start)
    other_row = signed_view[other_row_start:other_row_end]
    assert "Pending QA (DRAFT)" in other_row
    assert "Pending approval (DRAFT)" in other_row
