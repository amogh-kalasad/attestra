"""Auto draft technical reports after scan complete and CA save."""

from __future__ import annotations


# @lat: [[tests#Certification Authority#CA save refreshes draft reports]]
# @lat: [[tests#Phase 4 report tests#Scan complete saves draft report]]
def test_ensure_draft_after_scan_complete(loaded):
    from attestra import db
    from attestra.persistence.mongo import report_reads
    from attestra.reports.auto_draft import ensure_draft_technical_report

    with db.session() as s:
        assert report_reads.reports(loaded, kind="technical", limit=1) == []
        row = ensure_draft_technical_report(s, loaded, actor="scanner", user_id=None)
        assert row is not None
        assert row.status == "draft"
        assert row.kind == "technical"
        # Second call refreshes draft (new version) rather than leaving stale HTML.
        again = ensure_draft_technical_report(s, loaded, actor="scanner", user_id=None)
        assert again is not None
        assert again.version >= row.version
        assert again.status == "draft"


def test_ensure_draft_skips_submitted(loaded):
    from attestra import db
    from attestra.reports import generate_report, submit_report
    from attestra.reports.auto_draft import ensure_draft_technical_report

    with db.session() as s:
        r = generate_report(s, loaded, kind="technical", actor="tester")
        submit_report(s, r.id, actor="tester")
        skipped = ensure_draft_technical_report(s, loaded, actor="scanner")
        assert skipped is None
