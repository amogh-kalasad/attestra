"""H-04 merge/split audit history (pure; fingerprints never change)."""
# @lat: [[intel-and-reporting#Merge and split history]]

from __future__ import annotations

from types import SimpleNamespace

from attestra import crossmerge


def test_history_event_kinds():
    merge = crossmerge.history_event(5, None, (2, "cve:CVE-2024-1"))
    split = crossmerge.history_event(5, (2, "cve:CVE-2024-1"), None)
    relink = crossmerge.history_event(5, (2, "cve:CVE-2024-1"), (3, "map:x@app"))
    assert (merge["kind"], split["kind"], relink["kind"]) == ("merge", "split", "relink")
    assert relink["from_primary"] == 2 and relink["to_primary"] == 3
    assert all(e["fingerprint_changed"] is False for e in (merge, split, relink))


def test_merge_history_reads_audit(monkeypatch):
    from attestra import audit

    events = {
        "finding.cross_merge": [SimpleNamespace(ts="2026-11-17T01:00:00", actor="system", entity_id=5,
                                                details={"primary": 2, "rationale": "cve:X",
                                                         "history": crossmerge.history_event(5, None, (2, "cve:X"))})],
        "finding.cross_unmerge": [SimpleNamespace(ts="2026-11-17T02:00:00", actor="tester", entity_id=5,
                                                  details={"previous_primary": 2}),
                                  SimpleNamespace(ts="2026-11-17T03:00:00", actor="x", entity_id=99,
                                                  details={"previous_primary": 98})],
    }
    monkeypatch.setattr(audit, "find_events", lambda s, action=None, **k: events.get(action, []))
    hist = crossmerge.merge_history(None, 5)
    assert [h["kind"] for h in hist] == ["merge", "split"]
    assert crossmerge.merge_history(None, 2)[0]["member_id"] == 5  # visible from the primary too
