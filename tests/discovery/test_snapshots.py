"""A-06: append-only asset snapshots, diff correctness and attribution."""
# @lat: [[attack-surface-and-platform#Snapshots and change events]]

from __future__ import annotations

import copy

from attestra.discovery import snapshots as S
from tests.discovery._fakedb import FakeDB

BASE = {
    "dns": {"a": ["192.0.2.1"], "cname": ["edge.cdn.net."]},
    "cert": {"sha256": "aa", "issuer": "R3", "not_after": "2027-01-01", "sans": ["www.example.com"]},
    "ports": [443, 80],
    "tech": ["nginx"],
    "headers": {"Strict-Transport-Security": "max-age=31536000"},
}


def snap(data, *, run=None, actor="worker", taken="2026-11-17T00:00:00+00:00"):
    return S.build_snapshot(
        tenant_id=1, engagement_id=7, asset_key="WWW.example.com", data=data, source="scan", actor=actor,
        scan_run_id=run, taken_at=taken,
    )


def test_normalization_is_order_insensitive():
    a = snap(BASE)
    shuffled = copy.deepcopy(BASE)
    shuffled["ports"] = [80, 443]
    shuffled["dns"]["a"] = ["192.0.2.1"]
    shuffled["dns"]["cname"] = ["EDGE.cdn.net"]
    assert snap(shuffled)["hash"] == a["hash"]
    assert a["asset_key"] == "www.example.com"


def test_first_snapshot_has_no_events_and_append_only():
    db = FakeDB()
    r1 = S.append_snapshot(db, snap(BASE, run=1))
    assert r1["events"] == [] and not r1["unchanged"]
    first = copy.deepcopy(db[S.SNAPSHOTS].find_one({"_id": r1["snapshot_id"]}))
    changed = copy.deepcopy(BASE)
    changed["ports"] = [443, 8443]
    r2 = S.append_snapshot(db, snap(changed, run=2, taken="2026-11-18T00:00:00+00:00"))
    assert len(db[S.SNAPSHOTS].docs) == 2
    assert db[S.SNAPSHOTS].find_one({"_id": r1["snapshot_id"]}) == first  # earlier row untouched
    assert set(db[S.SNAPSHOTS].ops) == {"insert"}  # never update/replace/delete
    second = db[S.SNAPSHOTS].find_one({"_id": r2["snapshot_id"]})
    assert second["seq"] == 2 and second["previous_id"] == r1["snapshot_id"]


def test_identical_snapshot_not_stored_again():
    db = FakeDB()
    r1 = S.append_snapshot(db, snap(BASE, run=1))
    r2 = S.append_snapshot(db, snap(BASE, run=2))
    assert r2["unchanged"] and r2["snapshot_id"] == r1["snapshot_id"]
    assert len(db[S.SNAPSHOTS].docs) == 1


def test_diff_correctness_all_categories():
    new = copy.deepcopy(BASE)
    new["dns"] = {"a": ["192.0.2.9"], "cname": ["edge.cdn.net"], "ns": ["ns1.example.net"]}
    new["cert"] = {"sha256": "bb", "issuer": "R3", "not_after": "2027-06-01", "sans": ["www.example.com"]}
    new["ports"] = [443, 8080]
    new["tech"] = ["nginx", "php"]
    new["headers"] = {"Content-Security-Policy": "default-src 'self'"}
    ev = S.diff_snapshots(snap(BASE, run=1), snap(new, run=2, actor="lead"))
    got = {(e["category"], e["kind"], e["item"]) for e in ev}
    assert got == {
        ("dns", "added", "a:192.0.2.9"),
        ("dns", "removed", "a:192.0.2.1"),
        ("dns", "added", "ns:ns1.example.net"),
        ("cert", "changed", "sha256"),
        ("cert", "changed", "not_after"),
        ("port", "added", "8080"),
        ("port", "removed", "80"),
        ("tech", "added", "php"),
        ("header", "added", "content-security-policy"),
        ("header", "removed", "strict-transport-security"),
    }
    for e in ev:
        assert e["attribution"] == {"source": "scan", "actor": "lead", "scan_run_id": 2}
        assert len(e["dedup_key"]) == 40


def test_events_stored_once_with_snapshot_links():
    db = FakeDB()
    S.append_snapshot(db, snap(BASE, run=1))
    new = copy.deepcopy(BASE)
    new["tech"] = ["nginx", "wordpress"]
    r = S.append_snapshot(db, snap(new, run=2))
    assert len(r["events"]) == 1
    stored = list(db[S.CHANGE_EVENTS].find({}))
    assert len(stored) == 1 and stored[0]["snapshot_id"] == r["snapshot_id"]
    assert stored[0]["tenant_id"] == 1 and stored[0]["engagement_id"] == 7


def test_snapshots_are_tenant_separated():
    db = FakeDB()
    S.append_snapshot(db, snap(BASE, run=1))
    other = S.build_snapshot(tenant_id=2, engagement_id=8, asset_key="www.example.com", data={"ports": [22]}, source="scan")
    r = S.append_snapshot(db, other)
    assert r["events"] == []  # no diff against tenant 1's snapshot
    assert S.latest_snapshot(db, tenant_id=2, asset_key="www.example.com")["data"]["ports"] == [22]
