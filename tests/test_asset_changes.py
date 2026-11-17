"""I-04: asset-change alert selection, dedup and send-once (mail and store faked)."""
# @lat: [[attack-surface-and-platform#Asset change alerts]]

from __future__ import annotations

import copy

import pytest

from attestra.alerts import asset_changes as AC
from attestra.alerts import headers as hdr
from attestra.alerts import service
from attestra.discovery import snapshots as S

OLD = {"dns": {"a": ["192.0.2.1"], "txt": ["v=spf1 -all"]}, "ports": [443], "tech": ["nginx"], "headers": {"x-frame-options": "DENY"}}


def events():
    new = copy.deepcopy(OLD)
    new["dns"] = {"a": ["192.0.2.2"], "txt": ["v=spf1 ~all"]}
    new["ports"] = [443, 22]
    new["headers"] = {}
    a = S.build_snapshot(tenant_id=1, engagement_id=7, asset_key="www.example.com", data=OLD, source="scan")
    b = S.build_snapshot(tenant_id=1, engagement_id=7, asset_key="www.example.com", data=new, source="scan")
    return S.diff_snapshots(a, b)


def test_significance_filter():
    ev = events()
    keep = AC.select_alertable(ev)
    items = {(e["category"], e["item"]) for e in keep}
    assert ("port", "22") in items and ("header", "x-frame-options") in items
    assert ("dns", "a:192.0.2.2") in items
    assert not any(e["item"].startswith("txt:") for e in keep)


def test_dedupe_and_entity_id():
    ev = events()
    doubled = ev + copy.deepcopy(ev)
    assert len(AC.dedupe(doubled)) == len(ev)
    ids = {AC.alert_entity_id(e) for e in ev}
    assert len(ids) == len(ev) and all(0 <= i < 2**48 for i in ids)


def test_describe_event():
    ev = {e["item"]: e for e in events()}
    assert AC.describe_event(ev["22"]) == "Port added: 22"
    assert AC.describe_event(ev["x-frame-options"]).startswith("Header removed")


def test_header_change_keys_stable():
    k1 = hdr.change_dedup_key("www.example.com", {"header": "CSP", "kind": "removed"})
    k2 = hdr.change_dedup_key("www.example.com", {"header": "CSP", "kind": "removed"})
    assert k1 == k2 and len(k1) == 40


@pytest.fixture
def fake_mail(monkeypatch):
    sent_store: set = set()
    mails: list[dict] = []
    monkeypatch.setattr(service, "_already_sent", lambda s, ev, et, eid: (ev, et, eid) in sent_store)
    monkeypatch.setattr(service, "_mark_sent", lambda s, tid, ev, et, eid: sent_store.add((ev, et, eid)))

    def fake_send(s, **kw):
        mails.append(kw)
        return True

    monkeypatch.setattr(service, "_send", fake_send)
    return mails


def test_send_once(fake_mail):
    ev = events()
    r1 = AC.monitor_and_alert(None, tenant_id=1, engagement_id=7, engagement_name="Acme <Prod>", target="www.example.com", events=ev)
    assert r1["sent"] is True and r1["count"] == len(AC.select_alertable(ev))
    assert "<Prod>" not in fake_mail[0]["html"] and "&lt;Prod&gt;" in fake_mail[0]["html"]
    r2 = AC.monitor_and_alert(None, tenant_id=1, engagement_id=7, engagement_name="Acme", target="www.example.com", events=ev)
    assert r2["sent"] is False and r2["duplicates"] == r1["count"]
    assert len(fake_mail) == 1


def test_nothing_significant_no_mail(fake_mail):
    only_txt = [e for e in events() if e["item"].startswith("txt:")]
    r = AC.monitor_and_alert(None, tenant_id=1, engagement_id=7, engagement_name="A", target="t", events=only_txt)
    assert r["sent"] is False and r["count"] == 0 and fake_mail == []


def test_monitor_never_raises(monkeypatch):
    monkeypatch.setattr(service, "notify_asset_changes", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("smtp")))
    r = AC.monitor_and_alert(None, tenant_id=1, engagement_id=7, engagement_name="A", target="t", events=events())
    assert r["sent"] is False and r["error"] == "RuntimeError"
