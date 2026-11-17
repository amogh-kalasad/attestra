"""Append-only asset snapshots and change events (A-06).

A snapshot is a normalized, value-free picture of what passive sources and finished
scans saw for one asset: DNS records, TLS certificate identity, open ports, detected
technology and security headers. Snapshots are only ever inserted (never updated or
deleted by this module). Comparing the latest two yields change events, each with an
attribution (which scan run / source / actor produced the newer snapshot) and a stable
``dedup_key`` so alerting can send each change once.
"""
# @lat: [[attack-surface-and-platform#Snapshots and change events]]

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

SNAPSHOTS = "asset_snapshots"
CHANGE_EVENTS = "asset_change_events"
CATEGORIES = ("dns", "cert", "port", "tech", "header")


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _sorted_unique(values) -> list[str]:
    return sorted({str(v).strip().lower().rstrip(".") for v in values or () if str(v).strip()})


def normalize_data(data: dict[str, Any] | None) -> dict[str, Any]:
    d = data or {}
    dns = d.get("dns") or {}
    cert = d.get("cert") or {}
    headers = d.get("headers") or {}
    return {
        "dns": {k: _sorted_unique(dns.get(k)) for k in ("a", "aaaa", "cname", "mx", "ns", "txt") if dns.get(k)},
        "cert": {
            k: (str(cert[k]).strip() if k != "sans" else _sorted_unique(cert[k]))
            for k in ("sha256", "issuer", "subject", "not_after", "sans")
            if cert.get(k)
        },
        "ports": sorted({int(p) for p in d.get("ports") or () if str(p).isdigit()}),
        "tech": _sorted_unique(d.get("tech")),
        "headers": {str(k).lower(): str(v).strip() for k, v in sorted(headers.items()) if str(v).strip()},
    }


def snapshot_hash(data: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def build_snapshot(
    *,
    tenant_id: int,
    engagement_id: int,
    asset_key: str,
    data: dict[str, Any],
    source: str,
    actor: str = "system",
    scan_run_id: int | None = None,
    taken_at: str | None = None,
) -> dict[str, Any]:
    norm = normalize_data(data)
    return {
        "tenant_id": int(tenant_id),
        "engagement_id": int(engagement_id),
        "asset_key": str(asset_key).lower(),
        "taken_at": taken_at or _now_iso(),
        "data": norm,
        "hash": snapshot_hash(norm),
        "attribution": {"source": source, "actor": actor, "scan_run_id": scan_run_id},
    }


def _event(category: str, kind: str, item: str, before, after, snap: dict) -> dict[str, Any]:
    key_raw = json.dumps([snap["tenant_id"], snap["asset_key"], category, kind, item, before, after], sort_keys=True, default=str)
    return {
        "tenant_id": snap["tenant_id"],
        "engagement_id": snap["engagement_id"],
        "asset_key": snap["asset_key"],
        "category": category,
        "kind": kind,  # added | removed | changed
        "item": item,
        "before": before,
        "after": after,
        "at": snap["taken_at"],
        "attribution": dict(snap.get("attribution") or {}),
        "dedup_key": hashlib.sha256(key_raw.encode()).hexdigest()[:40],
    }


def diff_snapshots(prev: dict | None, cur: dict) -> list[dict[str, Any]]:
    """Change events from ``prev`` → ``cur`` (empty for the first snapshot of an asset)."""
    if not prev:
        return []
    a, b = prev.get("data") or {}, cur.get("data") or {}
    out: list[dict[str, Any]] = []
    da, db_ = a.get("dns") or {}, b.get("dns") or {}
    for rtype in sorted(set(da) | set(db_)):
        before, after = set(da.get(rtype) or []), set(db_.get(rtype) or [])
        for v in sorted(after - before):
            out.append(_event("dns", "added", f"{rtype}:{v}", None, v, cur))
        for v in sorted(before - after):
            out.append(_event("dns", "removed", f"{rtype}:{v}", v, None, cur))
    ca, cb = a.get("cert") or {}, b.get("cert") or {}
    for k in sorted(set(ca) | set(cb)):
        if ca.get(k) != cb.get(k):
            kind = "added" if k not in ca else ("removed" if k not in cb else "changed")
            out.append(_event("cert", kind, k, ca.get(k), cb.get(k), cur))
    pa, pb = set(a.get("ports") or []), set(b.get("ports") or [])
    for p in sorted(pb - pa):
        out.append(_event("port", "added", str(p), None, p, cur))
    for p in sorted(pa - pb):
        out.append(_event("port", "removed", str(p), p, None, cur))
    ta, tb = set(a.get("tech") or []), set(b.get("tech") or [])
    for t in sorted(tb - ta):
        out.append(_event("tech", "added", t, None, t, cur))
    for t in sorted(ta - tb):
        out.append(_event("tech", "removed", t, t, None, cur))
    ha, hb = a.get("headers") or {}, b.get("headers") or {}
    for h in sorted(set(ha) | set(hb)):
        if ha.get(h) != hb.get(h):
            kind = "added" if h not in ha else ("removed" if h not in hb else "changed")
            out.append(_event("header", kind, h, ha.get(h), hb.get(h), cur))
    return out


def latest_snapshot(db, *, tenant_id: int, asset_key: str) -> dict | None:
    rows = list(
        db[SNAPSHOTS].find({"tenant_id": int(tenant_id), "asset_key": str(asset_key).lower()}).sort("seq", -1).limit(1)
    )
    return rows[0] if rows else None


def append_snapshot(db, snap: dict) -> dict[str, Any]:
    """Insert ``snap`` (append-only) and its change events against the previous one.

    Returns ``{"snapshot_id", "unchanged", "events"}``. An identical consecutive snapshot
    is not stored again (``unchanged=True``), which keeps the history compact without ever
    rewriting an earlier row.
    """
    prev = latest_snapshot(db, tenant_id=snap["tenant_id"], asset_key=snap["asset_key"])
    if prev is not None and prev.get("hash") == snap.get("hash"):
        return {"snapshot_id": prev.get("_id"), "unchanged": True, "events": []}
    seq = int(prev.get("seq", 0)) + 1 if prev else 1
    doc = dict(snap)
    doc["seq"] = seq
    doc["_id"] = f"snap_{snap['tenant_id']}_{hashlib.sha256(snap['asset_key'].encode()).hexdigest()[:16]}_{seq}"
    doc["previous_id"] = prev.get("_id") if prev else None
    db[SNAPSHOTS].insert_one(doc)
    events = diff_snapshots(prev, doc)
    for ev in events:
        ev = dict(ev)
        ev["snapshot_id"] = doc["_id"]
        ev["previous_snapshot_id"] = doc["previous_id"]
        ev["_id"] = f"ace_{ev['dedup_key']}"
        if db[CHANGE_EVENTS].find_one({"_id": ev["_id"]}) is None:
            db[CHANGE_EVENTS].insert_one(ev)
    return {"snapshot_id": doc["_id"], "unchanged": False, "events": events}
