"""DNS / certificate / port / technology change monitoring and alert dedup (I-04).

Input is the change events produced by :func:`attestra.discovery.snapshots.append_snapshot`
(or header diffs via :func:`attestra.alerts.headers.header_changes_as_events`). This module:

* filters to *significant* changes (DNS address/CNAME/NS/MX moves, certificate identity or
  expiry changes, new or closed ports, new or removed technology, security headers);
* deduplicates by ``dedup_key`` within a batch and across runs (send-once store);
* renders a one-line, value-light description per change;
* hands the batch to :func:`attestra.alerts.service.notify_asset_changes`.

No network access happens here; everything works from stored snapshots.
"""
# @lat: [[attack-surface-and-platform#Asset change alerts]]

from __future__ import annotations

from typing import Any

SIGNIFICANT_DNS = frozenset({"a", "aaaa", "cname", "ns", "mx"})
SIGNIFICANT_CERT = frozenset({"sha256", "issuer", "not_after", "subject", "sans"})


def is_significant(event: dict[str, Any]) -> bool:
    cat = event.get("category")
    item = str(event.get("item") or "")
    if cat == "dns":
        return item.split(":", 1)[0] in SIGNIFICANT_DNS
    if cat == "cert":
        return item in SIGNIFICANT_CERT
    return cat in ("port", "tech", "header")


def dedupe(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for e in events or []:
        key = str(e.get("dedup_key") or "")
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


def alert_entity_id(event: dict[str, Any]) -> int:
    """Integer id for the send-once store (48 bits of the dedup key)."""
    return int(str(event.get("dedup_key") or "0").ljust(12, "0")[:12], 16)


_LABEL = {"dns": "DNS", "cert": "Certificate", "port": "Port", "tech": "Technology", "header": "Header"}


def describe_event(e: dict[str, Any]) -> str:
    cat = _LABEL.get(str(e.get("category")), str(e.get("category")))
    kind = str(e.get("kind") or "")
    item = str(e.get("item") or "")
    before, after = e.get("before"), e.get("after")
    if kind == "added":
        return f"{cat} added: {item}" + ("" if str(after) in item else f" = {after}")
    if kind == "removed":
        return f"{cat} removed: {item}"
    return f"{cat} changed: {item}: {before} → {after}"


def select_alertable(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return dedupe([e for e in events or [] if is_significant(e)])


def monitor_and_alert(
    s,
    *,
    tenant_id: int,
    engagement_id: int,
    engagement_name: str,
    target: str,
    events: list[dict[str, Any]],
    actor: str = "system",
    link: str = "",
) -> dict[str, Any]:
    """Filter + dedup a batch and send it (never raises; returns a summary)."""
    batch = select_alertable(events)
    if not batch:
        return {"sent": False, "count": 0, "duplicates": 0, "considered": len(events or [])}
    try:
        from attestra.alerts import service

        res = service.notify_asset_changes(
            s,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            engagement_name=engagement_name,
            target=target,
            events=batch,
            actor=actor,
            link=link,
        )
    except Exception as exc:  # noqa: BLE001 - alerting must never break a scan pipeline
        return {"sent": False, "count": 0, "duplicates": 0, "considered": len(events or []), "error": type(exc).__name__}
    res["considered"] = len(events or [])
    return res
