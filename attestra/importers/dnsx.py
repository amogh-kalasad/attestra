"""dnsx importer (``-json``): resolution records → discovery observations (A-03).

Returns no findings (:func:`parse` only validates); :func:`parse_observations` keeps the
A/AAAA/CNAME records and the DNS status so candidates get a resolution state.
"""
# @lat: [[attack-surface-and-platform#Discovery adapters]]

from __future__ import annotations

from attestra.importers.base import NormalizedFinding
from attestra.importers.subfinder import DiscoveryParseError, json_rows

_STATUS = {"NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED", "TIMEOUT"}


def _list(v) -> list[str]:
    if isinstance(v, str):
        v = [v]
    return sorted({str(x).strip().lower().rstrip(".") for x in v or [] if str(x).strip()})[:50]


def parse_observations(raw: bytes) -> list:
    from attestra.discovery.candidates import Observation

    merged: dict[str, dict] = {}
    for row in json_rows(raw, "dnsx"):
        host = str(row.get("host") or "").strip().lower().rstrip(".")
        if not host:
            raise DiscoveryParseError("dnsx: row without host")
        status = str(row.get("status_code") or row.get("rcode") or "").upper()
        cur = merged.setdefault(host, {"a": [], "aaaa": [], "cname": [], "status": "", "seen_at": ""})
        for k in ("a", "aaaa", "cname"):
            cur[k] = sorted(set(cur[k]) | set(_list(row.get(k))))
        if status in _STATUS and (not cur["status"] or status == "NOERROR"):
            cur["status"] = status
        elif not cur["status"] and (cur["a"] or cur["aaaa"] or cur["cname"]):
            cur["status"] = "NOERROR"
        cur["seen_at"] = max(cur["seen_at"], str(row.get("timestamp") or "")[:40])
    out = []
    for host in sorted(merged):
        d = merged[host]
        out.append(
            Observation(
                name=host,
                source="dnsx",
                seen_at=d.pop("seen_at"),
                detail={k: v for k, v in d.items() if v},
            )
        )
    return out


def parse(raw: bytes) -> list[NormalizedFinding]:
    parse_observations(raw)
    return []
