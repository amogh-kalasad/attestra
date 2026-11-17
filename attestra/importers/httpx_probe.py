"""httpx (ProjectDiscovery) probe importer (``-json``): HTTP metadata → observations (A-04).

Keeps status code, title, detected technology, CDN and web server per host. No findings.
"""
# @lat: [[attack-surface-and-platform#Discovery adapters]]

from __future__ import annotations

from urllib.parse import urlsplit

from attestra.importers.base import NormalizedFinding
from attestra.importers.subfinder import DiscoveryParseError, json_rows


def _host(row: dict) -> str:
    for k in ("input", "url"):
        v = str(row.get(k) or "").strip()
        if not v:
            continue
        h = urlsplit(v).hostname if "://" in v else v.split("/")[0].split(":")[0]
        if h:
            return h.lower().rstrip(".")
    return ""


def parse_observations(raw: bytes) -> list:
    from attestra.discovery.candidates import Observation

    best: dict[str, dict] = {}
    for row in json_rows(raw, "httpx"):
        host = _host(row)
        if not host:
            raise DiscoveryParseError("httpx: row without input/url")
        status = row.get("status_code", row.get("status-code"))
        try:
            status = int(status) if status not in (None, "") else None
        except (TypeError, ValueError):
            status = None
        tech = row.get("tech") or row.get("technologies") or []
        detail = {
            "status_code": status,
            "title": str(row.get("title") or "")[:200],
            "tech": sorted({str(t)[:60] for t in tech})[:30] if isinstance(tech, list) else [],
            "webserver": str(row.get("webserver") or "")[:100],
            "cdn": str(row.get("cdn_name") or ("yes" if row.get("cdn") is True else ""))[:60],
            "scheme": str(row.get("scheme") or (urlsplit(str(row.get("url") or "")).scheme))[:10],
        }
        prev = best.get(host)
        # Prefer the https answer when both schemes were probed (deterministic).
        if prev is None or (detail["scheme"] == "https" and prev["detail"]["scheme"] != "https"):
            best[host] = {"detail": detail, "seen_at": str(row.get("timestamp") or "")[:40]}
    return [
        Observation(name=h, source="httpx", seen_at=best[h]["seen_at"], detail={k: v for k, v in best[h]["detail"].items() if v not in ("", None, [])})
        for h in sorted(best)
    ]


def parse(raw: bytes) -> list[NormalizedFinding]:
    parse_observations(raw)
    return []
