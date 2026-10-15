"""Auto-capture request/response pairs from ZAP and Nuclei output when present."""

from __future__ import annotations

import json
from collections.abc import Iterator

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra.models import Finding
from attestra.proof.pair import HttpPair, pair_from_raw
from attestra.proof.store import attach_http_pair, has_http_pair

TOOLS = ("zap", "nuclei")


def _nuclei(data: bytes) -> Iterator[HttpPair]:
    for line in data.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        req, resp = row.get("request"), row.get("response")
        if not req or not resp:
            continue
        url = row.get("matched-at") or row.get("url") or ""
        extracted = row.get("extracted-results") or []
        match = extracted[0] if extracted and isinstance(extracted[0], str) else ""
        yield pair_from_raw(req, resp, url=url, match=match, source="nuclei")


def _zap(data: bytes) -> Iterator[HttpPair]:
    try:
        doc = json.loads(data.decode("utf-8", "replace"))
    except ValueError:
        return
    sites = doc.get("site") or []
    if isinstance(sites, dict):
        sites = [sites]
    for site in sites:
        for alert in site.get("alerts") or []:
            for inst in alert.get("instances") or []:
                req_h = inst.get("request-header") or inst.get("requestHeader") or ""
                resp_h = inst.get("response-header") or inst.get("responseHeader") or ""
                if not req_h or not resp_h:
                    continue
                req = req_h.rstrip("\r\n") + "\r\n\r\n" + (inst.get("request-body") or inst.get("requestBody") or "")
                resp = resp_h.rstrip("\r\n") + "\r\n\r\n" + (inst.get("response-body") or inst.get("responseBody") or "")
                yield pair_from_raw(req, resp, url=inst.get("uri") or "", match=inst.get("evidence") or "", source="zap")


def extract_pairs(tool: str, data: bytes) -> list[HttpPair]:
    if tool == "nuclei":
        return list(_nuclei(data))
    if tool == "zap":
        return list(_zap(data))
    return []


def _base(url: str) -> str:
    return url.split("?", 1)[0].split("#", 1)[0].rstrip("/").lower()


def capture_from_import(s: Session, engagement_id: int, tool: str, data: bytes, *, actor: str) -> int:
    """Attach one redacted pair per matching finding that has none yet. Returns count attached."""
    if tool not in TOOLS:
        return 0
    pairs = extract_pairs(tool, data)
    if not pairs:
        return 0
    findings = [f for f in s.scalars(select(Finding).where(Finding.engagement_id == engagement_id)) if tool in (f.tools or [])]
    attached = 0
    done: set[int] = set()
    for pair in pairs:
        key = _base(pair.url)
        for f in findings:
            if f.id in done or not key or _base(f.location.split(" [param:", 1)[0]) != key:
                continue
            if has_http_pair(s, f.id):
                done.add(f.id)
                continue
            attach_http_pair(s, f.id, pair, actor=actor, note=f"auto-captured from {tool}")
            done.add(f.id)
            attached += 1
            break
    return attached
