"""Scan-vendor (ASV) external scan results importer (PCI DSS 11.3.2).

Vendors export in their own formats, so Attestra accepts one generic layout as
JSON or CSV. Testers convert the vendor export to it before import.

JSON::

    {"vendor": "Example ASV", "scan_date": "2026-09-30", "passing": true,
     "components": [{"host": "203.0.113.10", "port": 443, "title": "...",
                     "severity": "medium", "cvss": 5.3, "cve": "CVE-...", "status": "fail"}]}

CSV columns: vendor, scan_date, host, port, title, severity, cvss, cve, status
(one row per component result; vendor and scan_date from the first row).

Per the ASV program guide a component fails at CVSS >= 4.0 unless the vendor
marks it explicitly. The scan passes only if no component fails, unless the
file states an overall ``passing`` value.
"""
from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from datetime import date

from attestra.importers.base import norm_severity

FAIL_CVSS = 4.0


@dataclass
class AsvItem:
    host: str
    port: int | None
    title: str
    severity: str
    cvss_score: float | None
    cve: str
    passing: bool
    note: str = ""


@dataclass
class AsvResult:
    vendor: str
    scan_date: date
    passing: bool
    items: list[AsvItem] = field(default_factory=list)

    @property
    def failing_count(self) -> int:
        return sum(1 for i in self.items if not i.passing)


def _float(v) -> float | None:
    if v in (None, ""):
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _int(v) -> int | None:
    if v in (None, ""):
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _bool(v) -> bool | None:
    if v is None or v == "":
        return None
    if isinstance(v, bool):
        return v
    t = str(v).strip().lower()
    if t in ("pass", "passed", "passing", "true", "yes", "1", "compliant"):
        return True
    if t in ("fail", "failed", "failing", "false", "no", "0", "non-compliant", "noncompliant"):
        return False
    return None


def _item(row: dict) -> AsvItem:
    cvss = _float(row.get("cvss", row.get("cvss_score")))
    sev = norm_severity(row.get("severity"))
    explicit = _bool(row.get("status", row.get("passing")))
    if explicit is None:
        explicit = not ((cvss is not None and cvss >= FAIL_CVSS) or (cvss is None and sev in ("critical", "high", "medium")))
    return AsvItem(
        host=str(row.get("host", "") or "").strip(),
        port=_int(row.get("port")),
        title=str(row.get("title", "") or "").strip()[:500],
        severity=sev,
        cvss_score=cvss,
        cve=str(row.get("cve", "") or "").strip()[:50],
        passing=explicit,
        note=str(row.get("note", "") or "").strip(),
    )


def _date(v) -> date:
    try:
        return date.fromisoformat(str(v).strip()[:10])
    except (TypeError, ValueError):
        raise ValueError(f"ASV results need scan_date as YYYY-MM-DD, got {v!r}") from None


def parse(raw: bytes) -> AsvResult:
    text = raw.decode("utf-8-sig").strip()
    if not text:
        raise ValueError("empty ASV results file")
    if text[0] in "{[":
        doc = json.loads(text)
        if isinstance(doc, list):
            doc = {"components": doc}
        rows = doc.get("components") or doc.get("results") or []
        vendor = str(doc.get("vendor", "") or "").strip()
        scan_date = _date(doc.get("scan_date"))
        overall = _bool(doc.get("passing", doc.get("scan_status")))
    else:
        rows = list(csv.DictReader(io.StringIO(text)))
        if not rows:
            raise ValueError("ASV CSV has no result rows")
        vendor = str(rows[0].get("vendor", "") or "").strip()
        scan_date = _date(rows[0].get("scan_date"))
        overall = None
    if not vendor:
        raise ValueError("ASV results need a vendor name")
    items = [_item(r) for r in rows if isinstance(r, dict)]
    passing = overall if overall is not None else all(i.passing for i in items)
    return AsvResult(vendor=vendor, scan_date=scan_date, passing=passing, items=items)
