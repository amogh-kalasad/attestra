"""NVD CVE API 2.0 ingestion (G-02): parse, validate and index CVE records offline.

Network access is never made at import time or by the parsers. :func:`refresh` takes an
injectable ``fetch`` callable so the maintenance job (registered by INT/WP4 behind
``ATTESTRA_INTEL_AUTO_REFRESH``) owns when the NVD is contacted. CVSS 4.0 vectors are
re-scored locally with :mod:`attestra.intel.cvss4`; a disagreement with NVD's stored base
score is recorded, not hidden.
"""
# @lat: [[intel-and-reporting#NVD and OSV]]

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from urllib.parse import urlencode

from attestra.intel import cvss4

SCHEMA = "nvd-cve-api-2.0"
API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_CWE_RE = re.compile(r"^CWE-(\d+)$")


class NvdError(ValueError):
    pass


@dataclass
class NvdRecord:
    cve: str
    published: str = ""
    last_modified: str = ""
    status: str = ""
    cwes: list[int] = field(default_factory=list)
    cvss40_vector: str = ""
    cvss40_score: float | None = None
    cvss40_local_score: float | None = None
    cvss40_mismatch: bool = False
    cvss31_vector: str = ""
    cvss31_score: float | None = None
    description: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def _primary(metrics: list) -> dict:
    if not isinstance(metrics, list) or not metrics:
        return {}
    for m in metrics:
        if isinstance(m, dict) and m.get("type") == "Primary":
            return m
    return metrics[0] if isinstance(metrics[0], dict) else {}


def parse_record(item: dict) -> NvdRecord:
    cve = (item or {}).get("cve") if isinstance(item, dict) else None
    if not isinstance(cve, dict):
        raise NvdError("NVD item has no 'cve' object")
    cid = str(cve.get("id") or "").strip().upper()
    if not _CVE_RE.match(cid):
        raise NvdError(f"invalid CVE id {cid!r}")
    rec = NvdRecord(
        cve=cid,
        published=str(cve.get("published") or ""),
        last_modified=str(cve.get("lastModified") or ""),
        status=str(cve.get("vulnStatus") or ""),
    )
    for d in cve.get("descriptions") or []:
        if isinstance(d, dict) and d.get("lang") == "en":
            rec.description = str(d.get("value") or "")[:2000]
            break
    cwes: set[int] = set()
    for w in cve.get("weaknesses") or []:
        for d in (w or {}).get("description") or []:
            m = _CWE_RE.match(str((d or {}).get("value") or ""))
            if m:
                cwes.add(int(m.group(1)))
    rec.cwes = sorted(cwes)
    metrics = cve.get("metrics") or {}
    m40 = (_primary(metrics.get("cvssMetricV40") or []).get("cvssData")) or {}
    if m40.get("vectorString"):
        rec.cvss40_vector = str(m40["vectorString"])
        rec.cvss40_score = float(m40["baseScore"]) if m40.get("baseScore") is not None else None
        local = cvss4.try_score(rec.cvss40_vector)
        if local is not None:
            rec.cvss40_local_score = local.score
            rec.cvss40_mismatch = rec.cvss40_score is not None and abs(local.score - rec.cvss40_score) > 0.05
    m31 = (_primary(metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []).get("cvssData")) or {}
    if m31.get("vectorString"):
        rec.cvss31_vector = str(m31["vectorString"])
        rec.cvss31_score = float(m31["baseScore"]) if m31.get("baseScore") is not None else None
    return rec


def parse_response(raw: bytes) -> tuple[dict[str, NvdRecord], dict]:
    """Validate one NVD API 2.0 page; return ``({cve: record}, meta)``.

    Raises :class:`NvdError` for a malformed page. Individual malformed items are
    skipped and counted in ``meta['skipped']``; a page that is mostly malformed fails.
    """
    try:
        doc = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise NvdError(f"NVD response is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("vulnerabilities"), list):
        raise NvdError("NVD response has no 'vulnerabilities' list")
    if doc.get("format") not in (None, "NVD_CVE"):
        raise NvdError(f"unexpected NVD format {doc.get('format')!r}")
    out: dict[str, NvdRecord] = {}
    skipped = 0
    for item in doc["vulnerabilities"]:
        try:
            rec = parse_record(item)
        except (NvdError, TypeError, ValueError):
            skipped += 1
            continue
        out[rec.cve] = rec
    total = len(doc["vulnerabilities"])
    if total and len(out) / total < 0.95:
        raise NvdError(f"NVD page has too many malformed items ({skipped}/{total})")
    meta = {
        "schema": SCHEMA,
        "version": str(doc.get("version") or ""),
        "timestamp": str(doc.get("timestamp") or ""),
        "total_results": int(doc.get("totalResults") or total),
        "start_index": int(doc.get("startIndex") or 0),
        "results_per_page": int(doc.get("resultsPerPage") or total),
        "records": len(out),
        "skipped": skipped,
    }
    return out, meta


def build_query_url(*, last_mod_start: str = "", last_mod_end: str = "", start_index: int = 0,
                    results_per_page: int = 2000, cve_id: str = "") -> str:
    """URL for an incremental NVD query (no API key is placed in the URL)."""
    params: dict = {"startIndex": int(start_index), "resultsPerPage": int(results_per_page)}
    if cve_id:
        params = {"cveId": cve_id}
    if last_mod_start and last_mod_end:
        params["lastModStartDate"] = last_mod_start
        params["lastModEndDate"] = last_mod_end
    return f"{API_URL}?{urlencode(params)}"


def refresh(fetch, *, last_mod_start: str = "", last_mod_end: str = "", max_pages: int = 50) -> tuple[dict[str, NvdRecord], dict]:
    """Page through an NVD window using ``fetch(url) -> bytes`` (injected; may add API key header).

    Pages are validated individually; any invalid page aborts the refresh so a partial
    window is never stored as if complete.
    """
    records: dict[str, NvdRecord] = {}
    start = 0
    pages = 0
    total = 0
    while pages < max_pages:
        raw = fetch(build_query_url(last_mod_start=last_mod_start, last_mod_end=last_mod_end, start_index=start))
        page, meta = parse_response(raw)
        records.update(page)
        pages += 1
        total = meta["total_results"]
        start = meta["start_index"] + max(meta["results_per_page"], 1)
        if start >= total or not page:
            break
    complete = start >= total
    return records, {"schema": SCHEMA, "pages": pages, "records": len(records), "total_results": total,
                     "complete": complete, "window": [last_mod_start, last_mod_end]}


def dumps(records: dict[str, NvdRecord]) -> bytes:
    """Serialise records for the feed store (sorted, deterministic)."""
    return json.dumps({"schema": SCHEMA, "records": [records[k].as_dict() for k in sorted(records)]},
                      sort_keys=True).encode("utf-8")


def loads(raw: bytes) -> dict[str, dict]:
    doc = json.loads(raw)
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA or not isinstance(doc.get("records"), list):
        raise NvdError("stored NVD snapshot has an unexpected schema")
    return {r["cve"]: r for r in doc["records"] if isinstance(r, dict) and r.get("cve")}
