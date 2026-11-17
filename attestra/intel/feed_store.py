"""Hardened KEV / EPSS feed store: validate before write, atomic replace, keep last good.

Contract (G-01):

* A download is parsed and validated **before** anything touches disk.
* Valid content is written to a temp file in the same directory, fsynced, then
  ``os.replace``-d over the live file. The previous good copy is kept as ``<file>.prev``.
* Invalid content is never written; ``feed_state.json`` records the failure and the
  live file (last good) stays intact, so a feed failure never erases enrichment.
* Re-storing identical bytes is idempotent (no rewrite, only ``checked_at`` moves).
* ``feed_state.json`` records source, etag/last-modified, fetched_at, sha256, schema,
  record count, status and the last error per feed.
"""
# @lat: [[intel-and-reporting#Feed store and freshness]]

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from attestra.intel.freshness import freshness_report

STORE_VERSION = "fs1"
SCHEMAS = {"kev": "cisa-kev-json-v1", "epss": "first-epss-csv-v1"}
FILENAMES = {"kev": "kev.json", "epss": "epss.csv"}
STATE_FILE = "feed_state.json"
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
# A feed where fewer than this share of rows is well-formed is rejected as corrupt.
MIN_VALID_RATIO = 0.95


class FeedValidationError(ValueError):
    """The downloaded bytes are not a valid feed; nothing was written."""


def default_dir() -> Path:
    from attestra import config

    config.ensure_dirs()
    d = config.DATA_DIR / "feeds"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _now() -> str:
    return datetime.now(UTC).isoformat()


# ------------------------------------------------------------------ validators


def decode_epss(raw: bytes) -> bytes:
    """Gunzip when the payload is gzip; otherwise return the bytes unchanged."""
    if raw[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(raw)
        except OSError as exc:
            raise FeedValidationError(f"EPSS gzip payload is corrupt: {exc}") from exc
    return raw


def parse_kev(raw: bytes) -> tuple[set[str], dict]:
    """Validate a CISA KEV JSON document; return ``(cve_ids, meta)``."""
    try:
        doc = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise FeedValidationError(f"KEV feed is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise FeedValidationError("KEV feed root must be a JSON object")
    vulns = doc.get("vulnerabilities")
    if not isinstance(vulns, list) or not vulns:
        raise FeedValidationError("KEV feed has no 'vulnerabilities' list")
    ids: set[str] = set()
    bad = 0
    for v in vulns:
        cve = (v or {}).get("cveID") if isinstance(v, dict) else None
        if isinstance(cve, str) and _CVE_RE.match(cve.strip()):
            ids.add(cve.strip().upper())
        else:
            bad += 1
    if not ids or (len(vulns) - bad) / len(vulns) < MIN_VALID_RATIO:
        raise FeedValidationError(f"KEV feed has too many malformed entries ({bad}/{len(vulns)})")
    count = doc.get("count")
    if isinstance(count, int) and count != len(vulns):
        raise FeedValidationError(f"KEV feed count {count} does not match {len(vulns)} entries (truncated?)")
    meta = {
        "records": len(ids),
        "catalog_version": str(doc.get("catalogVersion") or ""),
        "date_released": str(doc.get("dateReleased") or ""),
    }
    return ids, meta


def parse_epss(raw: bytes) -> tuple[dict[str, float], dict]:
    """Validate a FIRST EPSS CSV (optionally gzip); return ``({cve: epss}, meta)``."""
    data = decode_epss(raw)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FeedValidationError(f"EPSS feed is not UTF-8 text: {exc}") from exc
    score_date = ""
    model_version = ""
    body: list[str] = []
    for line in text.splitlines():
        if line.startswith("#"):
            low = line.lower()
            m = re.search(r"score_date:([^,\s]+)", low)
            if m:
                score_date = m.group(1)
            m = re.search(r"model_version:([^,\s]+)", low)
            if m:
                model_version = m.group(1)
            continue
        if line.strip():
            body.append(line)
    if not body:
        raise FeedValidationError("EPSS feed is empty")
    reader = csv.DictReader(io.StringIO("\n".join(body)))
    fields = [f.strip().lower() for f in (reader.fieldnames or [])]
    if "cve" not in fields or "epss" not in fields:
        raise FeedValidationError("EPSS feed header must contain 'cve' and 'epss' columns")
    scores: dict[str, float] = {}
    rows = bad = 0
    for row in reader:
        rows += 1
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
        try:
            val = float(row["epss"])
        except (KeyError, ValueError):
            bad += 1
            continue
        cve = row.get("cve", "")
        if not _CVE_RE.match(cve) or not (0.0 <= val <= 1.0):
            bad += 1
            continue
        scores[cve.upper()] = val
    if not scores or (rows - bad) / max(rows, 1) < MIN_VALID_RATIO:
        raise FeedValidationError(f"EPSS feed has too many malformed rows ({bad}/{rows})")
    return scores, {"records": len(scores), "score_date": score_date, "model_version": model_version}


def validate(feed: str, raw: bytes) -> dict:
    """Validate ``raw`` for ``feed`` (kev|epss); return metadata or raise FeedValidationError."""
    if not raw:
        raise FeedValidationError(f"{feed} feed is empty")
    if feed == "kev":
        return parse_kev(raw)[1]
    if feed == "epss":
        return parse_epss(raw)[1]
    raise FeedValidationError(f"unknown feed {feed!r}")


# ------------------------------------------------------------------ state + writes


def load_state(directory: Path | None = None) -> dict:
    p = (directory or default_dir()) / STATE_FILE
    if not p.is_file():
        return {}
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return doc if isinstance(doc, dict) else {}


def atomic_write(path: Path, data: bytes) -> None:
    """Write via temp file in the same directory + fsync + ``os.replace``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _save_state(state: dict, directory: Path) -> None:
    state["store_version"] = STORE_VERSION
    atomic_write(directory / STATE_FILE, json.dumps(state, indent=2, sort_keys=True).encode("utf-8"))


def store_feed(
    feed: str,
    raw: bytes,
    *,
    source: str = "",
    etag: str = "",
    last_modified: str = "",
    directory: Path | None = None,
    now: str | None = None,
) -> dict:
    """Validate then atomically store one feed. Returns that feed's state entry.

    Raises :class:`FeedValidationError` (after recording the failure in state) when the
    bytes are invalid; the previously stored file is left untouched in that case.
    """
    directory = directory or default_dir()
    now = now or _now()
    state = load_state(directory)
    entry = dict(state.get(feed) or {})
    entry.update({"source": source or entry.get("source", ""), "checked_at": now, "schema": SCHEMAS.get(feed, "")})
    if feed == "epss":
        raw = decode_epss(raw) if raw else raw
    try:
        meta = validate(feed, raw)
    except FeedValidationError as exc:
        entry.update({"status": "error", "last_error": str(exc)[:500], "last_error_at": now})
        state[feed] = entry
        _save_state(state, directory)
        raise
    digest = hashlib.sha256(raw).hexdigest()
    live = directory / FILENAMES[feed]
    unchanged = live.is_file() and entry.get("sha256") == digest and hashlib.sha256(live.read_bytes()).hexdigest() == digest
    if not unchanged:
        if live.is_file():
            atomic_write(live.with_name(live.name + ".prev"), live.read_bytes())
        atomic_write(live, raw)
        entry["fetched_at"] = now
        entry["last_good_at"] = now
    entry.update(
        {
            "status": "ok",
            "sha256": digest,
            "etag": etag or entry.get("etag", ""),
            "last_modified": last_modified or entry.get("last_modified", ""),
            "records": meta.get("records", 0),
            "meta": meta,
            "path": str(live),
            "last_error": "",
            "unchanged": unchanged,
        }
    )
    entry.setdefault("fetched_at", now)
    entry.setdefault("last_good_at", now)
    state[feed] = entry
    _save_state(state, directory)
    return entry


def record_failure(feed: str, error: str, *, source: str = "", directory: Path | None = None) -> dict:
    """Record a fetch failure (network/HTTP) without touching the stored feed."""
    directory = directory or default_dir()
    state = load_state(directory)
    entry = dict(state.get(feed) or {})
    now = _now()
    entry.update({"status": "error", "last_error": str(error)[:500], "last_error_at": now, "checked_at": now})
    if source:
        entry["source"] = source
    state[feed] = entry
    _save_state(state, directory)
    return entry


# ------------------------------------------------------------------ reads


@dataclass
class IntelSnapshot:
    """Validated feeds as read from disk, with provenance and freshness."""

    kev_json: bytes | None = None
    epss_csv: bytes | None = None
    kev: set[str] = field(default_factory=set)
    epss: dict[str, float] = field(default_factory=dict)
    state: dict = field(default_factory=dict)
    freshness: dict = field(default_factory=dict)
    used_fallback: list[str] = field(default_factory=list)

    @property
    def kev_known(self) -> bool:
        return self.kev_json is not None

    @property
    def epss_known(self) -> bool:
        return self.epss_csv is not None

    @property
    def source_version(self) -> str:
        return intel_source_version(self.state)


def _read_valid(feed: str, directory: Path) -> tuple[bytes | None, bool]:
    """Return (bytes, used_prev). Falls back to ``.prev`` when the live file is corrupt."""
    live = directory / FILENAMES[feed]
    for path, is_prev in ((live, False), (live.with_name(live.name + ".prev"), True)):
        if not path.is_file():
            continue
        data = path.read_bytes()
        try:
            validate(feed, data)
        except FeedValidationError:
            continue
        return data, is_prev
    return None, False


def load_validated(directory: Path | None = None, *, now: datetime | None = None) -> IntelSnapshot:
    """Load KEV and EPSS from disk, re-validating them; never returns corrupt content."""
    directory = directory or default_dir()
    snap = IntelSnapshot(state=load_state(directory))
    kev, kev_prev = _read_valid("kev", directory)
    epss, epss_prev = _read_valid("epss", directory)
    if kev is not None:
        snap.kev_json = kev
        snap.kev = parse_kev(kev)[0]
        if kev_prev:
            snap.used_fallback.append("kev")
    if epss is not None:
        snap.epss_csv = epss
        snap.epss = parse_epss(epss)[0]
        if epss_prev:
            snap.used_fallback.append("epss")
    snap.freshness = freshness_report(snap.state, now=now)
    for feed, data in (("kev", kev), ("epss", epss)):
        if data is None:
            snap.freshness["feeds"][feed]["status"] = "missing"
            if feed not in snap.freshness["stale_inputs"]:
                snap.freshness["stale_inputs"].append(feed)
    return snap


def intel_source_version(state: dict) -> str:
    """Compact provenance string stamped on enrichment, e.g. ``fs1;kev=2026.10.01@ab12cd34;epss=...``."""
    parts = [STORE_VERSION]
    for feed in ("kev", "epss"):
        e = (state or {}).get(feed) or {}
        meta = e.get("meta") or {}
        label = meta.get("catalog_version") or meta.get("score_date") or (e.get("last_good_at") or "")[:10] or "none"
        sha = (e.get("sha256") or "")[:8] or "none"
        parts.append(f"{feed}={label}@{sha}")
    return ";".join(parts)


def status(directory: Path | None = None) -> dict:
    """Operator view for ``attestra intel status`` (no feed contents, no secrets)."""
    snap = load_validated(directory)
    return {
        "source_version": snap.source_version,
        "freshness": snap.freshness,
        "used_fallback": snap.used_fallback,
        "feeds": {
            k: {kk: v.get(kk) for kk in ("status", "records", "fetched_at", "last_good_at", "checked_at",
                                         "sha256", "schema", "last_error", "source")}
            for k, v in snap.state.items()
            if isinstance(v, dict)
        },
    }
