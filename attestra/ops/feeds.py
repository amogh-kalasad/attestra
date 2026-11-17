"""Download and cache CISA KEV / FIRST EPSS feeds for enrich --refresh.

G-01: downloads are validated by :mod:`attestra.intel.feed_store` *before* they are
written; writes are atomic and the last good copy is kept, so a broken or partial
download never erases existing enrichment. ``catalog.json`` is still maintained for
report templates that read :func:`load_catalog_meta`.
"""
# @lat: [[architecture#Engagement flow]]
# @lat: [[intel-and-reporting#Feed store and freshness]]

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime
from pathlib import Path
from urllib.request import urlopen

from attestra import config
from attestra.intel import feed_store


class FeedError(Exception):
    pass


def feeds_dir() -> Path:
    config.ensure_dirs()
    d = config.DATA_DIR / "feeds"
    d.mkdir(parents=True, exist_ok=True)
    return d


def catalog_meta_path() -> Path:
    return feeds_dir() / "catalog.json"


def load_catalog_meta() -> dict:
    p = catalog_meta_path()
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _header(resp, name: str) -> str:
    headers = getattr(resp, "headers", None)
    try:
        return str(headers.get(name) or "") if headers is not None else ""
    except Exception:  # noqa: BLE001 — fake/odd response objects
        return ""


def _download(url: str) -> tuple[bytes, str, str]:
    with urlopen(url, timeout=60) as resp:  # noqa: S310 — operator-configured feed URL
        return resp.read(), _header(resp, "ETag"), _header(resp, "Last-Modified")


def _epss_bytes(raw: bytes, url: str) -> bytes:
    if raw[:2] == b"\x1f\x8b":
        return gzip.decompress(raw)
    if url.endswith(".gz"):
        try:
            return gzip.decompress(raw)
        except OSError:
            return raw  # some mirrors serve plain CSV at a .gz URL
    return raw


def refresh_feeds(*, kev_url: str | None = None, epss_url: str | None = None) -> dict:
    """Download, validate and atomically store KEV JSON and EPSS CSV; update catalog.json.

    Each feed is handled independently: a failure on one (network or validation) keeps
    its last good file and is recorded in ``feed_state.json``; the other feed still
    refreshes. :class:`FeedError` is raised at the end if any feed failed.
    """
    kev_url = kev_url or config.KEV_URL
    epss_url = epss_url or config.EPSS_URL
    now = datetime.now(UTC).isoformat()
    meta = load_catalog_meta()
    directory = feeds_dir()
    errors: list[str] = []

    try:
        kev_bytes, etag, last_mod = _download(kev_url)
        entry = feed_store.store_feed(
            "kev", kev_bytes, source=kev_url, etag=etag, last_modified=last_mod, directory=directory, now=now
        )
        kmeta = entry.get("meta") or {}
        meta["kev_date"] = kmeta.get("date_released") or kmeta.get("catalog_version") or now
        meta["kev_fetched_at"] = now
        meta["kev_path"] = str(directory / feed_store.FILENAMES["kev"])
    except feed_store.FeedValidationError as exc:
        errors.append(f"KEV feed rejected (last good copy kept): {exc}")
    except Exception as exc:  # noqa: BLE001 — network/HTTP failure
        feed_store.record_failure("kev", f"{type(exc).__name__}: {exc}", source=kev_url, directory=directory)
        errors.append(f"KEV download failed (last good copy kept): {type(exc).__name__}")

    try:
        raw, etag, last_mod = _download(epss_url)
        epss_bytes = _epss_bytes(raw, epss_url)
        entry = feed_store.store_feed(
            "epss", epss_bytes, source=epss_url, etag=etag, last_modified=last_mod, directory=directory, now=now
        )
        emeta = entry.get("meta") or {}
        catalog_date = emeta.get("score_date") or now
        # Backward compatible: FIRST CSV comment line carries the score date.
        if not emeta.get("score_date"):
            for line in epss_bytes.decode("utf-8", errors="replace").splitlines()[:5]:
                if "score_date" in line.lower() or line.startswith("#"):
                    catalog_date = line.lstrip("#").strip()
                    break
        meta["epss_date"] = catalog_date
        meta["epss_fetched_at"] = now
        meta["epss_path"] = str(directory / feed_store.FILENAMES["epss"])
    except feed_store.FeedValidationError as exc:
        errors.append(f"EPSS feed rejected (last good copy kept): {exc}")
    except Exception as exc:  # noqa: BLE001
        feed_store.record_failure("epss", f"{type(exc).__name__}: {exc}", source=epss_url, directory=directory)
        errors.append(f"EPSS download failed (last good copy kept): {type(exc).__name__}")

    meta["intel_source_version"] = feed_store.intel_source_version(feed_store.load_state(directory))
    feed_store.atomic_write(catalog_meta_path(), json.dumps(meta, indent=2).encode("utf-8"))
    if errors:
        raise FeedError("; ".join(errors))
    return meta


def load_cached_feeds() -> tuple[bytes | None, bytes | None]:
    """Return (kev_json, epss_csv) from local cache if present and valid (last good copy)."""
    snap = feed_store.load_validated(feeds_dir())
    return snap.kev_json, snap.epss_csv
