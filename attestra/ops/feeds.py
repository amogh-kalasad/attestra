"""Download and cache CISA KEV / FIRST EPSS feeds for enrich --refresh."""
# @lat: [[architecture#Engagement flow]]

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime
from pathlib import Path
from urllib.request import urlopen

from attestra import config


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


def refresh_feeds(*, kev_url: str | None = None, epss_url: str | None = None) -> dict:
    """Download KEV JSON and EPSS CSV into DATA_DIR/feeds/; update catalog.json dates."""
    kev_url = kev_url or config.KEV_URL
    epss_url = epss_url or config.EPSS_URL
    now = datetime.now(UTC).isoformat()
    meta = load_catalog_meta()

    with urlopen(kev_url, timeout=60) as resp:  # noqa: S310 — operator-configured feed URL
        kev_bytes = resp.read()
    kev_path = feeds_dir() / "kev.json"
    kev_path.write_bytes(kev_bytes)
    try:
        doc = json.loads(kev_bytes)
        meta["kev_date"] = doc.get("dateReleased") or doc.get("catalogVersion") or now
    except json.JSONDecodeError as exc:
        raise FeedError(f"KEV feed is not valid JSON: {exc}") from exc
    meta["kev_fetched_at"] = now
    meta["kev_path"] = str(kev_path)

    with urlopen(epss_url, timeout=60) as resp:  # noqa: S310
        raw = resp.read()
    if raw[:2] == b"\x1f\x8b":
        epss_bytes = gzip.decompress(raw)
    elif epss_url.endswith(".gz"):
        try:
            epss_bytes = gzip.decompress(raw)
        except OSError:
            epss_bytes = raw  # some mirrors serve plain CSV at a .gz URL
    else:
        epss_bytes = raw
    epss_path = feeds_dir() / "epss.csv"
    epss_path.write_bytes(epss_bytes)
    # FIRST CSV often has a comment line with score date
    catalog_date = now
    for line in epss_bytes.decode("utf-8", errors="replace").splitlines()[:5]:
        if "score_date" in line.lower() or line.startswith("#"):
            catalog_date = line.lstrip("#").strip()
            break
    meta["epss_date"] = catalog_date
    meta["epss_fetched_at"] = now
    meta["epss_path"] = str(epss_path)

    catalog_meta_path().write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def load_cached_feeds() -> tuple[bytes | None, bytes | None]:
    """Return (kev_json, epss_csv) from local cache if present."""
    kev_p = feeds_dir() / "kev.json"
    epss_p = feeds_dir() / "epss.csv"
    kev = kev_p.read_bytes() if kev_p.is_file() else None
    epss = epss_p.read_bytes() if epss_p.is_file() else None
    return kev, epss
