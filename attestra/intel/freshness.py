"""Feed freshness: how old each intel input is and whether it is stale.

Stale or missing intel is reported as *unknown*, never silently treated as zero.
"""
# @lat: [[intel-and-reporting#Feed store and freshness]]

from __future__ import annotations

import os
from datetime import UTC, datetime

# Defaults: CISA KEV and FIRST EPSS both publish daily; NVD is incremental.
DEFAULT_MAX_AGE_HOURS: dict[str, float] = {"kev": 72.0, "epss": 72.0, "nvd": 168.0, "osv": 168.0}


def max_age_hours(feed: str) -> float:
    """Per-feed staleness threshold; ``ATTESTRA_INTEL_MAX_AGE_HOURS_<FEED>`` overrides."""
    env = os.environ.get(f"ATTESTRA_INTEL_MAX_AGE_HOURS_{feed.upper()}", "").strip()
    if env:
        try:
            return max(float(env), 0.0)
        except ValueError:
            pass
    return DEFAULT_MAX_AGE_HOURS.get(feed, 168.0)


def _parse_ts(value) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def feed_freshness(feed: str, fetched_at, *, now: datetime | None = None) -> dict:
    """Return ``{feed, fetched_at, age_hours, max_age_hours, stale, known}`` for one feed."""
    now = now or datetime.now(UTC)
    ts = _parse_ts(fetched_at)
    limit = max_age_hours(feed)
    if ts is None:
        return {"feed": feed, "fetched_at": None, "age_hours": None, "max_age_hours": limit,
                "stale": True, "known": False}
    age = max((now - ts).total_seconds() / 3600.0, 0.0)
    return {"feed": feed, "fetched_at": ts.isoformat(), "age_hours": round(age, 2),
            "max_age_hours": limit, "stale": age > limit, "known": True}


def freshness_report(state: dict, *, feeds=("kev", "epss"), now: datetime | None = None) -> dict:
    """Freshness for each feed in a feed-store ``state`` dict, plus ``stale_inputs``."""
    out: dict = {"feeds": {}, "stale_inputs": []}
    for feed in feeds:
        entry = (state or {}).get(feed) or {}
        fr = feed_freshness(feed, entry.get("last_good_at") or entry.get("fetched_at"), now=now)
        fr["status"] = entry.get("status") or ("missing" if not entry else "unknown")
        out["feeds"][feed] = fr
        if fr["stale"]:
            out["stale_inputs"].append(feed)
    return out
