"""Stable finding fingerprints so the same issue from two tools or two runs dedupes."""
# @lat: [[findings#Deduplication]]

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit


def normalize_location(location: str) -> str:
    """Lowercase scheme/host, drop query values and fragments, trim trailing slash."""
    loc = location.strip()
    if "://" in loc:
        parts = urlsplit(loc)
        query_keys = sorted(k.split("=")[0] for k in parts.query.split("&") if k)
        path = parts.path.rstrip("/") or "/"
        loc = f"{parts.scheme.lower()}://{parts.netloc.lower()}{path}"
        if query_keys:
            loc += "?" + "&".join(query_keys)
    return loc


def normalize_title(title: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", title.lower()).strip()


def fingerprint(
    *, location: str, cwe: int | None, cves: list[str], title: str, param: str = "", package: str = ""
) -> str:
    loc = normalize_location(location)
    if cves:
        key = ["cve", ",".join(sorted(c.upper() for c in cves)), package.lower(), loc]
    elif cwe:
        key = ["cwe", str(cwe), loc, param.lower()]
    else:
        key = ["title", normalize_title(title), loc, param.lower()]
    return hashlib.sha256("|".join(key).encode()).hexdigest()
