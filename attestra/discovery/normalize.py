"""Hostname normalization and deterministic candidate keys (A-01)."""
# @lat: [[attack-surface-and-platform#Passive discovery]]

from __future__ import annotations

import hashlib
import ipaddress
import re

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def normalize_hostname(raw: object) -> str | None:
    """Lowercase, strip wildcard/trailing dot, IDNA-encode and validate. None when invalid.

    IP literals, URLs with paths, names with spaces or inner wildcards are rejected.
    """
    if raw is None:
        return None
    name = str(raw).strip().lower()
    if "://" in name:
        name = name.split("://", 1)[1]
    name = name.split("/", 1)[0].split("?", 1)[0]
    if name.count(":") == 1:  # host:port
        name = name.split(":", 1)[0]
    name = name.rstrip(".")
    while name.startswith("*."):
        name = name[2:]
    if not name or "*" in name or " " in name:
        return None
    try:
        ipaddress.ip_address(name.strip("[]"))
        return None
    except ValueError:
        pass
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(name) > 253:
        return None
    labels = name.split(".")
    if len(labels) < 2:
        return None
    for label in labels:
        # Underscore labels (e.g. _dmarc) are DNS-valid but never web hosts.
        if not _LABEL.match(label):
            return None
    if labels[-1].isdigit():
        return None
    return name


def under_apex(name: str, apex: str) -> bool:
    n = (name or "").strip(".").lower()
    a = (apex or "").strip(".").lower()
    return bool(n and a) and (n == a or n.endswith("." + a))


def host_denied(name: str, deny_hosts) -> bool:
    """Exact deny or ``*.example.com`` style suffix deny."""
    n = (name or "").lower().rstrip(".")
    for raw in deny_hosts or ():
        d = str(raw).strip().lower().rstrip(".")
        if not d:
            continue
        if d.startswith("*."):
            if under_apex(n, d[2:]) and n != d[2:]:
                return True
        elif n == d:
            return True
    return False


def candidate_key(tenant_id: int, engagement_id: int, name: str) -> str:
    """Stable document id: same tenant + engagement + normalized name → same key."""
    raw = f"{int(tenant_id)}|{int(engagement_id)}|{name.lower().rstrip('.')}"
    return "dc_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
