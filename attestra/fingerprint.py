"""Stable finding fingerprints so the same issue from two tools or two runs dedupes."""
# @lat: [[findings#Deduplication]]

from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urlsplit

# webcheck dns-caa and testssl DNS_CAArecord (R15) share this variant key.
CAA_VARIANT = "dns-caa"
_CAA_VARIANT_ALIASES = frozenset({"dns-caa", "dns_caarecord"})
_CAA_LEGACY_PORTS = ("443", "8443", "")


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


def is_caa_variant(variant: str) -> bool:
    """True for webcheck dns-caa or testssl DNS_CAArecord."""
    return (variant or "").strip().lower() in _CAA_VARIANT_ALIASES


def caa_host(location: str) -> str:
    """Bare hostname for CAA fingerprints (drop scheme, path, and :port)."""
    loc = (location or "").strip()
    if "://" in loc:
        parts = urlsplit(loc)
        host = parts.netloc.split("@")[-1]
    else:
        host = loc.split("/")[0]
    host = host.strip().lower()
    if host.startswith("[") and "]" in host:
        return host  # IPv6 literal — keep as-is
    if ":" in host:
        name, _, port = host.rpartition(":")
        if port.isdigit():
            return name
    return host


def is_cert_expiry_variant(variant: str) -> bool:
    """True for testssl/webcheck certificate expiry findings (same merge key)."""
    v = (variant or "").strip().lower()
    return v in {"cert_expirationstatus", "cert_expiration", "cert_expiring"}


CERT_EXPIRY_VARIANT = "cert_expirationStatus"


# DAST tools that report one alert instance per crawled URL (ZAP). Their findings
# are grouped: one finding per rule (pluginid / alertRef) per origin, and every
# URL stays on the finding (affected_urls) and as its own observation.
GROUPED_TOOLS = frozenset({"zap"})
AFFECTED_URLS_CAP = 500


def is_grouped_tool(tool: str) -> bool:
    return (tool or "").strip().lower() in GROUPED_TOOLS


def url_origin(location: str) -> str:
    """``scheme://host[:port]/`` for a URL, or "" when ``location`` is not a URL."""
    loc = (location or "").strip()
    if "://" not in loc:
        return ""
    try:
        parts = urlsplit(loc)
    except ValueError:
        return ""
    if not parts.scheme or not parts.netloc:
        return ""
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}/"


def group_kwargs(
    *, tool: str, location: str, param: str = "", variant: str = "", rule_key: str = ""
) -> tuple[str, str, str] | None:
    """(location, param, variant) for the grouped fingerprint, or None when not grouped.

    The rule id goes into the variant so two rules that share a CWE on one host
    (e.g. two missing-header alerts, both CWE-693) stay separate findings.
    """
    if not is_grouped_tool(tool):
        return None
    origin = url_origin(location)
    if not origin:
        return None
    v = variant or (f"{tool.strip().lower()}-{rule_key}" if rule_key else "")
    return origin, "", v


def affected_entry(location: str, param: str = "") -> str:
    """One affected-URL line, in the same ``url [param: x]`` shape as Finding.location."""
    loc = (location or "").strip()
    return f"{loc} [param: {param}]" if param else loc


def canonicalize_for_merge(
    *,
    location: str,
    cwe: int | None,
    cves: list[str],
    title: str,
    param: str = "",
    package: str = "",
    asset_id: int | None = None,
    variant: str = "",
    tool: str = "",
    rule_key: str = "",
) -> dict[str, Any]:
    """Return fingerprint kwargs; align CAA and cert-expiry fields across tools.

    For grouped DAST tools (ZAP) the key is rule + origin, not the per-URL location.
    """
    if is_caa_variant(variant):
        return {
            "location": caa_host(location),
            "cwe": 16,
            "cves": cves,
            "title": title,
            "param": "",
            "package": package,
            "asset_id": asset_id,
            "variant": CAA_VARIANT,
        }
    if is_cert_expiry_variant(variant):
        # One expiry finding per host: bare hostname, fixed CWE/param/variant.
        # Title is omitted from the key (CWE path) so band text can change in place.
        return {
            "location": caa_host(location),
            "cwe": 298,
            "cves": cves,
            "title": title,
            "param": "",
            "package": package,
            "asset_id": asset_id,
            "variant": CERT_EXPIRY_VARIANT,
        }
    grp = group_kwargs(tool=tool, location=location, param=param, variant=variant, rule_key=rule_key)
    if grp is not None:
        location, param, variant = grp
    return {
        "location": location,
        "cwe": cwe,
        "cves": cves,
        "title": title,
        "param": param,
        "package": package,
        "asset_id": asset_id,
        "variant": variant,
    }


def caa_legacy_fingerprints(*, host: str, asset_id: int | None = None) -> list[str]:
    """Pre-merge testssl DNS_CAArecord fingerprints (host:port + check-id param)."""
    bare = caa_host(host)
    out: list[str] = []
    seen: set[str] = set()
    for port in _CAA_LEGACY_PORTS:
        loc = f"{bare}:{port}" if port else bare
        for cwe in (16, 326):
            for variant, param in (("DNS_CAArecord", "DNS_CAArecord"), ("DNS_CAArecord", "")):
                fp = fingerprint(
                    location=loc,
                    cwe=cwe,
                    cves=[],
                    title="",
                    param=param,
                    asset_id=asset_id,
                    variant=variant,
                )
                if fp not in seen:
                    seen.add(fp)
                    out.append(fp)
    return out


def fingerprint(
    *,
    location: str,
    cwe: int | None,
    cves: list[str],
    title: str,
    param: str = "",
    package: str = "",
    asset_id: int | None = None,
    variant: str = "",
) -> str:
    """Stable fingerprint. Optional ``asset_id`` scopes DAST issues per target.

    When ``variant`` is non-empty it is appended as ``v=<variant>`` so distinct
    alert subtypes (for example ZAP alertRef) do not collide. Empty variant keeps
    the exact pre-variant key bytes.
    """
    loc = normalize_location(location)
    asset_part = str(asset_id) if asset_id is not None else ""
    if cves:
        key = ["cve", ",".join(sorted(c.upper() for c in cves)), package.lower(), loc, asset_part]
    elif cwe:
        key = ["cwe", str(cwe), loc, param.lower(), asset_part]
    else:
        key = ["title", normalize_title(title), loc, param.lower(), asset_part]
    if variant:
        key.append("v=" + variant.lower())
    return hashlib.sha256("|".join(key).encode()).hexdigest()
