"""Finding location/context normalization for cross-tool merge guards.

Security context keeps the same concept on one host from auto-merging when the
affected resource is infrastructure (CDN/challenge) vs application vs static.
Sibling CONCEPT_RULES expansions may add entries via ``EXTRA_CONCEPT_RULES``.
Import-time CWE remapping keeps deprecated X-XSS-Protection and Expect-CT out of
CWE-79 XSS fingerprints and CSP concepts. CSP directive / missing-directive /
unsafe-* alerts share one concept so soft-match and fingerprint collision merge them.
"""
# @lat: [[findings#Deduplication#Cross-tool merge]]
# @lat: [[findings#Review corrections#CSP directive consolidation]]

from __future__ import annotations

import re
from urllib.parse import urlsplit

from attestra.fingerprint import caa_host, normalize_location, url_origin
from attestra.finding_validation.infrastructure import (
    is_cache_related_finding,
    is_cdn_challenge_url,
    is_static_asset_url,
)

# Optional sibling expansions (CORS / Permissions-Policy / SameSite / weak-cipher).
# crossmerge merges these with try/getattr so either side can land first.
EXTRA_CONCEPT_RULES: dict[str, dict[str, list[tuple[str, str]]]] = {}

# Protection Mechanism Failure — not reflected XSS (CWE-79).
XSS_PROTECTION_CWE = 693
EXPECT_CT_CWE = 693
# Hyphen, underscore, or space (ZAP "XSS Protection"); rule id 10016.
_XSS_PROTECTION_RE = re.compile(
    r"(?i)xss[-_\s]?protection|xss\.?deprecated[.\-_]?header|x-xss-protection"
    r"|xss_deprecated_header|(?:^|[\s,;])10016(?:$|[\s,;:])"
)
_EXPECT_CT_RE = re.compile(
    r"(?i)expect[-_\s]?ct|expect\.?ct[.\-_]?header|(?:^|[\s,;/])expect-ct(?:$|[\s,;:])"
)

# One concept for fragmented CSP directive / incomplete-policy alerts (Gemini review).
# Distinct from header:csp-missing (ZAP 10038 / nuclei header-not-set).
CSP_WEAK_OR_INCOMPLETE = "csp:weak-or-incomplete"
CSP_UNIFIED_VARIANT = "csp:weak-or-incomplete"
CSP_CANONICAL_TITLE = "Weak or Incomplete Content Security Policy (CSP)"
CSP_OBS_MARKER = "CSP observations:"

# Titles like "CSP: script-src unsafe-eval", "CSP: object-src directive missing".
_CSP_DIRECTIVE_TITLE_RE = re.compile(
    r"(?i)^csp:\s|"
    r"weak (?:or incomplete )?content security policy|"
    r"incomplete content security policy|"
    r"content.security.policy.+\b(?:unsafe-inline|unsafe-eval|wildcard|form-action|"
    r"object-src|frame-ancestors)\b"
)
# ZAP 10055 (+ subtypes), webcheck csp:*, nuclei weak-csp / csp-*-unsafe|wildcard.
_CSP_DIRECTIVE_RULE_RE = re.compile(
    r"(?i)^10055(?:-\d+)?$|"
    r"^(?:webcheck/)?csp:|"
    r"^weak-csp|"
    r"^csp-[a-z0-9_-]*(?:wildcard|unsafe)"
)

# CONCEPT_RULES sibling: all CSP directive / incomplete-policy alerts share one key.
EXTRA_CONCEPT_RULES[CSP_WEAK_OR_INCOMPLETE] = {
    "zap": [(r"^10055$", r"")],
    "webcheck": [
        (r"^(?:webcheck/)?csp:", r""),
        (r"^csp:", r""),
    ],
    "nuclei": [
        (r"^(?:weak-csp-detect|csp-[a-z0-9_-]*(?:wildcard|unsafe)[a-z0-9_-]*)(?::.*)?$", r""),
    ],
    "observatory": [(r"^content-security-policy$", r"^csp:")],
}

_CDN_CGI_MARKERS = ("/cdn-cgi/", "cdn-cgi/")
_CHALLENGE_MARKERS = (
    "challenge-platform",
    "/cdn-cgi/challenge-platform",
    "challenges.cloudflare.com",
    "cf-chl-",
)
_STATIC_PREFIXES = ("/_next/", "/__nextjs", "/_vercel/", "/static/", "/assets/")
_HOSTPORT = re.compile(r"^[a-z0-9.-]+(:\d{1,5})?$", re.IGNORECASE)


def is_xss_protection_deprecated(
    *,
    title: str = "",
    rule_id: str = "",
    rule_ids: list[str] | None = None,
) -> bool:
    """True for deprecated X-XSS-Protection hardening (not reflected XSS)."""
    if _XSS_PROTECTION_RE.search(title or ""):
        return True
    blob = " ".join([rule_id or "", *(str(r) for r in (rule_ids or []))])
    return bool(blob.strip() and _XSS_PROTECTION_RE.search(blob))


def is_expect_ct_deprecated(
    *,
    title: str = "",
    rule_id: str = "",
    rule_ids: list[str] | None = None,
    description: str = "",
) -> bool:
    """True for obsolete Expect-CT header observations (not CSP / XSS)."""
    if _EXPECT_CT_RE.search(title or "") or _EXPECT_CT_RE.search(description or ""):
        return True
    blob = " ".join([rule_id or "", *(str(r) for r in (rule_ids or []))])
    return bool(blob.strip() and _EXPECT_CT_RE.search(blob))


def normalize_cwe_for_import(
    *,
    title: str = "",
    rule_id: str = "",
    rule_ids: list[str] | None = None,
    cwe: int | None = None,
    description: str = "",
) -> int | None:
    """Remap misleading template CWEs before fingerprint / soft-match.

    Nuclei ``xss-deprecated-header`` often ships CWE-79; that must not share a
    fingerprint with reflected XSS at the same location. Expect-CT must not keep
    CWE-79 either (wrong XSS/CSP Injection path).
    """
    if is_xss_protection_deprecated(title=title, rule_id=rule_id, rule_ids=rule_ids):
        return XSS_PROTECTION_CWE
    if is_expect_ct_deprecated(
        title=title, rule_id=rule_id, rule_ids=rule_ids, description=description
    ):
        # Clear wrong XSS/Injection CWE; keep non-79 values unless absent.
        if cwe is None or cwe == 79:
            return EXPECT_CT_CWE
        return cwe
    return cwe


_HSTS_MISSING_RE = re.compile(
    r"(?i)(?:hsts|strict-transport-security).{0,40}(?:missing|not\s+set|absent|not\s+present)"
    r"|(?:missing|not\s+set|absent).{0,40}(?:hsts|strict-transport-security)"
    r"|hsts\s+header\s+missing"
    r"|(?:^|[\s,;/])(?:webcheck/)?hsts-present(?:$|[\s,;:])"
    r"|(?:^|[\s,;/])10035(?:$|[\s,;:])"
)
_SSL_STRIP_POC_RE = re.compile(
    r"(?i)ssl[-\s]?strip|sslstrip|mitm\s+downgrade|confirmed\s+(?:ssl\s+)?stripp"
)


def is_hsts_missing_claim(
    *,
    title: str = "",
    rule_id: str = "",
    rule_ids: list[str] | None = None,
    description: str = "",
) -> bool:
    """True for missing/absent HSTS header observations (not short max-age alone)."""
    blob = f"{title or ''}\n{description or ''}\n{rule_id or ''}\n" + " ".join(
        str(r) for r in (rule_ids or [])
    )
    return bool(_HSTS_MISSING_RE.search(blob))


_ZAP_NOTICE_RULE_RE = re.compile(r"(?:^|[\s,;/])(?:10109|10112)(?:$|[\s,;:])")
_ZAP_NOTICE_TITLE_RE = re.compile(
    r"(?i)modern\s+web\s+application|session\s+management\s+response\s+identified"
)


def normalize_severity_for_import(
    *,
    title: str = "",
    rule_id: str = "",
    rule_ids: list[str] | None = None,
    description: str = "",
    severity: str | None = None,
    location: str = "",
) -> str | None:
    """Cap misleading scanner severities before fingerprint / soft-match.

    Expect-CT → info. ZAP 10109/10112 notices → info. Cache on static/CDN → info.
    HSTS-missing without SSL-strip PoC → low (never Medium/CVSS 5.0 by default;
    aligns with library seed default_severity).
    """
    if is_expect_ct_deprecated(
        title=title, rule_id=rule_id, rule_ids=rule_ids, description=description
    ):
        sev = (severity or "").strip().lower()
        if sev in ("critical", "high", "medium", "moderate"):
            return "info"
        return severity or "info"

    rule_blob = " ".join([rule_id or "", *(str(r) for r in (rule_ids or []))])
    notice_blob = f"{title or ''}\n{description or ''}"
    if _ZAP_NOTICE_RULE_RE.search(rule_blob) or _ZAP_NOTICE_TITLE_RE.search(notice_blob):
        return "info"

    # Cache contradictions on static Next.js / CDN assets — never Medium open vulns.
    if is_cache_related_finding(title, [rule_id, *(rule_ids or [])], description):
        if is_static_asset_url(location) or is_cdn_challenge_url(location):
            return "info"

    if is_hsts_missing_claim(
        title=title, rule_id=rule_id, rule_ids=rule_ids, description=description
    ):
        exploit_blob = f"{title or ''}\n{description or ''}"
        if not _SSL_STRIP_POC_RE.search(exploit_blob):
            sev = (severity or "").strip().lower()
            if sev in ("critical", "high", "medium", "moderate"):
                return "low"
    return severity


def is_csp_weak_or_incomplete(
    *,
    title: str = "",
    rule_id: str = "",
    rule_ids: list[str] | None = None,
    variant: str = "",
) -> bool:
    """True for CSP directive / incomplete-policy alerts (not header-not-set 10038)."""
    if _CSP_DIRECTIVE_TITLE_RE.search((title or "").strip()):
        return True
    for rid in [rule_id or "", variant or "", *(str(r) for r in (rule_ids or []))]:
        if rid.strip() and _CSP_DIRECTIVE_RULE_RE.search(rid.strip()):
            return True
    return False


def csp_fingerprint_kwargs(
    *,
    location: str,
    cwe: int | None,
    cves: list,
    title: str,
    param: str = "",
    package: str = "",
    asset_id: int | None = None,
) -> dict:
    """Shared fingerprint fields so CSP directive subtypes collide intentionally."""
    origin = url_origin(location) or normalize_location(_bare_location(location))
    return {
        "location": origin,
        "cwe": cwe if cwe is not None else XSS_PROTECTION_CWE,
        "cves": cves,
        "title": title,
        "param": "",
        "package": package,
        "asset_id": asset_id,
        "variant": CSP_UNIFIED_VARIANT,
    }


def append_csp_observation(description: str, observation_title: str) -> str:
    """Append a distinct CSP sub-observation bullet to a finding description."""
    note = (observation_title or "").strip()
    if not note:
        return description or ""
    desc = description or ""
    if note.lower() in desc.lower():
        return desc
    bullet = f"- {note}"
    if CSP_OBS_MARKER in desc:
        return desc.rstrip() + "\n" + bullet
    base = desc.rstrip()
    if base:
        return f"{base}\n\n{CSP_OBS_MARKER}\n{bullet}"
    return f"{CSP_OBS_MARKER}\n{bullet}"


def _bare_location(location: str) -> str:
    loc = (location or "").strip()
    if " [param:" in loc:
        loc = loc.split(" [param:", 1)[0].strip()
    return loc


def context_host(location: str) -> str:
    """Lowercase hostname for a URL or ``host[:port]``; "" for files/images."""
    loc = _bare_location(location)
    if not loc:
        return ""
    if "://" in loc:
        try:
            host = urlsplit(loc).hostname or ""
        except ValueError:
            return ""
        return host.lower().rstrip(".")
    if _HOSTPORT.match(loc) and "." in loc:
        return caa_host(loc).rstrip(".")
    return ""


def path_context_bucket(location: str, title: str = "") -> str:
    """Path security bucket: ``challenge``, ``cdn-cgi``, ``static``, or ``app``."""
    loc = _bare_location(location)
    blob = f"{loc}\n{title or ''}".lower()
    if any(m in blob for m in _CHALLENGE_MARKERS):
        return "challenge"
    if any(m in blob for m in _CDN_CGI_MARKERS):
        return "cdn-cgi"
    path = ""
    if "://" in loc:
        try:
            path = (urlsplit(loc).path or "").lower()
        except ValueError:
            path = ""
    else:
        path = loc.lower()
    if any(p in path for p in _STATIC_PREFIXES):
        return "static"
    return "app"


def security_context_key(location: str, title: str = "") -> str:
    """Host + path-context key so CDN/challenge findings do not merge with app ones.

    Format: ``{host}@{bucket}`` (e.g. ``shop.example.com@app``). When host is
    missing, uses normalized location (or empty) before ``@{bucket}``.
    """
    bucket = path_context_bucket(location, title)
    host = context_host(location)
    if host:
        return f"{host}@{bucket}"
    loc = normalize_location(_bare_location(location)).lower()
    return f"{loc}@{bucket}" if loc else f"@{bucket}"
