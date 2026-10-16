"""Google Safe Browsing v4 threatMatches:find lookup (passive reputation).

Off by default. Runs only when ``ATTESTRA_GSB_ENABLED`` is on and
``ATTESTRA_GSB_API_KEY`` is set. The API key is never logged, saved, or
returned in findings, notes, checks, or the report body.
"""
# @lat: [[runner#Scanner runs#webcheck (passive headers and DNS)#Safe Browsing]]

from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from attestra.checks import FAILED, PASSED, SKIPPED, check_row

log = logging.getLogger("attestra.safe_browsing")

GSB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
GSB_CHECK_ID = "safe-browsing"
GSB_CHECK_NAME = "Not on Google Safe Browsing list"
GSB_SKIP_NOTE = "Safe Browsing check skipped: no API key"
GSB_THREAT_TYPES = ("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE")
_REMEDIATION = (
    "Clean the site (remove malware, backdoors, and injected script), "
    "rotate any stolen credentials, then request a review in Google Search Console."
)

PostFn = Callable[[dict, str], dict]


def gsb_enabled() -> bool:
    return os.environ.get("ATTESTRA_GSB_ENABLED", "").strip().lower() in ("1", "true", "yes")


def gsb_api_key() -> str:
    return (os.environ.get("ATTESTRA_GSB_API_KEY") or "").strip()


def mask_secret(text: str, secret: str) -> str:
    """Replace every occurrence of ``secret`` (and its URL-encoded form) with ***."""
    if not text or not secret:
        return text
    out = text.replace(secret, "***")
    encoded = quote(secret, safe="")
    if encoded and encoded != secret:
        out = out.replace(encoded, "***")
    return out


def _safe_note(msg: str, secret: str = "") -> str:
    key = secret or gsb_api_key()
    return mask_secret(str(msg), key)


@dataclass
class SafeBrowsingResult:
    """Findings, notes, and C5 check rows from one Safe Browsing lookup."""

    findings: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    checks: list[dict] = field(default_factory=list)


def _finding_for_matches(matches: list[dict], location: str) -> dict:
    types: list[str] = []
    for m in matches:
        t = str(m.get("threatType") or "").strip().upper()
        if t in GSB_THREAT_TYPES and t not in types:
            types.append(t)
    if not types:
        types = ["UNKNOWN"]
    label = ", ".join(types)
    return {
        "id": GSB_CHECK_ID,
        "title": f"Listed on Google Safe Browsing ({label})",
        "severity": "high",
        "cwe": 506,
        "description": (
            f"Google Safe Browsing lists this URL for: {label}. "
            "Browsers and search may warn users or block the site."
        ),
        "location": location,
        "recommendation": _REMEDIATION,
        "variant": GSB_CHECK_ID,
    }


def _default_post(body: dict, api_key: str) -> dict:
    """POST threatMatches:find. The keyed URL is never returned or logged."""
    qs = urlencode({"key": api_key})
    url = f"{GSB_ENDPOINT}?{qs}"
    payload = json.dumps(body).encode("utf-8")
    req = Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "attestra-webcheck/0.1",
        },
    )
    try:
        with urlopen(req, timeout=10) as resp:  # noqa: S310 - Google API, not engagement target
            raw = resp.read(1_000_000)
    except HTTPError as exc:
        # Read body for status context but never include the request URL (has key).
        detail = ""
        try:
            detail = exc.read(2000).decode("utf-8", errors="replace")
        except Exception:
            detail = ""
        raise RuntimeError(_safe_note(f"Safe Browsing API HTTP {exc.code}: {detail}", api_key)) from None
    except URLError as exc:
        raise RuntimeError(_safe_note(f"Safe Browsing API network error: {exc.reason}", api_key)) from None
    text = raw.decode("utf-8", errors="replace").strip() or "{}"
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Safe Browsing API returned non-JSON") from exc
    if not isinstance(data, dict):
        raise RuntimeError("Safe Browsing API returned unexpected JSON")
    return data


def check_safe_browsing(
    urls: list[str],
    *,
    post_fn: PostFn | None = None,
) -> SafeBrowsingResult:
    """Lookup in-scope URLs against Google Safe Browsing (one batched request).

    Silent when the feature flag is off. When enabled with no key, returns a
    skip note and a skipped check (no network). API errors become notes, not findings.
    """
    result = SafeBrowsingResult()
    if not gsb_enabled():
        return result

    key = gsb_api_key()
    if not key:
        result.notes.append(GSB_SKIP_NOTE)
        result.checks.append(
            check_row(
                check_id=GSB_CHECK_ID,
                name=GSB_CHECK_NAME,
                status=SKIPPED,
                source="webcheck",
                evidence=GSB_SKIP_NOTE,
            )
        )
        return result

    cleaned: list[str] = []
    seen: set[str] = set()
    for u in urls:
        u = (u or "").strip()
        if not u or u in seen:
            continue
        seen.add(u)
        cleaned.append(u)
    if not cleaned:
        result.notes.append("Safe Browsing check skipped: no in-scope URLs")
        result.checks.append(
            check_row(
                check_id=GSB_CHECK_ID,
                name=GSB_CHECK_NAME,
                status=SKIPPED,
                source="webcheck",
                evidence="no in-scope URLs",
            )
        )
        return result

    body = {
        "client": {"clientId": "attestra", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": list(GSB_THREAT_TYPES),
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in cleaned],
        },
    }

    # Log only that a lookup ran — never the key, never the keyed URL.
    log.info("Safe Browsing lookup for %d URL(s)", len(cleaned))

    try:
        data = (post_fn or _default_post)(body, key)
    except Exception as exc:  # noqa: BLE001 - turn into scan note
        note = _safe_note(f"Safe Browsing check failed: {exc}", key)
        # Belt-and-braces: ensure key never leaks via str(exc).
        note = mask_secret(note, key)
        result.notes.append(note)
        result.checks.append(
            check_row(
                check_id=GSB_CHECK_ID,
                name=GSB_CHECK_NAME,
                status=SKIPPED,
                source="webcheck",
                evidence=note,
            )
        )
        return result

    matches = data.get("matches") if isinstance(data, dict) else None
    if not isinstance(matches, list):
        matches = []
    # Only treat known threat types as hits.
    hits = [
        m
        for m in matches
        if isinstance(m, dict) and str(m.get("threatType") or "").strip().upper() in GSB_THREAT_TYPES
    ]

    location = cleaned[0]
    if hits:
        finding = _finding_for_matches(hits, location)
        # Never embed the API key in finding text.
        for field_name in ("description", "recommendation", "title", "location"):
            finding[field_name] = mask_secret(str(finding.get(field_name) or ""), key)
        result.findings.append(finding)
        result.checks.append(
            check_row(
                check_id=GSB_CHECK_ID,
                name=GSB_CHECK_NAME,
                status=FAILED,
                source="webcheck",
                evidence=finding["title"],
            )
        )
    else:
        result.checks.append(
            check_row(
                check_id=GSB_CHECK_ID,
                name=GSB_CHECK_NAME,
                status=PASSED,
                source="webcheck",
            )
        )
    return result
