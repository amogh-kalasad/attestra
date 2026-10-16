"""Import a saved Mozilla HTTP Observatory JSON file (upload only, no live API).

Supports the classic ``tests`` map and the newer ``scan`` + ``tests`` shapes.
Failed tests become findings. Variants match webcheck header ids where possible
so the same issue merges instead of doubling.
"""
# @lat: [[import-pipeline#Supported formats]]

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from attestra.importers.base import NormalizedFinding

# Map Observatory test name → (variant, title, severity, cwe, recommendation).
# Variants aligned with webcheck where the same header is checked.
_TEST_MAP: dict[str, tuple[str, str, str, int, str]] = {
    "content-security-policy": (
        "content-security-policy",
        "CSP: Content-Security-Policy issues (Observatory)",
        "medium",
        693,
        "Tighten Content-Security-Policy; avoid unsafe-inline/unsafe-eval and wildcards.",
    ),
    "strict-transport-security": (
        "hsts-present",
        "HSTS header missing or weak (Observatory)",
        "medium",
        319,
        "Send Strict-Transport-Security with a positive max-age on HTTPS responses.",
    ),
    "x-content-type-options": (
        "x-content-type-options",
        "X-Content-Type-Options is missing or not nosniff",
        "low",
        693,
        "Set X-Content-Type-Options: nosniff on all responses.",
    ),
    "x-frame-options": (
        "x-frame-options",
        "X-Frame-Options / frame protection missing (Observatory)",
        "medium",
        693,
        "Set X-Frame-Options or a CSP frame-ancestors directive.",
    ),
    "x-xss-protection": (
        "x-xss-protection",
        "X-XSS-Protection legacy value set",
        "info",
        693,
        "Remove X-XSS-Protection; rely on a strong Content-Security-Policy instead.",
    ),
    "referrer-policy": (
        "referrer-policy",
        "Referrer-Policy is not a strict value",
        "low",
        200,
        "Set Referrer-Policy to no-referrer or same-origin.",
    ),
    "redirection": (
        "http-no-redirect",
        "Plain HTTP does not redirect to HTTPS",
        "medium",
        319,
        "Respond to HTTP with a redirect to HTTPS.",
    ),
    "cookies": (
        "cookies",
        "Cookie flags incomplete (Observatory)",
        "low",
        614,
        "Set Secure, HttpOnly and SameSite on session cookies.",
    ),
    "cross-origin-resource-sharing": (
        "cors",
        "CORS misconfiguration (Observatory)",
        "medium",
        942,
        "Restrict Access-Control-Allow-Origin to trusted origins.",
    ),
    "subresource-integrity": (
        "sri",
        "Subresource Integrity missing (Observatory)",
        "info",
        353,
        "Add integrity attributes to third-party script and style tags.",
    ),
}


def _host_from_doc(doc: dict[str, Any]) -> str:
    for key in ("host", "hostname", "domain"):
        val = doc.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip().lower().split("/")[0]
    scan = doc.get("scan")
    if isinstance(scan, dict):
        for key in ("host", "hostname"):
            val = scan.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip().lower().split("/")[0]
    # details_url?host=
    details = doc.get("details_url") or (scan.get("details_url") if isinstance(scan, dict) else "")
    if isinstance(details, str) and "host=" in details:
        part = details.split("host=", 1)[1]
        return part.split("&", 1)[0].strip().lower()
    return ""


def _location(host: str) -> str:
    if not host:
        return ""
    if host.startswith("http://") or host.startswith("https://"):
        parts = urlsplit(host)
        return f"{parts.scheme}://{parts.hostname or host}/"
    return f"https://{host}/"


def _tests_map(doc: dict[str, Any]) -> dict[str, Any]:
    tests = doc.get("tests")
    if isinstance(tests, dict):
        return tests
    return {}


def parse(raw: bytes) -> list[NormalizedFinding]:
    doc = json.loads(raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw)
    if not isinstance(doc, dict):
        return []
    host = _host_from_doc(doc)
    location = _location(host)
    out: list[NormalizedFinding] = []
    for name, test in _tests_map(doc).items():
        if not isinstance(test, dict):
            continue
        # Only failed tests become findings.
        if test.get("pass") is True:
            continue
        mapped = _TEST_MAP.get(str(name))
        if mapped:
            variant, title, severity, cwe, rec = mapped
        else:
            variant = str(name)
            title = f"Observatory: {name} failed"
            severity = "low"
            cwe = 693
            rec = "Review the Mozilla HTTP Observatory guidance for this test."
        desc_parts = [
            str(test.get("score_description") or test.get("scoreDescription") or "").strip(),
            f"result={test.get('result')}" if test.get("result") else "",
            f"expectation={test.get('expectation')}" if test.get("expectation") else "",
        ]
        description = "; ".join(p for p in desc_parts if p) or f"Observatory test '{name}' did not pass."
        out.append(
            NormalizedFinding(
                tool="observatory",
                rule_id=f"observatory/{name}",
                variant=variant,
                title=title,
                severity=severity,
                location=location,
                description=description,
                recommendation=rec,
                cwe=cwe,
            )
        )
    return out


def checks_from_observatory(raw: bytes | str) -> list[dict[str, str]]:
    """C5-compatible check rows: Observatory pass → passed, fail → failed."""
    from attestra.checks import FAILED, PASSED, check_row

    if isinstance(raw, str):
        raw_b = raw.encode("utf-8")
    else:
        raw_b = raw
    try:
        doc = json.loads(raw_b.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return []
    if not isinstance(doc, dict):
        return []
    rows: list[dict[str, str]] = []
    for name, test in _tests_map(doc).items():
        if not isinstance(test, dict):
            continue
        mapped = _TEST_MAP.get(str(name))
        label = mapped[1] if mapped else f"Observatory: {name}"
        ok = test.get("pass") is True
        rows.append(
            check_row(
                check_id=f"observatory/{name}",
                name=label,
                status=PASSED if ok else FAILED,
                source="observatory",
                evidence=str(test.get("result") or test.get("score_description") or ""),
            )
        )
    return rows
