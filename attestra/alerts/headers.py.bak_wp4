"""Compare security headers between two saved scan results (no new network)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Header names tracked for change alerts (lowercase).
SECURITY_HEADERS: tuple[str, ...] = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "feature-policy",
    "x-xss-protection",
)

# Check id → header name for older reports that only stored checks/findings.
_CHECK_TO_HEADER: dict[str, str] = {
    "hsts-present": "strict-transport-security",
    "x-content-type-options": "x-content-type-options",
    "referrer-policy": "referrer-policy",
    "x-xss-protection": "x-xss-protection",
    "expect-ct": "expect-ct",
    "10035": "strict-transport-security",
    "10038": "content-security-policy",
    "10021": "x-content-type-options",
    "10020": "x-frame-options",
    "10016": "x-xss-protection",
    "10063": "permissions-policy",
}


def snapshot_from_headers(headers: dict[str, str] | None) -> dict[str, str]:
    """Build a name→value map from a response header dict (keys lowercased)."""
    out: dict[str, str] = {}
    if not headers:
        return out
    lower = {str(k).lower(): str(v).strip() for k, v in headers.items()}
    for name in SECURITY_HEADERS:
        val = lower.get(name, "")
        if val:
            out[name] = val
    return out


def snapshot_from_report(doc: dict[str, Any] | None) -> dict[str, str]:
    """Extract a security-header snapshot from a saved webcheck/ZAP-style report."""
    if not isinstance(doc, dict):
        return {}
    raw = doc.get("headers")
    if isinstance(raw, dict) and raw:
        return snapshot_from_headers(raw)
    # Older reports: rebuild from checks (status + evidence) and findings.
    out: dict[str, str] = {}
    for row in doc.get("checks") or []:
        if not isinstance(row, dict):
            continue
        cid = str(row.get("id") or "")
        header = _CHECK_TO_HEADER.get(cid)
        if not header:
            # CSP analysis rows share the content-security-policy header.
            if cid.startswith("csp") or "content-security-policy" in cid:
                header = "content-security-policy"
            else:
                continue
        status = str(row.get("status") or "")
        evidence = str(row.get("evidence") or "").strip()
        if status == "passed":
            # Present and acceptable; value may be unknown.
            out.setdefault(header, evidence or "(present)")
        elif status == "failed":
            # Missing or weak — keep evidence when it looks like a header value.
            if evidence and evidence.lower() not in ("(missing)", "missing"):
                out[header] = evidence[:500]
            else:
                out.pop(header, None)
                out.setdefault(f"{header}__status", "missing")
    # Findings: id often matches the check / header name.
    for f in doc.get("findings") or []:
        if not isinstance(f, dict):
            continue
        fid = str(f.get("id") or f.get("variant") or "")
        header = _CHECK_TO_HEADER.get(fid)
        if not header and ("content-security-policy" in fid or fid.startswith("csp")):
            header = "content-security-policy"
        if not header:
            continue
        desc = str(f.get("description") or f.get("evidence") or "")[:500]
        if header not in out and desc:
            out[f"{header}__finding"] = desc
    return out


def load_report(path: str | Path | None) -> dict[str, Any] | None:
    if not path:
        return None
    try:
        p = Path(path)
        if not p.is_file():
            return None
        doc = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        return doc if isinstance(doc, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def diff_headers(previous: dict[str, str], current: dict[str, str]) -> list[dict[str, str]]:
    """Return changes: added, removed, or value changed. Each item has name/before/after."""
    keys = sorted(set(previous) | set(current))
    changes: list[dict[str, str]] = []
    for key in keys:
        # Internal status/finding markers only matter when the real header is absent.
        if key.endswith("__status") or key.endswith("__finding"):
            base = key.rsplit("__", 1)[0]
            if base in previous or base in current:
                continue
        before = previous.get(key, "")
        after = current.get(key, "")
        if before == after:
            continue
        name = key.split("__", 1)[0]
        changes.append({"name": name, "before": before or "(absent)", "after": after or "(absent)"})
    # Deduplicate by header name (prefer real value rows over markers).
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for ch in changes:
        if ch["name"] in seen:
            continue
        seen.add(ch["name"])
        out.append(ch)
    return out
