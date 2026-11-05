"""Evidence helpers that detect header presence contradicting scanner claims."""

from __future__ import annotations

import re

_HSTS_PRESENT_RE = re.compile(
    r"(?is)strict-transport-security\s*:[^\n\r]*max-age\s*=\s*\d+",
)

_PERMISSIONS_POLICY_PRESENT_RE = re.compile(
    r"(?is)permissions-policy\s*:",
)


def response_has_header(text: str, header_name: str) -> bool:
    """Case-insensitive header present in raw HTTP response or evidence blob."""
    if not text or not header_name:
        return False
    name = re.escape(header_name.strip())
    return bool(
        re.search(rf"(?im)^[ \t]*{name}\s*:", text)
        or re.search(rf"(?i)(?:^|[\r\n;,\s]){name}\s*:", text)
    )


def hsts_present_in_evidence(texts: list[str]) -> bool:
    """True when any blob shows Strict-Transport-Security with max-age."""
    for raw in texts or []:
        if raw and _HSTS_PRESENT_RE.search(raw):
            return True
    return False


def permissions_policy_present_in_evidence(texts: list[str]) -> bool:
    """True when any blob shows a Permissions-Policy header line."""
    for raw in texts or []:
        if raw and _PERMISSIONS_POLICY_PRESENT_RE.search(raw):
            return True
    return False


def finding_claims_header_missing(title: str, description: str = "") -> str | None:
    """Return 'hsts' or 'permissions_policy' when title/desc claim the header is missing."""
    blob = f"{title or ''}\n{description or ''}"
    missing = bool(re.search(r"(?i)not\s+set|missing|absent|not\s+present", blob))
    if not missing:
        return None
    if re.search(r"(?i)hsts|strict-transport-security", blob):
        return "hsts"
    if re.search(r"(?i)permissions[-\s]?policy", blob):
        return "permissions_policy"
    return None
