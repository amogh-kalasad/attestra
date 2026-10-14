"""Mask secrets and PANs in captured evidence before hash/store."""
# @lat: [[findings#Evidence]]

from __future__ import annotations

import re
from typing import Any

# 13–19 digit runs (optional spaces/dashes); validated with Luhn before masking.
_PAN_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# Require separator check in _is_phone_shaped so bare digit runs are not phones.
_PHONE = re.compile(r"(?<!\d)(?:\+?\d[\d\s().-]{6,}\d)(?!\d)")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_AUTH_HEADER = re.compile(r"(?im)^(authorization\s*[:=]\s*)(.+)$")
_COOKIE_HEADER = re.compile(r"(?im)^(cookie\s*[:=]\s*)(.+)$")
_PASSWORD_FIELD = re.compile(
    r'(?i)((?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*)([^\s&;"\']+)'
)
_BEARER = re.compile(r"(?i)\b(bearer\s+)([A-Za-z0-9._\-+=/]{8,})")
_API_KEY_INLINE = re.compile(r"(?i)\b((?:api[_-]?key|token|secret)[=:]\s*)([A-Za-z0-9_\-]{8,})")


def _is_phone_shaped(s: str) -> bool:
    return bool(re.search(r"[\s().+-]", s)) and len(re.sub(r"\D", "", s)) <= 15


def luhn_ok(digits: str) -> bool:
    nums = [int(c) for c in digits if c.isdigit()]
    if len(nums) < 13 or len(nums) > 19:
        return False
    checksum = 0
    parity = len(nums) % 2
    for i, n in enumerate(nums):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        checksum += n
    return checksum % 10 == 0


def _mask_pan_digits(digits: str) -> str:
    keep_first, keep_last = 6, 4
    if len(digits) <= keep_first + keep_last:
        return "*" * len(digits)
    return digits[:keep_first] + ("*" * (len(digits) - keep_first - keep_last)) + digits[-keep_last:]


def mask_bytes(data: bytes, content_type: str = "") -> tuple[bytes, dict[str, Any]]:
    """Return (masked_bytes, report) with counts of each masking category applied."""
    report: dict[str, Any] = {
        "content_type": content_type or "application/octet-stream",
        "pan": 0,
        "email": 0,
        "phone": 0,
        "jwt": 0,
        "auth_header": 0,
        "cookie_header": 0,
        "password": 0,
        "api_key": 0,
    }
    ct = (content_type or "").lower()
    if b"\x00" in data[:256] and not any(x in ct for x in ("json", "text", "xml", "html", "javascript", "csv")):
        report["skipped"] = "binary"
        return data, report

    try:
        text = data.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        try:
            text = data.decode("latin-1")
            encoding = "latin-1"
        except Exception:
            report["skipped"] = "undecodable"
            return data, report

    def pan_repl(m: re.Match[str]) -> str:
        raw = m.group(0)
        digits = re.sub(r"\D", "", raw)
        if not luhn_ok(digits):
            return raw
        report["pan"] += 1
        masked = _mask_pan_digits(digits)
        out: list[str] = []
        di = 0
        for ch in raw:
            if ch.isdigit():
                out.append(masked[di])
                di += 1
            else:
                out.append(ch)
        return "".join(out)

    text = _PAN_CANDIDATE.sub(pan_repl, text)

    def bump(key: str, repl: str):
        def _r(m: re.Match[str]) -> str:
            report[key] += 1
            if m.lastindex and m.lastindex >= 1 and "{1}" in repl:
                return m.group(1) + repl.replace("{1}", "")
            return m.expand(repl) if "\\" in repl else (m.group(1) + repl if m.lastindex else repl)

        return _r

    text = _AUTH_HEADER.sub(bump("auth_header", "[REDACTED]"), text)
    text = _COOKIE_HEADER.sub(bump("cookie_header", "[REDACTED]"), text)
    text = _PASSWORD_FIELD.sub(bump("password", "[REDACTED]"), text)
    text = _BEARER.sub(bump("api_key", "[REDACTED]"), text)
    text = _API_KEY_INLINE.sub(bump("api_key", "[REDACTED]"), text)

    def simple(key: str, token: str):
        def _r(_m: re.Match[str]) -> str:
            report[key] += 1
            return token

        return _r

    text = _JWT.sub(simple("jwt", "[REDACTED_JWT]"), text)
    text = _EMAIL.sub(simple("email", "[REDACTED_EMAIL]"), text)

    def phone_repl(m: re.Match[str]) -> str:
        raw = m.group(0)
        if not _is_phone_shaped(raw):
            return raw
        report["phone"] += 1
        return "[REDACTED_PHONE]"

    text = _PHONE.sub(phone_repl, text)

    return text.encode(encoding), report
