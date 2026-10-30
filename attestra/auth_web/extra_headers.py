"""Optional, non-secret extra request headers on an auth credential profile.

Some sites check more than the session token: a tenant / portal / API-version
header the browser app always sends (e.g. ``x-tenant-id: abc``). A profile can
list those as plain ``Name: value`` lines; they ride alongside the session
header/cookie on the pre-scan login check, the ZAP Replacer rules (target host
only), the Nuclei authx secret file, and form / OTP login requests.

These values are stored in clear text (``AuthCredentialProfile.extra_headers``):
anything secret belongs in the encrypted profile secret instead. Session-bearing
and hop-by-hop headers are therefore rejected here.
"""
# @lat: [[architecture#Authenticated website testing]]

from __future__ import annotations

import re

MAX_LINES = 10
MAX_NAME_LEN = 100
MAX_VALUE_LEN = 1000
MAX_TEXT_LEN = 4000

# RFC 7230 "token" characters for a header field name.
_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
# Headers that must never come from this clear-text field (session material,
# or headers the HTTP client / scanner owns).
FORBIDDEN_NAMES = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
    }
)


class ExtraHeadersError(ValueError):
    """The extra headers text is not valid."""


def parse_extra_headers(text: str | None, *, own_header_name: str | None = None) -> list[tuple[str, str]]:
    """Parse ``Name: value`` lines into an ordered list of (name, value).

    Blank lines and ``#`` comment lines are ignored. Raises
    :class:`ExtraHeadersError` with a user-facing (value-free) message.
    ``own_header_name`` is the profile's session header (rejected as a duplicate).
    """
    raw = text or ""
    if len(raw) > MAX_TEXT_LEN:
        raise ExtraHeadersError(f"extra headers must be at most {MAX_TEXT_LEN} characters")
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    own = (own_header_name or "").strip().lower()
    # splitlines() also splits on bare CR, so a value can never smuggle CR/LF.
    lines = [ln for ln in raw.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if len(lines) > MAX_LINES:
        raise ExtraHeadersError(f"at most {MAX_LINES} extra headers are allowed")
    for n, line in enumerate(lines, start=1):
        if ":" not in line:
            raise ExtraHeadersError(f"extra header line {n} must look like 'Name: value'")
        name, value = line.split(":", 1)
        name = name.strip()
        value = value.strip()
        if not name:
            raise ExtraHeadersError(f"extra header line {n} has no header name")
        if len(name) > MAX_NAME_LEN or not _NAME_RE.match(name):
            raise ExtraHeadersError(
                f"extra header line {n}: invalid header name (letters, digits and !#$%&'*+-.^_`|~ only)"
            )
        if any(c in value for c in ("\r", "\n", "\x00")) or any(ord(c) < 0x20 and c != "\t" for c in value):
            raise ExtraHeadersError(f"extra header '{name}': value contains control characters")
        if len(value) > MAX_VALUE_LEN:
            raise ExtraHeadersError(f"extra header '{name}': value must be at most {MAX_VALUE_LEN} characters")
        low = name.lower()
        if low in FORBIDDEN_NAMES:
            raise ExtraHeadersError(
                f"extra header '{name}' is not allowed here; put tokens/cookies in the Secret field"
            )
        if own and low == own:
            raise ExtraHeadersError(f"extra header '{name}' duplicates the profile's session header")
        if low in seen:
            raise ExtraHeadersError(f"extra header '{name}' is listed more than once")
        seen.add(low)
        out.append((name, value))
    return out


def normalize_extra_headers(text: str | None, *, own_header_name: str | None = None) -> str:
    """Validate and return the canonical stored text (``Name: value`` per line)."""
    return "\n".join(f"{k}: {v}" for k, v in parse_extra_headers(text, own_header_name=own_header_name))


def merge_extra_headers(headers: dict[str, str], extra: list[tuple[str, str]]) -> dict[str, str]:
    """Return ``headers`` plus ``extra``; existing (session) headers always win."""
    out = dict(headers)
    present = {k.lower() for k in out}
    for k, v in extra:
        if k.lower() not in present:
            out[k] = v
            present.add(k.lower())
    return out


def own_header_name(method: str | None, cfg: dict | None) -> str | None:
    """The session header name a profile injects itself (``header`` method only)."""
    if (method or "").strip().lower() != "header":
        return None
    cfg = cfg or {}
    return str(cfg.get("header_name") or cfg.get("name") or "Authorization").strip() or "Authorization"
