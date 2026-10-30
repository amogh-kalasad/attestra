"""Optional, ENCRYPTED extra cookies on an auth credential profile.

Some APIs check more than the session header: e.g. a ``Bearer`` access token AND a
``refreshToken`` cookie that carries the server-side session id. A profile can
store such cookies as ``name=value; name2=value2`` (or one ``name=value`` per
line). They are merged into a single ``Cookie`` header together with any
cookie-method session cookie and ride on the pre-scan login check, the ZAP
Replacer rules (target host only), the Nuclei authx secret file, and form / OTP
login requests.

Unlike Extra Headers, cookie values are treated as secrets: the text is stored
only through the Fernet credential store (``AuthCredentialProfile.extra_cookies_ref``),
never shown back, and every value is added to the scanner log redaction list.
Only cookie NAMES are kept in clear (``extra_cookie_names``) for the UI / audit.
"""
# @lat: [[architecture#Authenticated website testing]]

from __future__ import annotations

import re

MAX_COOKIES = 10
MAX_NAME_LEN = 100
MAX_VALUE_LEN = 4096
MAX_TEXT_LEN = 16000

# RFC 6265 cookie-name is an RFC 7230 token.
_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_COOKIE_PREFIX_RE = re.compile(r"(?i)^\s*cookie\s*:\s*")


class ExtraCookiesError(ValueError):
    """The extra cookies text is not valid (message never contains a value)."""


def parse_extra_cookies(text: str | None) -> list[tuple[str, str]]:
    """Parse ``name=value`` pairs separated by ``;`` and/or new lines.

    A leading ``Cookie:`` on a line is tolerated (pasted from DevTools). Blank
    parts and ``#`` comment lines are ignored. ``;`` / CR / LF are separators, so
    a value can never contain them. Raises :class:`ExtraCookiesError` with a
    value-free message.
    """
    raw = text or ""
    if len(raw) > MAX_TEXT_LEN:
        raise ExtraCookiesError(f"extra cookies must be at most {MAX_TEXT_LEN} characters")
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        if line.strip().startswith("#"):
            continue
        line = _COOKIE_PREFIX_RE.sub("", line, count=1)
        for part in line.split(";"):
            part = part.strip()
            if not part:
                continue
            if "=" not in part:
                raise ExtraCookiesError(f"extra cookie #{len(out) + 1} must look like 'name=value'")
            name, value = part.split("=", 1)
            name = name.strip()
            value = value.strip()
            if not name:
                raise ExtraCookiesError(f"extra cookie #{len(out) + 1} has no cookie name")
            if len(name) > MAX_NAME_LEN or not _NAME_RE.match(name):
                raise ExtraCookiesError(
                    f"extra cookie #{len(out) + 1}: invalid cookie name (letters, digits and !#$%&'*+-.^_`|~ only)"
                )
            if not value:
                raise ExtraCookiesError(f"extra cookie '{name}' has an empty value")
            if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
                raise ExtraCookiesError(f"extra cookie '{name}': value contains control characters")
            if len(value) > MAX_VALUE_LEN:
                raise ExtraCookiesError(f"extra cookie '{name}': value must be at most {MAX_VALUE_LEN} characters")
            if name in seen:
                raise ExtraCookiesError(f"extra cookie '{name}' is listed more than once")
            seen.add(name)
            out.append((name, value))
            if len(out) > MAX_COOKIES:
                raise ExtraCookiesError(f"at most {MAX_COOKIES} extra cookies are allowed")
    return out


def normalize_extra_cookies(text: str | None) -> str:
    """Validate and return the canonical secret text (``name=value; name2=value2``)."""
    return "; ".join(f"{k}={v}" for k, v in parse_extra_cookies(text))


def cookie_names(pairs: list[tuple[str, str]]) -> list[str]:
    return [k for k, _ in pairs]


def names_text(pairs: list[tuple[str, str]]) -> str:
    """Comma-separated cookie NAMES (safe to store in clear / show in UI)."""
    return ", ".join(cookie_names(pairs))


def merge_cookies(cookies: dict[str, str], extra: list[tuple[str, str]]) -> dict[str, str]:
    """Return ``cookies`` plus ``extra``; existing (session) cookies always win."""
    out = dict(cookies)
    for k, v in extra:
        if k not in out:
            out[k] = v
    return out


def own_cookie_name(method: str | None, cfg: dict | None) -> str | None:
    """The single session cookie name a ``cookie`` profile injects itself (if named)."""
    if (method or "").strip().lower() != "cookie":
        return None
    cfg = cfg or {}
    name = str(cfg.get("cookie_name") or cfg.get("name") or "").strip()
    return name or None
