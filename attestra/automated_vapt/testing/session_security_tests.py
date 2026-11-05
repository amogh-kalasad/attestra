"""Session cookie and JWT structure observations for Elite automated security testing."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from attestra.automated_vapt.testing._http import (
    clear_cookies,
    find_jwt_candidates,
    inspect_jwt_structure,
    login_response,
    observe_cookie_flags,
)

# @lat: [[architecture#Elite automated security testing#Authz test modules]]

_SESSION_NAME_HINTS = frozenset(
    {
        "mock_session",
        "session",
        "sessionid",
        "sess",
        "sessid",
        "sid",
        "jsessionid",
        "phpsessid",
        "aspxauth",
        "auth",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "jwt",
        "connect.sid",
    }
)


def _is_session_like(name: str) -> bool:
    n = (name or "").strip().lower()
    if n in _SESSION_NAME_HINTS:
        return True
    return "session" in n or n.endswith("sess") or n.startswith("sess")


def run(client, base_url: str, **_kwargs) -> dict[str, Any]:
    """Observe session cookies, flag hygiene, and JWT header structure when present.

    Non-destructive: login once, inspect Set-Cookie / jar, decode JWT headers only.
    Does not forge tokens, rotate sessions against production, or force invalidation.
    """
    clear_cookies(client)
    resp = login_response(client, base_url, "viewer", "viewer-pass")
    login_status = int(resp.status_code)
    header_map = {str(k): str(v) for k, v in getattr(resp, "headers", {}).items()}
    cookie_flags = observe_cookie_flags(header_map)

    cookies: dict[str, str] = {}
    jar = getattr(client, "cookies", None)
    if jar is not None:
        try:
            cookies = {str(k): str(v) for k, v in dict(jar).items()}
        except Exception:
            cookies = {}

    has_session = any(_is_session_like(k) for k in cookies) or any(
        _is_session_like(str(row.get("name") or "")) for row in cookie_flags
    )

    scheme = (urlsplit(base_url).scheme or "").lower()
    https = scheme == "https"
    missing_httponly: list[str] = []
    missing_secure_https: list[str] = []
    missing_samesite: list[str] = []
    for row in cookie_flags:
        name = str(row.get("name") or "")
        if not _is_session_like(name):
            continue
        if not row.get("httponly"):
            missing_httponly.append(name)
        if https and not row.get("secure"):
            missing_secure_https.append(name)
        if not row.get("samesite"):
            missing_samesite.append(name)

    jwt_texts = [getattr(resp, "text", "") or ""]
    jwt_texts.extend(f"{k}={v}" for k, v in cookies.items())
    jwt_texts.extend(str(v) for v in header_map.values())
    jwt_tokens = find_jwt_candidates(*jwt_texts)
    jwt_inspections = [inspect_jwt_structure(t) for t in jwt_tokens[:5]]
    alg_none = any(bool(j.get("alg_none")) for j in jwt_inspections)

    finding_candidate = bool(missing_httponly) or bool(missing_secure_https) or alg_none
    return {
        "test_id": "SESSION",
        "category": "session",
        "observations": {
            "login_status": login_status,
            "has_session_cookie": has_session,
            "cookie_names": sorted(cookies.keys()),
            "cookie_flags": cookie_flags,
            "missing_httponly": missing_httponly,
            "missing_secure_on_https": missing_secure_https,
            "missing_samesite": missing_samesite,
            "https_target": https,
            "jwt_present": bool(jwt_tokens),
            "jwt_inspections": jwt_inspections,
            "jwt_alg_none": alg_none,
        },
        "finding_candidate": finding_candidate,
        "evidence_hints": ["POST /login Set-Cookie / JWT structure"],
    }
