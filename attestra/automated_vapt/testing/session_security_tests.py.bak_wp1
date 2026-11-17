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
from attestra.automated_vapt.testing._session import (
    SKIP_NO_AUTH_SESSION,
    probe_urls,
    request_auth,
    resolve_mode,
    skip_result,
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


def _flag_issues(cookie_flags: list[dict[str, Any]], https: bool) -> tuple[list[str], list[str], list[str]]:
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
    return missing_httponly, missing_secure_https, missing_samesite


def _run_with_session(client, base_url: str, auth: Any, **kwargs) -> dict[str, Any]:
    """Inspect engagement session material (JWT / Set-Cookie) — no lab /login."""
    header_map = {str(k): str(v) for k, v in dict(getattr(auth, "headers", None) or {}).items()}
    # Cookie names only — never values.
    cookie_names: list[str] = []
    for k, v in header_map.items():
        if k.lower() == "cookie":
            for part in str(v).split(";"):
                name = part.split("=", 1)[0].strip()
                if name:
                    cookie_names.append(name)

    # Optional: hit a page (or profile verify_url) and observe Set-Cookie flags.
    verify = ""
    cfg = getattr(auth, "cfg", None) or {}
    if isinstance(cfg, dict):
        verify = str(cfg.get("verify_url") or cfg.get("success_url") or "").strip()
    urls = [verify] if verify else []
    urls.extend(probe_urls(base_url, kwargs, api=False, limit=3))
    cookie_flags: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    for url in urls:
        if not url:
            continue
        try:
            pair = request_auth(client, "GET", url, auth, base_url)
        except Exception:
            continue
        for row in observe_cookie_flags(pair.response_headers or {}):
            name = str(row.get("name") or "")
            if name and name not in seen_names:
                seen_names.add(name)
                cookie_flags.append(row)

    has_session = bool(cookie_names) or any(_is_session_like(str(r.get("name") or "")) for r in cookie_flags)
    has_session = has_session or any(k.lower() == "authorization" for k in header_map)
    scheme = (urlsplit(base_url).scheme or "").lower()
    https = scheme == "https"
    missing_httponly, missing_secure_https, missing_samesite = _flag_issues(cookie_flags, https)

    # JWT structure from in-memory session headers only (alg / typ / claim keys).
    jwt_texts = [f"{k}={v}" for k, v in header_map.items()]
    jwt_tokens = find_jwt_candidates(*jwt_texts)
    jwt_inspections = [inspect_jwt_structure(t) for t in jwt_tokens[:5]]
    alg_none = any(bool(j.get("alg_none")) for j in jwt_inspections)

    # Only raise cookie-flag findings when we actually observed Set-Cookie (not just a Cookie header).
    finding_candidate = bool(missing_httponly) or bool(missing_secure_https) or alg_none
    return {
        "test_id": "SESSION",
        "category": "session",
        "observations": {
            "mode": "engagement_session",
            "login_status": None,
            "has_session_cookie": has_session,
            "cookie_names": sorted(set(cookie_names) | seen_names),
            "cookie_flags": cookie_flags,
            "missing_httponly": missing_httponly,
            "missing_secure_on_https": missing_secure_https,
            "missing_samesite": missing_samesite,
            "https_target": https,
            "jwt_present": bool(jwt_tokens),
            "jwt_inspections": jwt_inspections,
            "jwt_alg_none": alg_none,
            "injected_header_names": sorted(header_map.keys()),
        },
        "finding_candidate": finding_candidate,
        "evidence_hints": ["engagement session JWT / Set-Cookie structure"],
    }


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    """Observe session cookies, flag hygiene, and JWT header structure when present.

    Non-destructive: login once, inspect Set-Cookie / jar, decode JWT headers only.
    Does not forge tokens, rotate sessions against production, or force invalidation.
    """
    mode, auth = resolve_mode(client, kwargs)
    if mode == "engagement":
        return _run_with_session(client, base_url, auth, **kwargs)
    if mode == "skip":
        return skip_result(
            "SESSION",
            "session",
            SKIP_NO_AUTH_SESSION,
            "engagement login profile not ready; skipped lab POST /login session probes",
        )

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
    missing_httponly, missing_secure_https, missing_samesite = _flag_issues(cookie_flags, https)

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
