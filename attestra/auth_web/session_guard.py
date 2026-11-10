"""Mid-scan session guard: detect authentication loss, re-login from the profile, or block.

Pre-flight :func:`attestra.auth_web.scan_auth.verify_logged_in` only proves the session was
alive before the scan started. This module keeps checking during ZAP, Nuclei and automated
VAPT runs and, when the session dies, tries a bounded number of re-logins using the same
``AuthCredentialProfile`` material (form / otp login, or an opt-in ``refresh_url`` for
static header / cookie profiles, including an optional JSON refresh endpoint). When recovery
fails the affected work is reported as **blocked** — never as passed or as authenticated coverage.

Secrets stay inside closures / the per-scan secret directory; :meth:`SessionGuard.public`
and :meth:`SessionGuard.note` are value-free and safe for ``ScanRun.auth_note``, result JSON
and reports.

Environment (all optional):

* ``ATTESTRA_AUTH_MIDSCAN_ENABLED`` — ``0`` restores pre-flight-only behaviour (default on).
* ``ATTESTRA_AUTH_RELOGIN_MAX`` — re-login attempts per scan (default 2).
* ``ATTESTRA_AUTH_HEARTBEAT_S`` — liveness poll interval for ZAP / Nuclei chunking (default 120).
* ``ATTESTRA_AUTH_RELOGIN_MIN_INTERVAL_S`` — minimum spacing between re-login attempts (default 5).
"""
# @lat: [[runner#Authenticated scan wiring#Mid-scan session guard]]

from __future__ import annotations

import json
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from attestra.auth_web import extra_cookies as xc
from attestra.auth_web import extra_headers as xh
from attestra.auth_web import scan_auth as sa

# Prefix used in auth notes so checklist / reports can recognise an unrecovered loss.
AUTH_LOSS_MARKER = "auth-loss:"
AUTH_RECOVERED_MARKER = "auth-recovered:"
SKIP_REASON_AUTH_LOST = "auth_lost"

_TRUE = ("1", "true", "yes", "on")
_FALSE = ("0", "false", "no", "off")

_EXPIRED_BODY_RE = re.compile(
    r"(?i)session[_\s-]?(?:has\s+)?expired|token[_\s-]?(?:has\s+)?expired|jwt\s+expired|"
    r"invalid[_\s-]?token|expired[_\s-]?token|not\s+authenticated|authentication\s+required|"
    r"login\s+required|unauthenticated|please\s+(?:log|sign)\s*in\s+again|"
    r"\"(?:error|code|status)\"\s*:\s*\"(?:unauthorized|unauthenticated|invalid_grant|invalid_token|"
    r"session_expired|token_expired|auth_required)\""
)
_LOGIN_PATH_RE = re.compile(
    r"(?i)/(?:login|signin|sign-in|log-in|logon|auth(?:enticate)?|sso|oauth2?/authorize|"
    r"account/login|session/new|users/sign_in|wp-login\.php)(?:[/?#]|$)"
)


# ------------------------------------------------------------------ configuration


def midscan_enabled() -> bool:
    """``ATTESTRA_AUTH_MIDSCAN_ENABLED``; unset or any truthy value enables the guard."""
    raw = os.environ.get("ATTESTRA_AUTH_MIDSCAN_ENABLED", "").strip().lower()
    if raw in _FALSE:
        return False
    return True


def relogin_max() -> int:
    """``ATTESTRA_AUTH_RELOGIN_MAX`` clamped to 0..10 (default 2)."""
    try:
        n = int(os.environ.get("ATTESTRA_AUTH_RELOGIN_MAX", "2"))
    except ValueError:
        n = 2
    return max(0, min(10, n))


def heartbeat_s() -> int:
    """``ATTESTRA_AUTH_HEARTBEAT_S`` clamped to >= 10 (default 120)."""
    try:
        n = int(os.environ.get("ATTESTRA_AUTH_HEARTBEAT_S", "120"))
    except ValueError:
        n = 120
    return max(10, n)


def relogin_min_interval_s() -> float:
    try:
        v = float(os.environ.get("ATTESTRA_AUTH_RELOGIN_MIN_INTERVAL_S", "5"))
    except ValueError:
        v = 5.0
    return max(0.0, v)


# ------------------------------------------------------------------ detection


def looks_expired(
    status: int | None,
    *,
    body: str = "",
    headers: dict[str, str] | None = None,
    cfg: dict[str, Any] | None = None,
) -> tuple[bool, str]:
    """Cheap per-response trigger: does this response look like the session died?

    A positive answer is only a *hint*; callers confirm with :func:`check_session_alive`
    (the profile's ``verify_url``) before acting. 403 alone is treated as authorization,
    not authentication, unless the body also carries an expiry marker.
    """
    hdrs = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    text = body or ""
    if status == 401:
        return True, "HTTP 401"
    if status in (301, 302, 303, 307, 308):
        loc = hdrs.get("location", "")
        if loc and _LOGIN_PATH_RE.search(loc.split("?", 1)[0]):
            return True, "redirect to login page"
    logged_out = str((cfg or {}).get("logged_out_indicator") or "").strip()
    if logged_out and text:
        try:
            if re.search(logged_out, text):
                return True, "logged-out indicator present"
        except re.error:
            pass
    if text and _EXPIRED_BODY_RE.search(text[:20_000]):
        if status is None or status >= 400 or '"error"' in text[:2000].lower() or len(text) < 4000:
            return True, "session-expired marker in body"
    if status == 403 and text and _EXPIRED_BODY_RE.search(text[:20_000]):
        return True, "HTTP 403 with expiry marker"
    return False, ""


def check_session_alive(
    cfg: dict[str, Any],
    headers: dict[str, str],
    cookies: dict[str, str],
    *,
    login_probe: sa.LoginProbe,
) -> tuple[bool, str]:
    """Authoritative liveness check: wraps :func:`scan_auth.verify_logged_in`, never raises."""
    try:
        return sa.verify_logged_in(cfg, headers, cookies, login_probe=login_probe)
    except Exception as exc:  # noqa: BLE001 - value-free
        return False, f"login check failed: {type(exc).__name__}"


# ------------------------------------------------------------------ JSON / cookie refresh config

REFRESH_WAF_NOTE = "refresh blocked by WAF/challenge"

_REFRESH_SECRET_KEYS = {
    "refresh_token",
    "refreshtoken",
    "access_token",
    "accesstoken",
    "refresh_secret",
    "cookie_value",
    "refresh_cookie_value",
    "refresh_cookie_secret",
}
_COOKIE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_JSON_PATH_PART_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_CHALLENGE_BODY_RE = re.compile(
    r"(?i)just\s+a\s+moment|cdn-cgi/challenge-platform|cf-browser-verification|"
    r"cf-error-code|attention required!|enable javascript and cookies to continue"
)

# Optional injectable: http_request(url, method=..., body=b"", headers={}, cookies={}) -> HttpReply
HttpRequest = Callable[..., Any]


def validate_refresh_apply_as(value: str | None, *, required: bool = False) -> str:
    """Return a normalised ``refresh_apply_as`` or raise ``ValueError`` (value-free)."""
    raw = (value or "").strip()
    if not raw:
        if required:
            raise ValueError("refresh_apply_as is required when refresh_token_json_path is set")
        return ""
    low = raw.lower()
    if low == "bearer":
        return "bearer"
    if low.startswith("header:") or low.startswith("cookie:"):
        kind, _, name = raw.partition(":")
        name = name.strip()
        if not name or not _HEADER_NAME_RE.fullmatch(name):
            raise ValueError("refresh_apply_as header/cookie name must be alphanumeric, '_' or '-'")
        return f"{kind.lower()}:{name}"
    raise ValueError("refresh_apply_as must be 'bearer', 'header:<Name>', or 'cookie:<Name>'")


def _refresh_cookie_names(raw: Any) -> list[str]:
    if raw is None or raw == "":
        return []
    if isinstance(raw, str):
        parts = [p.strip() for p in raw.replace(";", ",").split(",") if p.strip()]
    elif isinstance(raw, (list, tuple)):
        parts = [str(p).strip() for p in raw if str(p).strip()]
    else:
        raise ValueError("refresh_cookies must be a list of cookie names")
    names: list[str] = []
    for name in parts:
        if "=" in name:
            raise ValueError("refresh_cookies lists cookie names only; values belong in the encrypted store")
        if not _COOKIE_NAME_RE.fullmatch(name):
            raise ValueError("refresh_cookies names must be alphanumeric, '_' or '-'")
        if name not in names:
            names.append(name)
    if len(names) > 10:
        raise ValueError("refresh_cookies accepts at most 10 names")
    return names


def _refresh_headers_dict(raw: Any) -> dict[str, str]:
    if raw is None or raw == "" or raw == {}:
        return {}
    if isinstance(raw, str):
        try:
            pairs = xh.parse_extra_headers(raw)
        except xh.ExtraHeadersError as exc:
            raise ValueError(str(exc)) from exc
        return {k: v for k, v in pairs}
    if isinstance(raw, dict):
        out: dict[str, str] = {}
        for k, v in raw.items():
            name = str(k).strip()
            if not name or not _HEADER_NAME_RE.fullmatch(name):
                raise ValueError("refresh_headers names must be alphanumeric, '_' or '-'")
            out[name] = "" if v is None else str(v)
        if len(out) > 10:
            raise ValueError("refresh_headers accepts at most 10 headers")
        return out
    raise ValueError("refresh_headers must be an object of header names to values")


def _json_path_get(data: Any, path: str) -> Any:
    cur = data
    for part in path.split("."):
        part = part.strip()
        if not part or not _JSON_PATH_PART_RE.fullmatch(part):
            return None
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit():
            idx = int(part)
            if idx < 0 or idx >= len(cur):
                return None
            cur = cur[idx]
        else:
            return None
    return cur


def sanitize_refresh_config(cfg: dict[str, Any] | None) -> dict[str, Any]:
    """Validate optional refresh_* keys in profile config; return a shallow-cleaned copy.

    Cookie / token *values* are rejected — only names and non-secret request metadata belong
    in ``config_json``. Raises ``ValueError`` with a value-free message.
    """
    out = dict(cfg or {})
    for key in list(out):
        if str(key).strip().lower().replace("-", "_") in _REFRESH_SECRET_KEYS:
            raise ValueError("refresh token values must not be stored in config_json; use the encrypted cookie store")
    url = out.get("refresh_url")
    if url is not None:
        url_s = str(url).strip()
        out["refresh_url"] = url_s
        if url_s and not (url_s.startswith("https://") or url_s.startswith("http://")):
            raise ValueError("refresh_url must be an absolute http(s) URL")
    method = out.get("refresh_method")
    if method is not None and str(method).strip():
        m = str(method).strip().upper()
        if m not in ("GET", "POST", "PUT", "PATCH"):
            raise ValueError("refresh_method must be GET, POST, PUT or PATCH")
        out["refresh_method"] = m
    elif "refresh_method" in out:
        out.pop("refresh_method", None)
    body = out.get("refresh_body")
    if body is not None:
        if isinstance(body, str) and body.strip():
            try:
                body = json.loads(body)
            except ValueError as exc:
                raise ValueError("refresh_body must be a JSON object") from exc
        if body in ("", None):
            out.pop("refresh_body", None)
        elif not isinstance(body, dict):
            raise ValueError("refresh_body must be a JSON object")
        else:
            out["refresh_body"] = body
    ctype = out.get("refresh_content_type")
    if ctype is not None and str(ctype).strip():
        c = str(ctype).strip().lower()
        if c in ("application/json", "json"):
            c = "json"
        elif c in ("application/x-www-form-urlencoded", "form", "urlencoded"):
            c = "form"
        else:
            raise ValueError("refresh_content_type must be json or form")
        out["refresh_content_type"] = c
    elif "refresh_content_type" in out:
        out.pop("refresh_content_type", None)
    if "refresh_cookies" in out:
        names = _refresh_cookie_names(out.get("refresh_cookies"))
        if names:
            out["refresh_cookies"] = names
        else:
            out.pop("refresh_cookies", None)
    if "refresh_headers" in out:
        hdrs = _refresh_headers_dict(out.get("refresh_headers"))
        if hdrs:
            out["refresh_headers"] = hdrs
        else:
            out.pop("refresh_headers", None)
    path = out.get("refresh_token_json_path")
    if path is not None:
        path_s = str(path).strip()
        if path_s:
            for part in path_s.split("."):
                if not part or not _JSON_PATH_PART_RE.fullmatch(part):
                    raise ValueError("refresh_token_json_path must be a dotted JSON path (e.g. accessToken)")
            out["refresh_token_json_path"] = path_s
        else:
            out.pop("refresh_token_json_path", None)
    apply_as = out.get("refresh_apply_as")
    json_path = str(out.get("refresh_token_json_path") or "").strip()
    if apply_as is not None and str(apply_as).strip():
        out["refresh_apply_as"] = validate_refresh_apply_as(str(apply_as), required=bool(json_path))
    elif "refresh_apply_as" in out:
        out.pop("refresh_apply_as", None)
    if json_path and not str(out.get("refresh_apply_as") or "").strip():
        out["refresh_apply_as"] = "bearer"
    if out.get("refresh_apply_as") and not json_path:
        raise ValueError("refresh_apply_as requires refresh_token_json_path")
    return out


def refresh_looks_like_challenge(
    status: int | None,
    *,
    body: str = "",
    headers: dict[str, str] | None = None,
) -> bool:
    """True when the refresh response is a WAF / Cloudflare challenge (value-free)."""
    hdrs = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    if hdrs.get("cf-mitigated"):
        return True
    text = body or ""
    if _CHALLENGE_BODY_RE.search(text[:20_000]):
        return True
    return False


def _set_fail(bag: dict[str, str] | None, note: str) -> None:
    if bag is not None:
        bag["note"] = (note or "")[:300]


def _replace_header(headers: dict[str, str], name: str, value: str) -> None:
    for k in list(headers):
        if k.lower() == name.lower():
            headers.pop(k, None)
    headers[name] = value


def _apply_access_token(headers: dict[str, str], cookies: dict[str, str], token: str, apply_as: str) -> None:
    kind = validate_refresh_apply_as(apply_as, required=True)
    if kind == "bearer":
        _replace_header(headers, "Authorization", f"Bearer {token}")
    elif kind.startswith("header:"):
        _replace_header(headers, kind.split(":", 1)[1], token)
    else:
        cookies[kind.split(":", 1)[1]] = token


def _uses_json_refresh(cfg: dict[str, Any]) -> bool:
    if str(cfg.get("refresh_token_json_path") or "").strip():
        return True
    if cfg.get("refresh_cookies"):
        return True
    if cfg.get("refresh_headers"):
        return True
    if cfg.get("refresh_apply_as"):
        return True
    body = cfg.get("refresh_body")
    if isinstance(body, dict) and body:
        return True
    if str(cfg.get("refresh_content_type") or "").strip():
        return True
    method = str(cfg.get("refresh_method") or "").strip().upper()
    if method and method != "POST":
        return True
    return False


def _encode_refresh_body(cfg: dict[str, Any]) -> tuple[bytes, str]:
    body = cfg.get("refresh_body")
    if body is None:
        payload: dict[str, Any] = {}
    elif isinstance(body, dict):
        payload = body
    else:
        payload = {}
    json_path = str(cfg.get("refresh_token_json_path") or "").strip()
    ctype = str(cfg.get("refresh_content_type") or "").strip().lower()
    if not ctype:
        ctype = "json" if json_path else "form"
    if ctype == "form":
        import urllib.parse

        return urllib.parse.urlencode({str(k): "" if v is None else str(v) for k, v in payload.items()}).encode("utf-8"), "application/x-www-form-urlencoded"
    return json.dumps(payload, separators=(",", ":")).encode("utf-8"), "application/json"


def _refresh_cookie_jar(
    names: list[str],
    current_cookies: dict[str, str] | None,
    extra_cookies: list[tuple[str, str]],
) -> dict[str, str] | None:
    store: dict[str, str] = {}
    for k, v in extra_cookies:
        if k:
            store[str(k)] = str(v)
    store.update(dict(current_cookies or {}))
    if not names:
        return dict(current_cookies or {})
    sent = {n: store[n] for n in names if n in store and store[n]}
    if not sent:
        return None
    return sent


# ------------------------------------------------------------------ re-login


@dataclass
class SessionMaterial:
    """Fresh session headers/cookies after a successful re-login (secret-bearing; keep in memory)."""

    headers: dict[str, str] = field(default_factory=dict, repr=False)
    cookies: dict[str, str] = field(default_factory=dict, repr=False)
    note: str = ""
    redact_values: tuple[str, ...] = field(default=(), repr=False)

    def request_headers(self) -> dict[str, str]:
        return sa.all_request_headers(self.headers, self.cookies)


RefreshPost = Callable[[str, dict[str, str], dict[str, str]], Any]  # (url, data, cookies) -> HttpReply


def attempt_relogin(
    method: str,
    cfg: dict[str, Any],
    secret: str,
    *,
    http_post: Any | None,
    login_probe: sa.LoginProbe,
    imap_search: Any | None = None,
    extra_headers: list[tuple[str, str]] | None = None,
    extra_cookies: list[tuple[str, str]] | None = None,
    current_cookies: dict[str, str] | None = None,
    verify: bool = True,
    http_request: HttpRequest | None = None,
    failure_note: dict[str, str] | None = None,
) -> SessionMaterial | None:
    """Re-establish a session from the profile material; ``None`` when impossible/failed.

    * ``form`` / ``otp``: the existing login paths in :mod:`scan_auth` run again.
    * ``header`` / ``cookie``: static material cannot be renewed unless the profile opts in
      with ``config_json.refresh_url``. Legacy behaviour (no JSON path / refresh cookies) is
      an empty form POST that must return ``Set-Cookie``. When ``refresh_token_json_path``
      (and optional ``refresh_cookies`` / ``refresh_headers`` / ``refresh_apply_as``) is set,
      a JSON or form refresh is sent and the new access token is applied as a header or cookie.
      The refresh response body is treated as secret and is never logged or stored.
    * ``sso_bootstrap`` / ``none``: never automatable.
    """
    method = (method or "").strip().lower()
    if method in ("", "none", "sso_bootstrap"):
        return None
    extra_headers = list(extra_headers or [])
    extra_cookies = list(extra_cookies or [])
    try:
        if method in ("header", "cookie"):
            material = _refresh_static_session(
                method, cfg, secret,
                http_post=http_post, http_request=http_request,
                extra_cookies=extra_cookies, current_cookies=current_cookies,
                failure_note=failure_note,
            )
            if material is None:
                return None
            headers, cookies, note = material
        else:
            if http_post is None:
                return None
            headers, cookies, note = sa.session_material(
                method, cfg, secret, http_post=http_post, imap_search=imap_search
            )
    except Exception as exc:  # noqa: BLE001 - ScanAuthError / transport problems → not recovered
        if not (failure_note or {}).get("note"):
            msg = str(exc).strip()
            _set_fail(failure_note, msg[:200] if msg and type(exc).__name__ == "ScanAuthError" else "refresh request failed")
        return None
    if not headers and not cookies:
        return None
    cookies = xc.merge_cookies(cookies, extra_cookies)
    redact = sa._redaction_values(secret, headers, cookies, extra_values=[v for _, v in extra_cookies])
    headers = xh.merge_extra_headers(headers, extra_headers)
    if verify:
        ok, vnote = check_session_alive(cfg, headers, cookies, login_probe=login_probe)
        if not ok:
            _set_fail(failure_note, "session still invalid after refresh")
            return None
        note = f"{note}; {vnote}"
    return SessionMaterial(headers=headers, cookies=cookies, note=note, redact_values=redact)


def _refresh_static_session(
    method: str,
    cfg: dict[str, Any],
    secret: str,
    *,
    http_post: Any | None,
    http_request: HttpRequest | None,
    extra_cookies: list[tuple[str, str]],
    current_cookies: dict[str, str] | None,
    failure_note: dict[str, str] | None,
) -> tuple[dict[str, str], dict[str, str], str] | None:
    refresh_url = str(cfg.get("refresh_url") or "").strip()
    if not refresh_url:
        return None
    if _uses_json_refresh(cfg):
        return _refresh_via_request(
            method, cfg, secret, refresh_url,
            http_request=http_request, extra_cookies=extra_cookies,
            current_cookies=current_cookies, failure_note=failure_note,
        )
    if http_post is None:
        return None
    reply = http_post(refresh_url, {}, dict(current_cookies or {}))
    status = int(getattr(reply, "status", 599) or 599)
    reply_headers = getattr(reply, "headers", None) or {}
    body = getattr(reply, "body", "") or ""
    if refresh_looks_like_challenge(status, body=body, headers=reply_headers):
        _set_fail(failure_note, REFRESH_WAF_NOTE)
        return None
    if status >= 400 or not getattr(reply, "cookies", None):
        _set_fail(failure_note, f"refresh failed (HTTP {status})" if status >= 400 else "refresh returned no Set-Cookie")
        return None
    headers, cookies, _ = sa.session_material(method, cfg, secret)
    cookies = {**cookies, **dict(reply.cookies)}
    return headers, cookies, "session refreshed via refresh_url"


def _refresh_via_request(
    method: str,
    cfg: dict[str, Any],
    secret: str,
    refresh_url: str,
    *,
    http_request: HttpRequest | None,
    extra_cookies: list[tuple[str, str]],
    current_cookies: dict[str, str] | None,
    failure_note: dict[str, str] | None,
) -> tuple[dict[str, str], dict[str, str], str] | None:
    if http_request is None:
        _set_fail(failure_note, "refresh request helper is not available")
        return None
    try:
        names = _refresh_cookie_names(cfg.get("refresh_cookies"))
    except ValueError as exc:
        _set_fail(failure_note, str(exc))
        return None
    sent = _refresh_cookie_jar(names, current_cookies, extra_cookies)
    if names and sent is None:
        _set_fail(failure_note, "refresh cookie missing")
        return None
    try:
        body, content_type = _encode_refresh_body(cfg)
        req_headers = {"Accept": "application/json, */*;q=0.8", "Content-Type": content_type}
        extra_rh = _refresh_headers_dict(cfg.get("refresh_headers"))
        req_headers.update(extra_rh)
    except ValueError as exc:
        _set_fail(failure_note, str(exc))
        return None
    method_name = str(cfg.get("refresh_method") or "POST").strip().upper() or "POST"
    payload = None if method_name == "GET" else body
    reply = http_request(
        refresh_url,
        method=method_name,
        body=payload if payload is not None else b"",
        headers=req_headers,
        cookies=dict(sent or {}),
    )
    status = int(getattr(reply, "status", 599) or 599)
    reply_headers = getattr(reply, "headers", None) or {}
    raw_body = getattr(reply, "body", "") or ""
    try:
        if refresh_looks_like_challenge(status, body=raw_body, headers=reply_headers):
            _set_fail(failure_note, REFRESH_WAF_NOTE)
            return None
        if status >= 400:
            _set_fail(failure_note, f"refresh failed (HTTP {status})")
            return None
        json_path = str(cfg.get("refresh_token_json_path") or "").strip()
        token = ""
        if json_path:
            try:
                parsed = json.loads(raw_body) if raw_body else None
            except ValueError:
                parsed = None
            extracted = _json_path_get(parsed, json_path) if isinstance(parsed, (dict, list)) else None
            if not isinstance(extracted, str) or not extracted.strip():
                _set_fail(failure_note, "refresh token missing in response")
                return None
            token = extracted.strip()
        headers, cookies, _ = sa.session_material(method, cfg, secret)
        if token:
            apply_as = str(cfg.get("refresh_apply_as") or "bearer")
            _apply_access_token(headers, cookies, token, apply_as)
        reply_cookies = dict(getattr(reply, "cookies", None) or {})
        if reply_cookies:
            cookies = {**cookies, **reply_cookies}
        if not token and not reply_cookies:
            _set_fail(failure_note, "refresh returned no token or Set-Cookie")
            return None
        return headers, cookies, "session refreshed via refresh_url"
    finally:
        # Treat the refresh body as secret: drop the local reference; never log it.
        raw_body = ""


# ------------------------------------------------------------------ guard


@dataclass
class SessionGuard:
    """Tracks one scan's session: liveness checks, bounded re-login, blocked-on-failure.

    ``verify(headers, cookies)`` and ``relogin()`` are injected closures (secrets inside).
    ``on_renew`` callbacks receive the new :class:`SessionMaterial` so adapters can rewrite
    their mounted hook / secret files.
    """

    verify: Callable[[dict[str, str], dict[str, str]], tuple[bool, str]]
    relogin: Callable[[], SessionMaterial | None]
    headers: dict[str, str] = field(default_factory=dict, repr=False)
    cookies: dict[str, str] = field(default_factory=dict, repr=False)
    method: str = ""
    enabled: bool = True
    max_relogins: int = 2
    min_interval_s: float = 5.0
    clock: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep
    on_renew: list[Callable[[SessionMaterial], None]] = field(default_factory=list, repr=False)
    redact_values: tuple[str, ...] = field(default=(), repr=False)
    status: str = "ok"  # ok | recovered | lost
    last_relogin_note: str = ""
    relogins: int = 0
    failed_relogins: int = 0
    checks: int = 0
    lost_reason: str = ""
    events: list[dict[str, Any]] = field(default_factory=list)
    _last_attempt: float | None = field(default=None, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    # -- helpers -------------------------------------------------------------
    def _event(self, kind: str, note: str) -> None:
        self.events.append(
            {
                "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "kind": kind,
                "note": _scrub(note, self.redact_values)[:300],
            }
        )
        del self.events[:-50]

    def request_headers(self) -> dict[str, str]:
        return sa.all_request_headers(self.headers, self.cookies)

    @property
    def lost(self) -> bool:
        return self.status == "lost"

    # -- checks --------------------------------------------------------------
    def alive(self) -> tuple[bool, str]:
        """Run the authoritative liveness check (unless already lost / disabled)."""
        with self._lock:
            if not self.enabled:
                return True, "mid-scan session guard disabled"
            if self.lost:
                return False, self.lost_reason
            self.checks += 1
            ok, note = self.verify(dict(self.headers), dict(self.cookies))
            if not ok:
                self._event("expired", note)
            return ok, note

    def recover(self, reason: str = "") -> bool:
        """Re-login until it succeeds or the attempt budget is spent (rate-limited).

        On success the material rotates and ``on_renew`` callbacks fire; on exhaustion
        the guard is marked lost and stays lost.
        """
        with self._lock:
            if not self.enabled:
                self._mark_lost(reason or "session expired; mid-scan re-login disabled")
                return False
            if self.lost:
                return False
            why = reason or "session expired"
            while True:
                if self.relogins + self.failed_relogins >= self.max_relogins:
                    tail = "re-login failed" if self.failed_relogins else f"re-login budget exhausted ({self.max_relogins} attempt(s))"
                    detail = f"{why}; {tail}"
                    extra = (self.last_relogin_note or "").strip()
                    if extra and extra not in detail:
                        detail = f"{detail}; {extra}"
                    self._mark_lost(detail)
                    return False
                if self._last_attempt is not None and self.min_interval_s > 0:
                    wait = self.min_interval_s - (self.clock() - self._last_attempt)
                    if wait > 0:
                        self.sleep(wait)
                self._last_attempt = self.clock()
                try:
                    material = self.relogin()
                except Exception as exc:  # noqa: BLE001
                    material = None
                    self._event("relogin_error", type(exc).__name__)
                if material is None:
                    self.failed_relogins += 1
                    self._event("relogin_failed", self.last_relogin_note or why)
                    continue
                self.relogins += 1
                self.headers = dict(material.headers)
                self.cookies = dict(material.cookies)
                self.redact_values = tuple(
                    sorted(set(self.redact_values) | set(material.redact_values), key=len, reverse=True)
                )
                self.status = "recovered"
                self._event("relogin_ok", material.note)
                for cb in list(self.on_renew):
                    try:
                        cb(material)
                    except Exception as exc:  # noqa: BLE001
                        self._event("renew_callback_error", type(exc).__name__)
                return True

    def check_and_recover(self) -> tuple[bool, str]:
        """Liveness check, then re-login when dead. ``(True, note)`` when the session is usable."""
        ok, note = self.alive()
        if ok:
            return True, note
        if self.recover(note):
            return True, f"session re-established after: {note}"
        return False, self.lost_reason or note

    def on_response(self, status: int | None, *, body: str = "", headers: dict[str, str] | None = None,
                    cfg: dict[str, Any] | None = None) -> tuple[bool, str]:
        """Per-response trigger: confirm + recover only when the response looks expired."""
        hint, why = looks_expired(status, body=body, headers=headers, cfg=cfg)
        if not hint:
            return True, ""
        ok, note = self.check_and_recover()
        return ok, note or why

    def _mark_lost(self, reason: str) -> None:
        self.status = "lost"
        self.lost_reason = _scrub(reason, self.redact_values)[:300]
        self._event("lost", self.lost_reason)

    # -- reporting -----------------------------------------------------------
    def note(self) -> str:
        """Value-free one-liner for ``ScanRun.auth_note`` / case details."""
        if self.lost:
            return f"{AUTH_LOSS_MARKER} {self.lost_reason} (re-logins ok={self.relogins}, failed={self.failed_relogins})"
        if self.relogins:
            return f"{AUTH_RECOVERED_MARKER} session re-established {self.relogins}x mid-scan"
        return ""

    def public(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "status": self.status,
            "checks": self.checks,
            "relogins": self.relogins,
            "failed_relogins": self.failed_relogins,
            "max_relogins": self.max_relogins,
            "lost_reason": self.lost_reason,
            "events": list(self.events[-20:]),
        }


def _scrub(text: str, values: tuple[str, ...]) -> str:
    out = text or ""
    for v in values:
        if v and len(v) >= 4 and v in out:
            out = out.replace(v, "[REDACTED]")
    return out


def disabled_guard() -> SessionGuard:
    """A guard that never checks or re-logs in (pre-flight-only behaviour)."""
    return SessionGuard(verify=lambda h, c: (True, "disabled"), relogin=lambda: None, enabled=False, max_relogins=0)


def build_guard(
    *,
    method: str,
    cfg: dict[str, Any],
    secret: str,
    headers: dict[str, str],
    cookies: dict[str, str],
    http_post: Any | None,
    login_probe: sa.LoginProbe,
    imap_search: Any | None = None,
    extra_headers: list[tuple[str, str]] | None = None,
    extra_cookies: list[tuple[str, str]] | None = None,
    redact_values: tuple[str, ...] = (),
    enabled: bool | None = None,
    max_relogins: int | None = None,
    http_request: HttpRequest | None = None,
) -> SessionGuard:
    """Guard wired to the profile's verify URL and login path (secrets captured in closures)."""
    state: dict[str, Any] = {"cookies": dict(cookies)}
    fail_bag: dict[str, str] = {"note": ""}

    def _verify(h: dict[str, str], c: dict[str, str]) -> tuple[bool, str]:
        state["cookies"] = dict(c)
        return check_session_alive(cfg, h, c, login_probe=login_probe)

    def _relogin() -> SessionMaterial | None:
        fail_bag["note"] = ""
        mat = attempt_relogin(
            method, cfg, secret,
            http_post=http_post, login_probe=login_probe, imap_search=imap_search,
            extra_headers=extra_headers, extra_cookies=extra_cookies,
            current_cookies=state.get("cookies"),
            http_request=http_request, failure_note=fail_bag,
        )
        guard.last_relogin_note = fail_bag.get("note", "")
        if mat is not None:
            state["cookies"] = dict(mat.cookies)
        return mat

    guard = SessionGuard(
        verify=_verify,
        relogin=_relogin,
        headers=dict(headers),
        cookies=dict(cookies),
        method=(method or "").lower(),
        enabled=midscan_enabled() if enabled is None else enabled,
        max_relogins=relogin_max() if max_relogins is None else max_relogins,
        min_interval_s=relogin_min_interval_s(),
        redact_values=tuple(redact_values),
    )
    return guard


# ------------------------------------------------------------------ background watcher


class ScanWatcher:
    """Daemon thread that polls :meth:`SessionGuard.check_and_recover` while a scanner runs."""

    def __init__(self, guard: SessionGuard, *, interval_s: float | None = None, cancel: threading.Event | None = None):
        self.guard = guard
        self.interval_s = float(interval_s if interval_s is not None else heartbeat_s())
        self._stop = threading.Event()
        self._cancel = cancel
        self._thread: threading.Thread | None = None
        self.polls = 0

    def start(self) -> None:
        if not self.guard.enabled or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="attestra-session-guard", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)

    def _run(self) -> None:
        while not self._stop.wait(self.interval_s):
            if self._cancel is not None and self._cancel.is_set():
                return
            self.polls += 1
            ok, _ = self.guard.check_and_recover()
            if not ok:
                return  # lost: nothing more to do; the scan result carries the blocked note


# ------------------------------------------------------------------ result helpers


def auth_note_after_scan(base_note: str, result_extra: dict[str, Any] | None) -> str:
    """Compose ``ScanRun.auth_note`` from the pre-flight note and the guard outcome."""
    note = (base_note or "").strip()
    auth = (result_extra or {}).get("auth") if isinstance(result_extra, dict) else None
    if not isinstance(auth, dict):
        return note[:500]
    status = str(auth.get("status") or "")
    if status == "lost":
        blocked = (result_extra or {}).get("auth_blocked_urls")
        extra = f"; {len(blocked)} URL(s) not scanned authenticated (blocked)" if isinstance(blocked, list) and blocked else ""
        line = f"{AUTH_LOSS_MARKER} {auth.get('lost_reason') or 'session lost mid-scan'}{extra}"
    elif int(auth.get("relogins") or 0) > 0:
        line = f"{AUTH_RECOVERED_MARKER} session re-established {auth.get('relogins')}x mid-scan"
    else:
        return note[:500]
    return (f"{note}; {line}" if note else line)[:500]


def note_has_auth_loss(note: str | None) -> bool:
    return AUTH_LOSS_MARKER in (note or "")
