"""Engagement-profile session helpers for Elite authz modules.

When a ready ``_session_auth`` is present, modules must use that profile's
headers against capture / target URLs and must not POST lab ``/login`` with
``account_a`` passwords. Lab login stays for TestClient mock apps that have
no session. Live httpx clients without a session SKIP instead of probing
lab paths (which would false-PASS or false-FIND on real targets).
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from attestra.automated_vapt.testing._http import request_pair

# Same codes the orchestrator / reports already understand.
SKIP_NO_AUTH_SESSION = "no_auth_session"
SKIP_NO_SECOND_ROLE = "no_second_role"
SKIP_AUTH_REQUESTS_FAILED = "auth_requests_failed"

_SECRET_KEY_RE = (
    "password",
    "passwd",
    "secret",
    "secret_note",
    "api_token",
    "apitoken",
    "access_token",
    "refresh_token",
    "private_key",
    "current_session",
    "currentsessiontoken",
)

_AUTH_HEADER_NAMES = frozenset(
    {
        "authorization",
        "cookie",
        "proxy-authorization",
        "x-auth-token",
        "x-access-token",
        "x-api-key",
    }
)


def ctx_extra(kwargs: dict[str, Any] | None) -> dict[str, Any]:
    if not kwargs:
        return {}
    ctx = kwargs.get("ctx")
    if ctx is None:
        return {}
    return getattr(ctx, "extra", {}) or {}


def ready_auth(kwargs: dict[str, Any] | None, key: str = "_session_auth") -> Any | None:
    """Return the session object only when status is ``ready``."""
    auth = ctx_extra(kwargs).get(key)
    if auth is not None and getattr(auth, "status", "") == "ready":
        return auth
    return None


def is_lab_client(client: Any) -> bool:
    """True for Starlette/FastAPI TestClient (unit-test mock apps)."""
    if client is None:
        return False
    if type(client).__name__ == "TestClient":
        return True
    return getattr(client, "app", None) is not None


def resolve_mode(client: Any, kwargs: dict[str, Any] | None) -> tuple[str, Any | None]:
    """``('engagement', auth)`` | ``('lab', None)`` | ``('skip', None)``."""
    auth = ready_auth(kwargs)
    if auth is not None:
        return "engagement", auth
    if is_lab_client(client):
        return "lab", None
    return "skip", None


def skip_result(test_id: str, category: str, reason: str, detail: str) -> dict[str, Any]:
    return {
        "test_id": test_id,
        "category": category,
        "status_hint": "SKIPPED",
        "skip_reason": reason,
        "observations": {"detail": detail},
        "finding_candidate": False,
        "evidence_hints": [],
    }


def origin(url: str) -> tuple[str, str, int]:
    p = urlsplit(url or "")
    scheme = (p.scheme or "").lower()
    try:
        port = p.port or (443 if scheme == "https" else 80)
    except ValueError:
        port = -1
    return scheme, (p.hostname or "").lower(), port


def same_origin(url: str, root: str) -> bool:
    if not url or not root:
        return False
    return origin(url) == origin(root)


def probe_urls(
    base_url: str,
    kwargs: dict[str, Any] | None,
    *,
    api: bool = False,
    limit: int = 8,
) -> list[str]:
    """Same-origin capture URLs, falling back to the target base."""
    extra = ctx_extra(kwargs)
    # Resolved API base (asset API Base URL / same-site refresh origin), else the target.
    api_root = str(extra.get("_api_base_url") or base_url or "")
    seen: list[str] = []

    def add(raw: Any) -> None:
        u = str(raw or "").strip()
        if not u or u in seen:
            return
        if base_url and not same_origin(u, base_url) and not (api_root and same_origin(u, api_root)):
            return
        seen.append(u)

    if api:
        for u in extra.get("_capture_api_urls") or []:
            add(u)
        js = extra.get("_js_api") or {}
        if isinstance(js, dict):
            for ep in js.get("endpoints_list") or []:
                path = ep.get("path") if isinstance(ep, dict) else getattr(ep, "path", "")
                if path:
                    from attestra.automated_vapt.testing._http import absolute

                    add(absolute(api_root or base_url, str(path)))
    else:
        for u in extra.get("_capture_urls") or []:
            add(u)
        for u in extra.get("_capture_api_urls") or []:
            add(u)
    if not seen and base_url:
        add(base_url)
    return seen[: max(1, int(limit))]


def request_plain(client: Any, method: str, url: str, **kwargs: Any) -> Any:
    """Unauthenticated request; default to not following redirects."""
    kwargs.setdefault("follow_redirects", False)
    # Drop any leftover auth the caller may have put on the client jar.
    headers = {str(k): str(v) for k, v in dict(kwargs.pop("headers", None) or {}).items()}
    # Do not inherit an Authorization default from the shared client if we can replace.
    return request_pair(client, method, url, headers=headers or None, **kwargs)


def request_auth(client: Any, method: str, url: str, auth: Any, root: str, **kwargs: Any) -> Any:
    """Request with engagement session headers (same-origin only)."""
    kwargs.setdefault("follow_redirects", False)
    headers = {str(k): str(v) for k, v in dict(kwargs.pop("headers", None) or {}).items()}
    extra = {}
    if auth is not None and hasattr(auth, "headers_for"):
        extra = auth.headers_for(url, root) or {}
    elif auth is not None and getattr(auth, "status", "") == "ready":
        extra = dict(getattr(auth, "headers", None) or {})
    for k, v in extra.items():
        headers.setdefault(k, v)
    return request_pair(client, method, url, headers=headers or None, **kwargs)


def scrub_pair(pair: Any, *auths: Any) -> Any:
    """Redact session secret values from an evidence pair (in place)."""
    if pair is None:
        return pair
    values: list[str] = []
    for auth in auths:
        if auth is None:
            continue
        values.extend(getattr(auth, "redact_values", ()) or ())
        scrub = getattr(auth, "scrub", None)
        if callable(scrub):
            if getattr(pair, "request_body", None):
                pair.request_body = scrub(pair.request_body)
            if getattr(pair, "response_body", None):
                pair.response_body = scrub(pair.response_body)
            if getattr(pair, "url", None):
                pair.url = scrub(pair.url)
            req_h = getattr(pair, "request_headers", None) or {}
            pair.request_headers = {k: scrub(str(v)) for k, v in req_h.items()}
            resp_h = getattr(pair, "response_headers", None) or {}
            pair.response_headers = {k: scrub(str(v)) for k, v in resp_h.items()}
            continue
    if values:
        def _redact(text: str) -> str:
            out = text or ""
            for v in values:
                if v and v in out:
                    out = out.replace(v, "[REDACTED]")
            return out

        if getattr(pair, "request_body", None):
            pair.request_body = _redact(pair.request_body)
        if getattr(pair, "response_body", None):
            pair.response_body = _redact(pair.response_body)
        req_h = getattr(pair, "request_headers", None) or {}
        pair.request_headers = {k: _redact(str(v)) for k, v in req_h.items()}
        resp_h = getattr(pair, "response_headers", None) or {}
        pair.response_headers = {k: _redact(str(v)) for k, v in resp_h.items()}
    # Never keep raw Authorization / Cookie in evidence if somehow unredacted
    # values remain — replace those header values with a name-only marker.
    for mapping_name in ("request_headers", "response_headers"):
        mapping = getattr(pair, mapping_name, None)
        if not isinstance(mapping, dict):
            continue
        cleaned = {}
        for k, v in mapping.items():
            if str(k).lower() in _AUTH_HEADER_NAMES and v and "[REDACTED]" not in str(v):
                cleaned[k] = "[REDACTED]"
            else:
                cleaned[k] = v
        setattr(pair, mapping_name, cleaned)
    return pair


def parse_json(text: str | None) -> Any:
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def is_substantive_json(status: int | None, text: str | None) -> bool:
    if int(status or 0) != 200:
        return False
    data = parse_json(text)
    if isinstance(data, dict):
        if not data:
            return False
        # Bare error envelopes are not "authenticated data".
        keys = {str(k).lower() for k in data}
        if keys <= {"error", "errors", "message", "detail", "status"} and len(data) <= 2:
            return False
        return True
    if isinstance(data, list):
        return True
    return False


def secret_key_names(data: Any, *, depth: int = 0) -> list[str]:
    """Return sensitive JSON *key names* only — never values."""
    found: list[str] = []
    if depth > 5:
        return found
    if isinstance(data, dict):
        for k, v in data.items():
            lk = str(k).lower()
            if any(s in lk for s in _SECRET_KEY_RE):
                found.append(str(k))
            found.extend(secret_key_names(v, depth=depth + 1))
    elif isinstance(data, list):
        for item in data[:30]:
            found.extend(secret_key_names(item, depth=depth + 1))
    # unique, stable
    out: list[str] = []
    seen: set[str] = set()
    for name in found:
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


def blocked_status(status: int | None) -> bool:
    return int(status or 0) in (301, 302, 303, 307, 308, 401, 403, 404)


def looks_privileged_url(url: str) -> bool:
    low = (url or "").lower()
    return any(
        token in low
        for token in (
            "/admin",
            "/settings",
            "/users",
            "/staff",
            "/manage",
            "/privilege",
            "/internal",
        )
    )
