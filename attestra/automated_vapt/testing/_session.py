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


def _js_endpoint_probe_ok(ep: Any) -> bool:
    """True only for JS-discovered paths that are GET-safe to replay (capture_safe + gettable)."""
    if ep is None:
        return False
    if isinstance(ep, dict):
        if "capture_safe" in ep or "gettable" in ep:
            return bool(ep.get("capture_safe")) and bool(ep.get("gettable", True))
        try:
            from attestra.automated_vapt.core.js_api_discovery import ApiEndpoint

            obj = ApiEndpoint.from_dict(ep)
        except Exception:
            return False
        return bool(obj.capture_safe and obj.gettable)
    return bool(getattr(ep, "capture_safe", False) and getattr(ep, "gettable", False))


def _pair_url_status(pair: Any) -> tuple[str, int | None]:
    if pair is None:
        return "", None
    if isinstance(pair, dict):
        url = str(pair.get("url") or "").strip()
        status = pair.get("status")
    else:
        url = str(getattr(pair, "url", "") or "").strip()
        status = getattr(pair, "status", None)
    try:
        code = int(status) if status is not None else None
    except (TypeError, ValueError):
        code = None
    return url, code


def _is_api_probe_url(url: str, api_root: str, api_captured: set[str]) -> bool:
    """True for inventoried API URLs or paths that look like API routes (not HTML pages)."""
    if not url:
        return False
    if url.rstrip("/") in api_captured:
        return True
    path = (urlsplit(url).path or "/").lower()
    return path.startswith("/api/") or path == "/api" or "/graphql" in path


def probe_urls(
    base_url: str,
    kwargs: dict[str, Any] | None,
    *,
    api: bool = False,
    limit: int = 8,
) -> list[str]:
    """Same-origin capture URLs, falling back to the target base.

    For API probes, prefer URLs T01 already captured with HTTP 200, then other
    ``_capture_api_urls``. JS-discovered paths are added only when they are
    ``capture_safe`` and ``gettable`` (no logout / refresh / register GETs).
    """
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
        api_captured = [str(u).strip() for u in (extra.get("_capture_api_urls") or []) if str(u).strip()]
        api_set = {u.rstrip("/") for u in api_captured}
        # 1. T01-captured 200 API responses first.
        for pair in extra.get("_http_pairs") or []:
            u, code = _pair_url_status(pair)
            if code == 200 and _is_api_probe_url(u, api_root, api_set):
                add(u)
        # 2. Other inventoried API capture URLs.
        for u in api_captured:
            add(u)
        # 3. JS-discovered GET-safe endpoints only.
        js = extra.get("_js_api") or {}
        if isinstance(js, dict):
            from attestra.automated_vapt.testing._http import absolute

            for ep in js.get("endpoints_list") or []:
                if not _js_endpoint_probe_ok(ep):
                    continue
                path = ep.get("path") if isinstance(ep, dict) else getattr(ep, "path", "")
                if path:
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
    """Unauthenticated request; default to not following redirects.

    Session credentials are omitted, but non-auth Extra Headers (WAF bypass, portal
    host, UA) are kept when ``auth`` + ``root`` are provided (or can be read from ``ctx``).
    """
    kwargs.setdefault("follow_redirects", False)
    # Drop any leftover auth the caller may have put on the client jar.
    headers = {str(k): str(v) for k, v in dict(kwargs.pop("headers", None) or {}).items()}
    auth = kwargs.pop("auth", None)
    root = str(kwargs.pop("root", "") or "")
    if auth is None or not root:
        extra = ctx_extra({"ctx": kwargs["ctx"]} if kwargs.get("ctx") is not None else {})
        if auth is None:
            auth = extra.get("_session_auth")
        if not root:
            ctx = kwargs.get("ctx")
            root = str(getattr(ctx, "target_base_url", "") or extra.get("_api_base_url") or "")
    kwargs.pop("ctx", None)
    if auth is not None:
        extras: dict[str, str] = {}
        if hasattr(auth, "extra_headers_for") and root:
            extras = auth.extra_headers_for(url, root) or {}
        elif root and hasattr(auth, "headers_for"):
            extras = {
                str(k): str(v)
                for k, v in (auth.headers_for(url, root) or {}).items()
                if str(k).lower() not in _AUTH_HEADER_NAMES
            }
        for k, v in extras.items():
            headers.setdefault(k, v)
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


def blocked_status(
    status: int | None,
    headers: dict[str, Any] | None = None,
    body: str = "",
) -> bool:
    """Deprecated (FND-04): use ``response_classifier.classify_pair`` + ``proves_enforcement``.

    Kept for callers outside WP1. Routed through the shared classifier so a WAF block
    page, challenge, or rate limit is never reported as "blocked by the application".
    A bare status without headers/body is still classified (status-only callers keep the
    old 3xx/401/403/404 behaviour minus infrastructure answers).
    """
    from attestra.automated_vapt.core.response_classifier import ResponseClass, classify_response

    code = int(status or 0)
    if code in (301, 302, 303, 307, 308) and not headers:
        return True  # status-only legacy call: cannot see Location
    cls = classify_response(code or None, headers or {}, body or "").cls
    return cls in (ResponseClass.APP_AUTH_DENIED, ResponseClass.AUTH_REDIRECT, ResponseClass.NOT_FOUND)


def classify_for_validity(pair: Any, *, authed: bool = False) -> dict[str, Any]:
    """Value-free ``validity_samples`` entry for one evidence pair (FND-03 input)."""
    from attestra.automated_vapt.core.response_classifier import classify_pair

    return classify_pair(pair, authed=authed).to_dict()


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
