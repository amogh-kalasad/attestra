"""Shared HTTP helpers for Elite testing modules (TestClient or httpx.Client)."""

from __future__ import annotations

import base64
import json
import re
from typing import Any
from urllib.parse import urljoin

from attestra.proof.pair import HttpPair

# JWT-shaped tokens only (structure observation; never forged or replayed as attack).
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]*)?")


def absolute(base: str, path: str) -> str:
    root = base if base.endswith("/") else base + "/"
    return urljoin(root, path.lstrip("/"))


def clear_cookies(client) -> None:
    """Drop client cookie jar when the client supports it (TestClient / httpx)."""
    jar = getattr(client, "cookies", None)
    if jar is None:
        return
    try:
        jar.clear()
    except Exception:
        pass


def request_json(client, method: str, url: str, **kwargs) -> tuple[int, Any, str]:
    """Return status, parsed JSON (or None), and text body."""
    pair = request_pair(client, method, url, **kwargs)
    data = None
    try:
        data = json.loads(pair.response_body) if pair.response_body else None
    except Exception:
        data = None
    return int(pair.status or 0), data, pair.response_body


def request_pair(client, method: str, url: str, **kwargs) -> HttpPair:
    """Perform a request and return an [[HttpPair]] for evidence documentation."""
    r = client.request(method, url, **kwargs)
    text = getattr(r, "text", "") or ""
    req_headers: dict[str, str] = {}
    req_body = ""
    try:
        req = getattr(r, "request", None)
        if req is not None:
            req_headers = {str(k): str(v) for k, v in getattr(req, "headers", {}).items()}
            content = getattr(req, "content", None)
            if content is None:
                content = getattr(req, "body", b"") or b""
            if isinstance(content, bytes):
                req_body = content.decode("utf-8", "replace")[:200_000]
            else:
                req_body = str(content)[:200_000]
    except Exception:
        pass
    resp_headers = {str(k): str(v) for k, v in r.headers.items()}
    return HttpPair(
        method=(method or "GET").upper(),
        url=url,
        request_headers=req_headers,
        request_body=req_body,
        status=int(r.status_code),
        response_headers=resp_headers,
        response_body=text[:200_000],
        source="automated_vapt",
    )


def login_response(client, base: str, username: str, password: str):
    """POST /login without following redirects; return the raw response object."""
    return client.post(
        absolute(base, "/login"),
        data={"username": username, "password": password},
        follow_redirects=False,
    )


def login(client, base: str, username: str, password: str) -> int:
    return int(login_response(client, base, username, password).status_code)


def parse_set_cookie_header(raw: str) -> dict[str, str] | None:
    """Parse ``name=value; Attr; Attr=val`` into name + lowercase attribute map."""
    text = (raw or "").strip()
    if not text or "=" not in text.split(";", 1)[0]:
        return None
    first, *rest = text.split(";")
    name, _, value = first.strip().partition("=")
    name = name.strip()
    if not name:
        return None
    attrs: dict[str, str] = {"_name": name, "_value": value.strip()}
    for part in rest:
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            ak, _, av = part.partition("=")
            attrs[ak.strip().lower()] = av.strip()
        else:
            attrs[part.lower()] = ""
    return attrs


def set_cookie_lines(headers: dict[str, str] | Any) -> list[str]:
    """Collect Set-Cookie values from a header mapping (case-insensitive)."""
    if headers is None:
        return []
    items: list[tuple[str, str]] = []
    try:
        items = [(str(k), str(v)) for k, v in headers.items()]
    except Exception:
        return []
    out: list[str] = []
    for key, val in items:
        if key.lower() != "set-cookie":
            continue
        text = str(val).strip()
        if not text:
            continue
        # Prefer newline-separated multi-cookie values.
        out.extend(line.strip() for line in text.split("\n") if line.strip())
    return out


def observe_cookie_flags(headers: dict[str, str] | Any) -> list[dict[str, Any]]:
    """Observe Secure / HttpOnly / SameSite on each Set-Cookie (no findings raised here)."""
    rows: list[dict[str, Any]] = []
    for raw in set_cookie_lines(headers):
        attrs = parse_set_cookie_header(raw)
        if not attrs:
            continue
        rows.append(
            {
                "name": attrs["_name"],
                "secure": "secure" in attrs,
                "httponly": "httponly" in attrs,
                "samesite": attrs.get("samesite"),
            }
        )
    return rows


def find_jwt_candidates(*texts: str) -> list[str]:
    """Return unique JWT-shaped strings from text blobs (cookies, bodies)."""
    found: list[str] = []
    seen: set[str] = set()
    for text in texts:
        if not text:
            continue
        for match in _JWT_RE.finditer(str(text)):
            token = match.group(0)
            if token not in seen:
                seen.add(token)
                found.append(token)
    return found


def inspect_jwt_structure(token: str) -> dict[str, Any]:
    """Decode JWT header/claims structure only — no signature check, no forging.

    Flags ``alg_none`` when the header algorithm is ``none`` / empty (classic bypass).
    """
    parts = (token or "").split(".")
    out: dict[str, Any] = {
        "parts": len(parts),
        "alg": None,
        "alg_none": False,
        "typ": None,
        "header_ok": False,
        "claims_keys": [],
    }
    if len(parts) < 2:
        return out

    def _b64url_json(segment: str) -> Any:
        pad = "=" * (-len(segment) % 4)
        raw = base64.urlsafe_b64decode((segment + pad).encode("ascii"))
        return json.loads(raw.decode("utf-8"))

    try:
        header = _b64url_json(parts[0])
    except Exception:
        return out
    if not isinstance(header, dict):
        return out
    out["header_ok"] = True
    alg = header.get("alg")
    out["alg"] = alg
    out["typ"] = header.get("typ")
    alg_l = str(alg or "").strip().lower()
    out["alg_none"] = alg_l in {"", "none"}
    if len(parts) >= 2 and parts[1]:
        try:
            claims = _b64url_json(parts[1])
            if isinstance(claims, dict):
                out["claims_keys"] = sorted(str(k) for k in claims.keys())
        except Exception:
            pass
    return out
