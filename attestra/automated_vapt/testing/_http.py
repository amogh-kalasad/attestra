"""Shared HTTP helpers for Elite testing modules (TestClient or httpx.Client)."""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

from attestra.proof.pair import HttpPair


def absolute(base: str, path: str) -> str:
    root = base if base.endswith("/") else base + "/"
    return urljoin(root, path.lstrip("/"))


def request_json(client, method: str, url: str, **kwargs) -> tuple[int, Any, str]:
    """Return status, parsed JSON (or None), and text body."""
    pair = request_pair(client, method, url, **kwargs)
    data = None
    try:
        import json

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


def login(client, base: str, username: str, password: str) -> int:
    r = client.post(
        absolute(base, "/login"),
        data={"username": username, "password": password},
        follow_redirects=False,
    )
    return int(r.status_code)
