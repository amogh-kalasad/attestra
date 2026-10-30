"""Shared HTTP helpers for Elite testing modules (TestClient or httpx.Client)."""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin


def absolute(base: str, path: str) -> str:
    root = base if base.endswith("/") else base + "/"
    return urljoin(root, path.lstrip("/"))


def request_json(client, method: str, url: str, **kwargs) -> tuple[int, Any, str]:
    """Return status, parsed JSON (or None), and text body."""
    r = client.request(method, url, **kwargs)
    text = getattr(r, "text", "") or ""
    data = None
    try:
        data = r.json()
    except Exception:
        data = None
    return int(r.status_code), data, text


def login(client, base: str, username: str, password: str) -> int:
    r = client.post(
        absolute(base, "/login"),
        data={"username": username, "password": password},
        follow_redirects=False,
    )
    return int(r.status_code)
