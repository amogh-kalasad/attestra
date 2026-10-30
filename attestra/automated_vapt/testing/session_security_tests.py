"""Basic session cookie checks after login."""

from __future__ import annotations

from typing import Any

from attestra.automated_vapt.testing._http import login

# @lat: [[architecture#Elite automated security testing#Authz test modules]]


def run(client, base_url: str, **_kwargs) -> dict[str, Any]:
    login(client, base_url, "viewer", "viewer-pass")
    cookies = {}
    jar = getattr(client, "cookies", None)
    if jar is not None:
        try:
            cookies = dict(jar)
        except Exception:
            cookies = {}
    has_session = any(k.lower() in ("mock_session", "session", "sessionid") for k in cookies)
    # Not a vulnerability by itself; observation only.
    return {
        "test_id": "SESSION",
        "category": "authentication",
        "observations": {"has_session_cookie": has_session, "cookie_names": sorted(cookies.keys())},
        "finding_candidate": False,
        "evidence_hints": ["POST /login"],
    }
