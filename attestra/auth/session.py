"""Signed session cookies for the web UI."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode

from attestra import config

COOKIE_NAME = "attestra_session"


def _secret() -> bytes:
    from attestra.secret_store import get_secret

    return get_secret("session_secret", config.SESSION_SECRET).encode("utf-8")


def _sign(payload: bytes) -> str:
    sig = hmac.new(_secret(), payload, hashlib.sha256).digest()
    return urlsafe_b64encode(payload + b"." + sig).decode("ascii")


def _unsign(token: str, *, max_age_s: int = 86400 * 7) -> dict | None:
    try:
        raw = urlsafe_b64decode(token.encode("ascii"))
        # The HMAC digest is raw bytes and may itself contain b".", so split at its fixed length.
        if len(raw) < 34 or raw[-33:-32] != b".":
            return None
        payload, sig = raw[:-33], raw[-32:]
        expected = hmac.new(_secret(), payload, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return None
        data = json.loads(payload.decode("utf-8"))
        if time.time() - float(data.get("ts", 0)) > max_age_s:
            return None
        return data
    except Exception:
        return None


def issue_session(user_id: int, username: str) -> str:
    payload = json.dumps({"uid": user_id, "u": username, "ts": time.time()}, separators=(",", ":")).encode()
    return _sign(payload)


def read_session(token: str | None) -> dict | None:
    if not token:
        return None
    return _unsign(token)
