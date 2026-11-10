"""Safe file-upload probe (catalogue UPLOAD).

Uploads a benign HTML marker file only when APP_ENV is local/test/development (or
ATTESTRA_AUTOMATED_VAPT_UPLOAD=1) and never plants executable content intended for
shared hosting. Verifies whether the stored URL is reachable anonymously.
"""

from __future__ import annotations

import os
from typing import Any

from attestra.automated_vapt.testing._http import absolute, clear_cookies, login, request_pair

# @lat: [[architecture#Remaining gaps plan (auth depth)]]

MARKER = b"<html><!-- attestra-upload-marker --></html>"
MARKER_NAME = "attestra-probe.html"
SKIP_DISABLED = "upload_probe_disabled"
SKIP_NO_ENDPOINT = "no_upload_endpoint"


def probe_enabled() -> bool:
    raw = (os.environ.get("ATTESTRA_AUTOMATED_VAPT_UPLOAD") or "").strip().lower()
    if raw in ("0", "false", "no", "off"):
        return False
    if raw in ("1", "true", "yes", "on"):
        return True
    from attestra import config

    env = config.parse_app_env() if hasattr(config, "parse_app_env") else getattr(config, "APP_ENV", None)
    allow = getattr(config, "_APP_ENV_BYPASS_ALLOWLIST", frozenset({"local", "test", "development"}))
    return env in allow


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    if not probe_enabled() and not kwargs.get("force"):
        return {
            "test_id": "UPLOAD",
            "category": "file",
            "status_hint": "SKIPPED",
            "skip_reason": SKIP_DISABLED,
            "observations": {
                "detail": "upload probe disabled outside local/test/development "
                "(set ATTESTRA_AUTOMATED_VAPT_UPLOAD=1)"
            },
            "finding_candidate": False,
            "evidence_hints": [],
        }

    upload_url = absolute(base_url, "/api/upload")
    # Prefer authenticated session when lab login works; anon is also informative.
    try:
        clear_cookies(client)
        login(client, base_url, "account_a", "account-a-pass")
    except Exception:
        pass

    try:
        r = client.post(
            upload_url,
            files={"file": (MARKER_NAME, MARKER, "text/html")},
        )
    except Exception as exc:  # noqa: BLE001
        return {
            "test_id": "UPLOAD",
            "category": "file",
            "status_hint": "SKIPPED",
            "skip_reason": SKIP_NO_ENDPOINT,
            "observations": {"detail": f"upload request failed: {exc}"},
            "finding_candidate": False,
            "evidence_hints": [],
        }

    status = int(getattr(r, "status_code", 0) or 0)
    body_text = getattr(r, "text", "") or ""
    stored_url = ""
    try:
        data = r.json()
        stored_url = str((data or {}).get("url") or "")
    except Exception:
        data = None

    if status in (401, 403, 404, 405):
        return {
            "test_id": "UPLOAD",
            "category": "file",
            "observations": {
                "upload_status": status,
                "stored_url": stored_url,
                "anon_fetch_status": None,
                "marker_served": False,
                "detail": "upload rejected or unavailable",
            },
            "finding_candidate": False,
            "evidence_hints": ["POST /api/upload rejected"],
        }

    if status not in (200, 201) or not stored_url:
        return {
            "test_id": "UPLOAD",
            "category": "file",
            "status_hint": "SKIPPED",
            "skip_reason": SKIP_NO_ENDPOINT,
            "observations": {"upload_status": status, "body": body_text[:200]},
            "finding_candidate": False,
            "evidence_hints": [],
        }

    # Anonymous fetch of stored URL (clear cookies).
    clear_cookies(client)
    fetch = request_pair(client, "GET", absolute(base_url, stored_url), follow_redirects=False)
    served = (fetch.response_body or "").encode("utf-8", "replace") if isinstance(fetch.response_body, str) else b""
    # TestClient may leave text as str containing the marker.
    marker_served = b"attestra-upload-marker" in served or "attestra-upload-marker" in (fetch.response_body or "")
    ct = (fetch.response_headers or {}).get("content-type") or (fetch.response_headers or {}).get("Content-Type") or ""
    finding = marker_served and int(fetch.status or 0) == 200 and "text/html" in ct.lower()

    return {
        "test_id": "UPLOAD",
        "category": "file",
        "observations": {
            "upload_status": status,
            "stored_url": stored_url,
            "anon_fetch_status": fetch.status,
            "marker_served": marker_served,
            "content_type": ct,
        },
        "finding_candidate": finding,
        "evidence_pairs": [fetch] if finding else [],
        "evidence_hints": [f"POST /api/upload → GET {stored_url}"],
    }
