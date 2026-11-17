"""Safe file-upload probe (catalogue UPLOAD).

Uploads a benign HTML marker file only when the FND-02 target-environment policy
allowed UPLOAD for this execution (``ctx.extra["_intrusive_policy"]["UPLOAD"]``: env
flag on, active profile, scope policy, asset environment in the dev/demo allowlist and
a cleanup-plan acknowledgement). Never plants executable content intended for shared
hosting. Verifies whether the stored URL is reachable anonymously.
"""

from __future__ import annotations

from typing import Any

from attestra.automated_vapt.core import intrusive_policy
from attestra.automated_vapt.core.response_classifier import (
    classify_httpx,
    classify_pair,
    is_blocking,
    mark_blocked_if_needed,
    samples_to_json,
    skip_reason_for,
)
from attestra.automated_vapt.testing._http import absolute, clear_cookies, login, request_pair
from attestra.automated_vapt.testing._session import (
    SKIP_NO_AUTH_SESSION,
    is_lab_client,
    request_auth,
    resolve_mode,
    skip_result,
)

# @lat: [[architecture#Remaining gaps plan (auth depth)]]

MARKER = b"<html><!-- attestra-upload-marker --></html>"
MARKER_NAME = "attestra-probe.html"
SKIP_DISABLED = "upload_probe_disabled"
SKIP_POLICY_DENIED = "policy_denied"
SKIP_NO_ENDPOINT = "no_upload_endpoint"


def probe_enabled(ctx: Any | None = None) -> bool:
    """True only when the FND-02 decision for this execution allows UPLOAD (absent => False)."""
    return intrusive_policy.decision_from_ctx(ctx, "UPLOAD").allow


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    decision = intrusive_policy.decision_from_ctx(kwargs.get("ctx"), "UPLOAD")
    # force=True is a unit-test hook honoured only for in-process lab mock clients.
    if not decision.allow and not (kwargs.get("force") and is_lab_client(client)):
        return intrusive_policy.skip_payload("UPLOAD", "file", decision, disabled_reason=SKIP_DISABLED)

    mode, auth = resolve_mode(client, kwargs)
    if mode == "skip":
        return skip_result(
            "UPLOAD",
            "file",
            SKIP_NO_AUTH_SESSION,
            "engagement login profile not ready; skipped lab /api/upload probes",
        )

    upload_url = absolute(base_url, "/api/upload")
    session_headers = {}
    if auth is not None and hasattr(auth, "headers_for"):
        session_headers = auth.headers_for(upload_url, base_url) or {}
    elif mode == "lab":
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
            headers=session_headers or None,
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
    up_cls = classify_httpx(r, authed=auth is not None)
    samples = [up_cls]
    if is_blocking(up_cls):
        return {
            "test_id": "UPLOAD",
            "category": "file",
            "status_hint": "BLOCKED",
            "skip_reason": skip_reason_for(samples),
            "observations": {"upload_status": status, "response_class": up_cls.cls.value,
                             "detail": "upload answered by WAF/challenge/rate limit, not the application"},
            "finding_candidate": False,
            "evidence_hints": [],
            "validity_samples": samples_to_json(samples),
        }
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
                "response_class": up_cls.cls.value,
            },
            "finding_candidate": False,
            "evidence_hints": ["POST /api/upload rejected"],
            "validity_samples": samples_to_json(samples),
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

    # Anonymous fetch of stored URL (clear cookies, no session headers).
    clear_cookies(client)
    fetch = request_pair(client, "GET", absolute(base_url, stored_url), follow_redirects=False)
    served = (fetch.response_body or "").encode("utf-8", "replace") if isinstance(fetch.response_body, str) else b""
    # TestClient may leave text as str containing the marker.
    marker_served = b"attestra-upload-marker" in served or "attestra-upload-marker" in (fetch.response_body or "")
    ct = (fetch.response_headers or {}).get("content-type") or (fetch.response_headers or {}).get("Content-Type") or ""
    finding = marker_served and int(fetch.status or 0) == 200 and "text/html" in ct.lower()
    samples.append(classify_pair(fetch))

    result = {
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
        "policy_decision": decision.to_json(),
        "validity_samples": samples_to_json(samples),
    }
    return mark_blocked_if_needed(result, samples)
