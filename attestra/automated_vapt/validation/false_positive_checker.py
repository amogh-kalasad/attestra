"""False-positive heuristics for Elite validation results."""

from __future__ import annotations

from typing import Any

# @lat: [[architecture#Elite automated security testing#Validation engine]]


def check_false_positive(ctx: dict[str, Any]) -> dict[str, Any]:
    """Return whether a result is likely a false positive.

    Does not suppress a legitimate vulnerability merely because the response
    looks normal. Always allows manual review.
    """
    reasons: list[str] = []
    status_code = ctx.get("status_code")
    body = ctx.get("response_body") or ""
    protected_exposed = bool(ctx.get("protected_data_exposed", False))
    authz_bypass = bool(ctx.get("authorization_bypass", False))

    if ctx.get("public_resource"):
        reasons.append("resource is intentionally public")
    if ctx.get("authorized_access") and not protected_exposed:
        reasons.append("access appears authorized")
    if ctx.get("cached_response"):
        reasons.append("response may be cached")
    if status_code in (401, 403, 404) and not protected_exposed:
        reasons.append("error/deny response without data exposure")
    if status_code and int(status_code) >= 500 and not protected_exposed:
        reasons.append("server error response")
    if not (body or "").strip() and not protected_exposed:
        reasons.append("empty response body")
    if ctx.get("auth_failure"):
        reasons.append("authentication failure")
    if ctx.get("env_inconsistent"):
        reasons.append("test environment inconsistency")
    if ctx.get("expected_behavior"):
        reasons.append("matches expected application behavior")

    # Never treat clear exposure/bypass as FP just because status looks normal.
    if protected_exposed or authz_bypass:
        return {
            "is_likely_fp": False,
            "reasons": ["protected exposure or bypass present; not suppressed"],
            "allow_manual_review": True,
        }

    return {
        "is_likely_fp": bool(reasons),
        "reasons": reasons,
        "allow_manual_review": True,
    }
