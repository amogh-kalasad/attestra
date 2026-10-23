"""Public signed-report verification: HMAC URL tokens and safe view payload."""
# @lat: [[interfaces#Public report verification]]
# @lat: [[reports#Verification#Public page]]

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra import config
from attestra.models import Engagement, Report, ScanRun
from attestra.reports import signing
from attestra.reports.render import verify_report
from attestra.verify.qr_svg import qr_svg


def _hmac_key() -> bytes:
    from attestra.secret_store import get_secret

    return get_secret("session_secret", config.SESSION_SECRET).encode("utf-8")


def make_sig(report_id: int, sha256_hex: str) -> str:
    """HMAC-SHA256 hex over ``{rid}:{sha256}`` for public verify URLs."""
    msg = f"{report_id}:{sha256_hex}".encode()
    return hmac.new(_hmac_key(), msg, hashlib.sha256).hexdigest()


def check_sig(report_id: int, sha256_hex: str, sig: str) -> bool:
    if not sig or not sha256_hex:
        return False
    expected = make_sig(report_id, sha256_hex)
    return hmac.compare_digest(expected, sig.strip().lower())


def verify_path(report_id: int, sig: str) -> str:
    """Relative path for the public verify page (caller prefixes absolute origin)."""
    return f"/verify/reports/{report_id}?sig={sig}"


def absolute_verify_url(base_url: str, report_id: int, sha256_hex: str) -> str:
    base = (base_url or "").rstrip("/")
    sig = make_sig(report_id, sha256_hex)
    return f"{base}{verify_path(report_id, sig)}"


def engagement_untested(s: Session, engagement_id: int) -> bool:
    """True when no asset in the engagement has a completed scan (P0-4)."""
    has_scan = s.scalar(
        select(ScanRun.id)
        .where(
            ScanRun.engagement_id == engagement_id,
            ScanRun.status.in_(("done", "succeeded", "completed")),
        )
        .limit(1)
    )
    return has_scan is None


def public_view(s: Session, report_id: int, sig: str, *, base_url: str = "") -> dict[str, Any] | None:
    """Safe public payload for a signed report with a valid HMAC, or None.

    Never includes findings, evidence, sealed HTML, or letter grades.
    """
    r = s.get(Report, report_id)
    if r is None or r.status != "signed" or not r.signature or not r.sha256:
        return None
    if not check_sig(report_id, r.sha256, sig):
        return None

    eng = s.get(Engagement, r.engagement_id)
    eng_name = (eng.name if eng else "") or f"Engagement {r.engagement_id}"

    try:
        check = verify_report(s, r.id)
        hash_matches = bool(check.get("hash_matches"))
        signature_valid = bool(check.get("signature_valid"))
        algorithm = check.get("algorithm") or r.algorithm or signing.algorithm_of(r.signature)
    except (OSError, LookupError):
        hash_matches = False
        signature_valid = bool(r.signature) and signing.verify(r.sha256, r.signature)
        algorithm = r.algorithm or signing.algorithm_of(r.signature)

    url = absolute_verify_url(base_url or "http://localhost", report_id, r.sha256)
    untested = engagement_untested(s, r.engagement_id)

    return {
        "report_id": r.id,
        "kind": r.kind,
        "framework": r.framework or "",
        "version": r.version,
        "engagement_name": eng_name,
        "sha256": r.sha256,
        "signed_at": r.signed_at,
        "signer": r.approved_by or "",
        "algorithm": algorithm,
        "hash_matches": hash_matches,
        "signature_valid": signature_valid,
        "verified": hash_matches and signature_valid,
        "verify_url": url,
        "qr_svg": qr_svg(url),
        # P0-4: never expose grade/score; flag when engagement has no completed scan.
        "untested": untested,
        "grade": None,
        "score": None,
    }
