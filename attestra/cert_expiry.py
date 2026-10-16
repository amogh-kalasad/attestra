"""Certificate expiry bands, findings, and a daily saved-date alert job.

Warn before expiry (30 / 14 / 7 day bands). One finding per certificate, updated
in place when the band changes. The daily job reads SAVED end dates only (no new
network) and emits ``cert.expiring`` once per band via the webhook system.
"""
# @lat: [[findings#Certificate expiry warning]]

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra import audit
from attestra.fingerprint import caa_host
from attestra.importers.base import NormalizedFinding
from attestra.models import (
    OPEN_STATUSES,
    Asset,
    CertExpiryAlert,
    Engagement,
    Finding,
    ImportRun,
    ScanRun,
    utcnow,
)

log = logging.getLogger(__name__)

CERT_EXPIRY_VARIANT = "cert_expirationStatus"
CERT_EXPIRY_CWE = 298
CERT_EXPIRY_PARAM = "cert_expirationStatus"
# Band labels used in storage and webhook payloads (narrowest threshold crossed).
BAND_30 = "30"
BAND_14 = "14"
BAND_7 = "7"
BAND_EXPIRED = "expired"

_NOT_AFTER_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d",
    "%b %d %H:%M:%S %Y %Z",
    "%b %d %H:%M:%S %Y GMT",
)
_DAYS_AGO_RE = re.compile(r"(\d+)\s*days?\s*ago", re.I)
_EXPIRES_IN_RE = re.compile(r"(?:expires?\s+in|expire\s+in|<)\s*(\d+)\s*days?", re.I)


def today_utc() -> date:
    """Calendar day used for band math; tests monkeypatch this."""
    return datetime.now(UTC).date()


def parse_not_after(text: str) -> date | None:
    """Parse a certificate notAfter string into a date, or None if unknown."""
    raw = (text or "").strip()
    if not raw or raw == "—":
        return None
    # Drop trailing timezone words that strptime %Z may not accept on all platforms.
    cleaned = raw
    for fmt in _NOT_AFTER_FORMATS:
        try:
            return datetime.strptime(cleaned, fmt).date()
        except ValueError:
            continue
    # OpenSSL-style without relying on %Z.
    try:
        return datetime.strptime(raw.rsplit(" ", 1)[0] if raw.endswith("GMT") else raw, "%b %d %H:%M:%S %Y").date()
    except ValueError:
        return None


def days_left(end: date, *, today: date | None = None) -> int:
    """Whole days from today until end (negative when already past)."""
    return (end - (today or today_utc())).days


def expiry_band(days: int) -> str | None:
    """Map days left to a warning band.

    - ``None`` when 30 or more days remain (no finding).
    - ``\"30\"`` when under 30 but not under 14 (Low).
    - ``\"14\"`` when under 14 but not under 7 (Medium).
    - ``\"7\"`` when under 7 but still positive (High).
    - ``\"expired\"`` when 0 or negative.
    """
    if days <= 0:
        return BAND_EXPIRED
    if days < 7:
        return BAND_7
    if days < 14:
        return BAND_14
    if days < 30:
        return BAND_30
    return None


def band_severity(band: str) -> str:
    return {
        BAND_30: "low",
        BAND_14: "medium",
        BAND_7: "high",
        BAND_EXPIRED: "high",
    }.get(band, "low")


def band_title(band: str, days: int) -> str:
    if band == BAND_EXPIRED:
        return "TLS: certificate expired"
    n = max(days, 0)
    return f"Certificate expires soon ({n} days)"


def is_cert_expiry_variant(variant: str) -> bool:
    v = (variant or "").strip().lower()
    return v in {CERT_EXPIRY_VARIANT.lower(), "cert_expiration", "cert_expiring"}


def finding_for_end_date(
    *,
    end: date,
    location: str,
    tool: str,
    rule_id: str,
    today: date | None = None,
) -> NormalizedFinding | None:
    """Build one expiry finding for ``end``, or None when more than 30 days remain."""
    left = days_left(end, today=today)
    band = expiry_band(left)
    if band is None:
        return None
    title = band_title(band, left)
    if band == BAND_EXPIRED:
        description = f"Certificate notAfter {end.isoformat()} (expired {-left} day(s) ago)."
        recommendation = "Replace the expired certificate and reload the TLS service."
    else:
        description = f"Certificate notAfter {end.isoformat()} ({left} day(s) left)."
        recommendation = "Replace the certificate before it expires."
    return NormalizedFinding(
        tool=tool,
        rule_id=rule_id,
        title=title,
        severity=band_severity(band),
        location=location,
        description=description,
        recommendation=recommendation,
        cwe=CERT_EXPIRY_CWE,
        param=CERT_EXPIRY_PARAM,
        variant=CERT_EXPIRY_VARIANT,
    )


def days_from_expiration_text(finding: str) -> int | None:
    """Best-effort days left from testssl cert_expirationStatus text."""
    text = finding or ""
    m = _DAYS_AGO_RE.search(text)
    if m:
        return -int(m.group(1))
    if "expired" in text.lower() or "not yet valid" in text.lower():
        return -1
    m = _EXPIRES_IN_RE.search(text)
    if m:
        return int(m.group(1))
    # e.g. "5 < 30 days"
    m = re.search(r"(\d+)\s*<\s*\d+\s*days?", text, re.I)
    if m:
        return int(m.group(1))
    return None


# ---------------------------------------------------------------- saved end dates (no network)


def _read_bytes(path_str: str) -> bytes | None:
    if not path_str:
        return None
    try:
        p = Path(path_str)
        if p.is_file():
            return p.read_bytes()
    except OSError:
        return None
    return None


def end_date_from_testssl_raw(raw: bytes) -> date | None:
    from attestra.importers import testssl as testssl_importer

    summary = testssl_importer.summarize(raw)
    if not summary.get("scanned"):
        return None
    return parse_not_after(str(summary.get("cert_expiry") or ""))


def end_date_from_webcheck_raw(raw: bytes) -> date | None:
    try:
        doc = json.loads(raw.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeError):
        return None
    if not isinstance(doc, dict):
        return None
    cert = doc.get("certificate")
    if isinstance(cert, dict):
        return parse_not_after(str(cert.get("not_after") or cert.get("notAfter") or ""))
    return None


def end_date_from_raw(tool: str, raw: bytes) -> date | None:
    t = (tool or "").lower()
    if t == "testssl":
        return end_date_from_testssl_raw(raw)
    if t == "webcheck":
        return end_date_from_webcheck_raw(raw)
    return None


def saved_cert_for_asset(s: Session, asset_id: int) -> dict[str, Any] | None:
    """Latest saved certificate end date for a target (scan or import), no network."""
    # Prefer finished scan runs tied to the asset (newest first).
    for run in s.scalars(
        select(ScanRun)
        .where(ScanRun.asset_id == asset_id, ScanRun.tool.in_(("testssl", "webcheck")))
        .order_by(ScanRun.id.desc())
    ):
        raw = _read_bytes(run.raw_artifact_uri or "")
        tool = run.tool
        if raw is None and run.import_run_id:
            imp = s.get(ImportRun, run.import_run_id)
            if imp:
                raw = _read_bytes(imp.raw_path or "")
                tool = imp.tool or tool
        if raw is None:
            continue
        end = end_date_from_raw(tool, raw)
        if end is not None:
            return {"asset_id": asset_id, "end_date": end, "tool": tool, "source": "scan_run", "scan_run_id": run.id}

    asset = s.get(Asset, asset_id)
    if asset is None:
        return None
    host_key = caa_host(asset.identifier)
    for run in s.scalars(
        select(ImportRun)
        .where(ImportRun.engagement_id == asset.engagement_id, ImportRun.tool.in_(("testssl", "webcheck")))
        .order_by(ImportRun.id.desc())
    ):
        raw = _read_bytes(run.raw_path or "")
        if raw is None:
            continue
        end = end_date_from_raw(run.tool, raw)
        if end is None:
            continue
        # Imports may not be asset-scoped; accept when host matches or only one asset.
        if run.tool == "testssl":
            from attestra.importers import testssl as testssl_importer

            summary = testssl_importer.summarize(raw)
            summary_host = caa_host(str(summary.get("host") or ""))
            if summary_host and host_key and summary_host != host_key and not host_key.endswith("." + summary_host):
                if summary_host not in host_key and host_key not in summary_host:
                    continue
        return {
            "asset_id": asset_id,
            "end_date": end,
            "tool": run.tool,
            "source": "import_run",
            "import_run_id": run.id,
        }
    return None


def asset_cert_status(s: Session, asset_id: int, *, today: date | None = None) -> dict[str, Any] | None:
    """UI helper: end date, days left, band, and warning colour class."""
    saved = saved_cert_for_asset(s, asset_id)
    if not saved:
        return None
    end: date = saved["end_date"]
    left = days_left(end, today=today)
    band = expiry_band(left)
    if band == BAND_EXPIRED:
        colour = "crit"
    elif band == BAND_7:
        colour = "crit"
    elif band == BAND_14:
        colour = "med"
    elif band == BAND_30:
        colour = "warn"
    else:
        colour = "ok"
    return {
        "end_date": end.isoformat(),
        "days_left": left,
        "band": band,
        "colour": colour,
        "tool": saved.get("tool"),
    }


# ---------------------------------------------------------------- findings reconcile


def close_renewed_for_asset(
    s: Session,
    *,
    engagement_id: int,
    asset_id: int | None,
    end: date | None,
    actor: str,
    today: date | None = None,
) -> int:
    """Mark open expiry findings fixed when the cert end date is more than 30 days away."""
    if asset_id is None or end is None:
        return 0
    if expiry_band(days_left(end, today=today)) is not None:
        return 0
    closed = 0
    rows = list(
        s.scalars(
            select(Finding).where(
                Finding.engagement_id == engagement_id,
                Finding.asset_id == asset_id,
                Finding.status.in_(OPEN_STATUSES),
            )
        )
    )
    for f in rows:
        tools = " ".join(f.tools or []).lower()
        blob = f"{f.title} {' '.join(f.rule_ids or [])} {tools}".lower()
        if CERT_EXPIRY_CWE and f.cwe == CERT_EXPIRY_CWE and (
            "expir" in blob or CERT_EXPIRY_PARAM in blob or "cert_expiration" in blob
        ):
            f.status = "fixed"
            audit.record(s, actor, "finding.closed_renewed", "finding", f.id, end_date=end.isoformat())
            closed += 1
    return closed


# ---------------------------------------------------------------- daily webhook job


def _alert_row(s: Session, asset_id: int) -> CertExpiryAlert | None:
    return s.scalars(select(CertExpiryAlert).where(CertExpiryAlert.asset_id == asset_id)).first()


def _ensure_alert_row(s: Session, *, tenant_id: int, engagement_id: int, asset_id: int, end: date) -> CertExpiryAlert:
    row = _alert_row(s, asset_id)
    if row is None:
        row = CertExpiryAlert(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            asset_id=asset_id,
            end_date=end,
            alerted_bands=[],
        )
        s.add(row)
        s.flush()
        return row
    if row.end_date != end:
        # Renewed (or different cert): reset which bands were already sent.
        row.end_date = end
        row.alerted_bands = []
    return row


def cert_expiring_payload(*, target: str, days_left_n: int, end_date: date, band: str, asset_id: int, engagement_id: int) -> dict:
    """Webhook data for ``cert.expiring`` — no secrets."""
    return {
        "event": "cert.expiring",
        "target": target,
        "asset_id": asset_id,
        "engagement_id": engagement_id,
        "days_left": days_left_n,
        "end_date": end_date.isoformat(),
        "band": band,
    }


def run_daily_cert_alerts(
    s: Session,
    *,
    today: date | None = None,
    actor: str = "system",
    emit=None,
) -> dict[str, int]:
    """Emit ``cert.expiring`` once per band per certificate from SAVED end dates only.

    ``emit(s, event, tenant_id=..., data=...)`` defaults to [[attestra/webhooks/service.py#emit]].
    Returns counts: checked, alerted, skipped.
    """
    from attestra.webhooks import service as wh

    emit_fn = emit or wh.emit
    day = today or today_utc()
    checked = alerted = skipped = 0

    assets = list(s.scalars(select(Asset).order_by(Asset.id)))
    for asset in assets:
        saved = saved_cert_for_asset(s, asset.id)
        if not saved:
            continue
        checked += 1
        end: date = saved["end_date"]
        left = days_left(end, today=day)
        band = expiry_band(left)
        if band is None or band == BAND_EXPIRED:
            # Expired is covered by the existing finding path; daily job alerts 30/14/7 only.
            if band is None:
                # Healthy: clear alert state for a renewed cert so a future cycle can alert again.
                row = _alert_row(s, asset.id)
                if row is not None and row.end_date != end:
                    row.end_date = end
                    row.alerted_bands = []
            skipped += 1
            continue
        eng = s.get(Engagement, asset.engagement_id)
        if eng is None:
            skipped += 1
            continue
        row = _ensure_alert_row(
            s, tenant_id=eng.tenant_id, engagement_id=eng.id, asset_id=asset.id, end=end
        )
        already = list(row.alerted_bands or [])
        if band in already:
            skipped += 1
            continue
        data = cert_expiring_payload(
            target=asset.identifier,
            days_left_n=left,
            end_date=end,
            band=band,
            asset_id=asset.id,
            engagement_id=eng.id,
        )
        emit_fn(s, "cert.expiring", tenant_id=eng.tenant_id, data=data, actor=actor)
        already.append(band)
        row.alerted_bands = already
        row.updated_at = utcnow()
        alerted += 1
        audit.record(
            s, actor, "cert.expiring", "asset", asset.id,
            band=band, days_left=left, end_date=end.isoformat(),
        )
    s.flush()
    return {"checked": checked, "alerted": alerted, "skipped": skipped}
