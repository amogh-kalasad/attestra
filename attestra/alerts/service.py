"""Email alert settings and event handlers (new high, header change, SLA missed)."""

from __future__ import annotations

import logging
import os
import re
from datetime import date
from html import escape

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra import audit, services
from attestra.alerts import headers as hdr
from attestra.auth.roles import has_permission
from attestra.models import (
    OPEN_STATUSES,
    Asset,
    EmailAlertSent,
    EmailAlertSettings,
    Engagement,
    Finding,
    ImportRun,
    ScanRun,
    UserInvite,
    utcnow,
)
from attestra.users import mailer

log = logging.getLogger(__name__)

EVENT_NEW_HIGH = "finding.new_high"
EVENT_HEADER_CHANGE = "header.changed"
EVENT_SLA_MISSED = "sla.missed"

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class AlertError(ValueError):
    pass


def public_base_url() -> str:
    return (os.environ.get("ATTESTRA_PUBLIC_URL") or os.environ.get("ATTESTRA_URL") or "").rstrip("/")


def finding_url(engagement_id: int, finding_id: int) -> str:
    base = public_base_url()
    path = f"/engagements/{engagement_id}/findings/{finding_id}"
    return f"{base}{path}" if base else path


def asset_url(engagement_id: int, asset_id: int) -> str:
    base = public_base_url()
    path = f"/engagements/{engagement_id}/targets/{asset_id}"
    return f"{base}{path}" if base else path


def _normalize_emails(raw) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        parts = re.split(r"[\s,;]+", raw)
    else:
        parts = list(raw)
    out: list[str] = []
    seen: set[str] = set()
    for p in parts:
        e = str(p or "").strip().lower()
        if not e or e in seen:
            continue
        if not _EMAIL_RE.match(e):
            raise AlertError(f"invalid email address: {p!r}")
        seen.add(e)
        out.append(e)
    return out


def _check_tenant(s: Session, principal, tenant_id: int) -> None:
    allowed = services.tenant_ids_for(s, principal)
    if allowed is not None and tenant_id not in allowed:
        raise LookupError(f"tenant {tenant_id} not found")
    if not has_permission(principal.role, "webhook.manage"):
        raise AlertError("not allowed to manage email alerts")


def get_settings(s: Session, tenant_id: int) -> EmailAlertSettings | None:
    return s.scalar(select(EmailAlertSettings).where(EmailAlertSettings.tenant_id == tenant_id))


def ensure_settings(s: Session, tenant_id: int) -> EmailAlertSettings:
    row = get_settings(s, tenant_id)
    if row is not None:
        return row
    row = EmailAlertSettings(tenant_id=tenant_id)
    s.add(row)
    s.flush()
    return row


def settings_dict(row: EmailAlertSettings | None, tenant_id: int) -> dict:
    if row is None:
        return {
            "tenant_id": tenant_id,
            "notify_new_high": True,
            "notify_header_change": True,
            "notify_sla_missed": True,
            "recipients": [],
            "updated_by": "",
            "updated_at": None,
        }
    return {
        "tenant_id": row.tenant_id,
        "notify_new_high": bool(row.notify_new_high),
        "notify_header_change": bool(row.notify_header_change),
        "notify_sla_missed": bool(row.notify_sla_missed),
        "recipients": list(row.recipients or []),
        "updated_by": row.updated_by or "",
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def update_settings(
    s: Session,
    principal,
    tenant_id: int,
    *,
    notify_new_high: bool | None = None,
    notify_header_change: bool | None = None,
    notify_sla_missed: bool | None = None,
    recipients=None,
) -> EmailAlertSettings:
    _check_tenant(s, principal, tenant_id)
    row = ensure_settings(s, tenant_id)
    if notify_new_high is not None:
        row.notify_new_high = bool(notify_new_high)
    if notify_header_change is not None:
        row.notify_header_change = bool(notify_header_change)
    if notify_sla_missed is not None:
        row.notify_sla_missed = bool(notify_sla_missed)
    if recipients is not None:
        row.recipients = _normalize_emails(recipients)
    row.updated_by = principal.actor
    row.updated_at = utcnow()
    s.flush()
    audit.record(
        s, principal.actor, "alert.settings.update", "email_alert_settings", row.id,
        tenant_id=tenant_id,
        notify_new_high=row.notify_new_high,
        notify_header_change=row.notify_header_change,
        notify_sla_missed=row.notify_sla_missed,
        recipients_count=len(row.recipients or []),
    )
    return row


def known_tenant_emails(s: Session, tenant_id: int) -> list[str]:
    """Invite emails for this tenant (users do not store email after accept)."""
    rows = s.scalars(
        select(UserInvite.email).where(
            UserInvite.tenant_id == tenant_id,
            UserInvite.email != "",
        )
    )
    return sorted({e.strip().lower() for e in rows if e and _EMAIL_RE.match(e.strip())})


def _recipients_for(s: Session, tenant_id: int, *, event: str) -> list[str]:
    row = get_settings(s, tenant_id)
    # Defaults when no settings row: events on, but no recipients → nothing sent.
    if row is None:
        return []
    enabled = {
        EVENT_NEW_HIGH: row.notify_new_high,
        EVENT_HEADER_CHANGE: row.notify_header_change,
        EVENT_SLA_MISSED: row.notify_sla_missed,
    }.get(event, False)
    if not enabled:
        return []
    return list(row.recipients or [])


def _html_escape_block(text: str) -> str:
    return "<br>\n".join(escape(line) for line in text.splitlines())


def _send(
    s: Session,
    *,
    tenant_id: int,
    event: str,
    subject: str,
    text: str,
    html: str,
    actor: str,
    count: int = 1,
    entity_type: str = "",
    entity_id: int | None = None,
) -> bool:
    recipients = _recipients_for(s, tenant_id, event=event)
    if not recipients:
        return False
    if not mailer.can_send():
        log.info("email alert skipped: ATTESTRA_SMTP_HOST not set (%s)", event)
        return False
    ok = mailer.send_email(recipients, subject, text, html=html)
    if ok:
        audit.record(
            s, actor, "alert.email.sent", entity_type or "tenant", entity_id or tenant_id,
            tenant_id=tenant_id,
            event=event,
            count=count,
            recipients_count=len(recipients),
        )
    return ok


def _already_sent(s: Session, event: str, entity_type: str, entity_id: int) -> bool:
    return (
        s.scalar(
            select(EmailAlertSent.id).where(
                EmailAlertSent.event_type == event,
                EmailAlertSent.entity_type == entity_type,
                EmailAlertSent.entity_id == entity_id,
            )
        )
        is not None
    )


def _mark_sent(s: Session, tenant_id: int, event: str, entity_type: str, entity_id: int) -> None:
    if _already_sent(s, event, entity_type, entity_id):
        return
    s.add(
        EmailAlertSent(
            tenant_id=tenant_id,
            event_type=event,
            entity_type=entity_type,
            entity_id=entity_id,
            sent_at=utcnow(),
        )
    )
    s.flush()


# ---------------------------------------------------------------- new Crit/High (grouped)


def notify_new_high_findings(
    s: Session,
    engagement_id: int,
    findings: list[Finding],
    *,
    actor: str = "system",
) -> bool:
    """One email for all new Critical/High findings from one import/scan."""
    high = [f for f in findings if (f.severity or "").lower() in ("critical", "high")]
    if not high:
        return False
    eng = s.get(Engagement, engagement_id)
    if eng is None:
        return False
    lines = []
    for f in high:
        link = finding_url(engagement_id, f.id)
        lines.append(f"- [{f.severity.upper()}] {f.title} (#{f.id})  {link}")
    target = ""
    asset_ids = {f.asset_id for f in high if f.asset_id}
    if len(asset_ids) == 1:
        asset = s.get(Asset, next(iter(asset_ids)))
        if asset:
            target = asset.name or asset.identifier
    subject = f"Attestra: {len(high)} new Critical/High finding(s)"
    if target:
        subject += f" on {target}"
    text = (
        f"Engagement #{engagement_id}: {eng.name}\n"
        f"Target: {target or '(multiple or unknown)'}\n\n"
        f"New Critical or High findings:\n" + "\n".join(lines) + "\n"
    )
    html = (
        f"<p><strong>Engagement #{engagement_id}</strong>: {escape(eng.name)}</p>"
        f"<p>Target: {escape(target or '(multiple or unknown)')}</p>"
        f"<p>New Critical or High findings:</p><ul>"
        + "".join(
            f"<li><strong>[{escape(f.severity.upper())}]</strong> "
            f"{escape(f.title)} "
            f"(<a href=\"{escape(finding_url(engagement_id, f.id))}\">#{f.id}</a>)</li>"
            for f in high
        )
        + "</ul>"
    )
    return _send(
        s,
        tenant_id=eng.tenant_id,
        event=EVENT_NEW_HIGH,
        subject=subject,
        text=text,
        html=html,
        actor=actor,
        count=len(high),
        entity_type="engagement",
        entity_id=engagement_id,
    )


def safe_notify_new_high(s: Session, engagement_id: int, findings: list, *, actor: str = "system") -> None:
    try:
        notify_new_high_findings(s, engagement_id, findings, actor=actor)
    except Exception:  # noqa: BLE001
        log.exception("email alert failed for new high findings")


# ---------------------------------------------------------------- header change


def _raw_path_for_scan(s: Session, run: ScanRun) -> str:
    if run.import_run_id:
        imp = s.get(ImportRun, run.import_run_id)
        if imp and imp.raw_path:
            return imp.raw_path
    return run.raw_artifact_uri or ""


def header_snapshot_for_scan(s: Session, run: ScanRun) -> dict[str, str]:
    path = _raw_path_for_scan(s, run)
    doc = hdr.load_report(path)
    if doc:
        return hdr.snapshot_from_report(doc)
    # Fall back to checks_json on the scan row.
    if run.checks_json:
        try:
            import json

            raw = json.loads(run.checks_json)
            if isinstance(raw, dict):
                return hdr.snapshot_from_report(raw)
            if isinstance(raw, list):
                return hdr.snapshot_from_report({"checks": raw})
        except (TypeError, ValueError):
            pass
    return {}


def previous_scan(s: Session, run: ScanRun) -> ScanRun | None:
    """Previous finished scan of the same tool on the same asset."""
    rows = list(
        s.scalars(
            select(ScanRun)
            .where(
                ScanRun.asset_id == run.asset_id,
                ScanRun.tool == run.tool,
                ScanRun.status.in_(("done", "quarantined")),
                ScanRun.id < run.id,
            )
            .order_by(ScanRun.id.desc())
            .limit(1)
        )
    )
    return rows[0] if rows else None


def compare_header_change(s: Session, run: ScanRun) -> list[dict[str, str]]:
    """Diff security headers vs the previous scan of the same tool. Empty if none."""
    prev = previous_scan(s, run)
    if prev is None:
        return []
    before = header_snapshot_for_scan(s, prev)
    after = header_snapshot_for_scan(s, run)
    return hdr.diff_headers(before, after)


def draft_header_change_email(s: Session, run: ScanRun, changes: list[dict[str, str]]) -> dict | None:
    """Build subject/text/html for a header-change alert without sending."""
    if not changes:
        return None
    eng = s.get(Engagement, run.engagement_id)
    asset = s.get(Asset, run.asset_id)
    if eng is None or asset is None:
        return None
    target = asset.name or asset.identifier
    link = asset_url(eng.id, asset.id)
    lines = [f"- {c['name']}: {c['before']} → {c['after']}" for c in changes]
    subject = f"Attestra: security header changed on {target}"
    text = (
        f"Engagement #{eng.id}: {eng.name}\n"
        f"Target: {target}\n"
        f"Scan #{run.id} ({run.tool})\n"
        f"Link: {link}\n\n"
        f"Header changes:\n" + "\n".join(lines) + "\n"
    )
    html = (
        f"<p><strong>Engagement #{eng.id}</strong>: {escape(eng.name)}</p>"
        f"<p>Target: <a href=\"{escape(link)}\">{escape(target)}</a></p>"
        f"<p>Scan #{run.id} ({escape(run.tool)})</p>"
        f"<p>Header changes:</p><ul>"
        + "".join(
            f"<li><code>{escape(c['name'])}</code>: "
            f"{escape(c['before'])} → {escape(c['after'])}</li>"
            for c in changes
        )
        + "</ul>"
    )
    return {
        "tenant_id": eng.tenant_id,
        "subject": subject,
        "text": text,
        "html": html,
        "count": len(changes),
        "target": target,
        "changes": changes,
    }


def notify_header_change(s: Session, run: ScanRun, *, actor: str = "system") -> bool:
    changes = compare_header_change(s, run)
    draft = draft_header_change_email(s, run, changes)
    if draft is None:
        return False
    return _send(
        s,
        tenant_id=draft["tenant_id"],
        event=EVENT_HEADER_CHANGE,
        subject=draft["subject"],
        text=draft["text"],
        html=draft["html"],
        actor=actor,
        count=draft["count"],
        entity_type="scan_run",
        entity_id=run.id,
    )


def safe_notify_header_change(s: Session, run: ScanRun, *, actor: str = "system") -> None:
    try:
        if getattr(run, "status", "") not in ("done", "quarantined"):
            return
        tool = (run.tool or "").lower()
        if tool not in ("webcheck", "zap", "observatory"):
            return
        notify_header_change(s, run, actor=actor)
    except Exception:  # noqa: BLE001
        log.exception("email alert failed for header change")


# ---------------------------------------------------------------- SLA missed (once)


def notify_sla_missed(s: Session, finding: Finding, *, actor: str = "system") -> bool:
    eng = s.get(Engagement, finding.engagement_id)
    if eng is None:
        return False
    if _already_sent(s, EVENT_SLA_MISSED, "finding", finding.id):
        return False
    asset = s.get(Asset, finding.asset_id) if finding.asset_id else None
    target = (asset.name or asset.identifier) if asset else finding.location
    link = finding_url(eng.id, finding.id)
    subject = f"Attestra: SLA missed — [{finding.severity}] {finding.title}"
    text = (
        f"Engagement #{eng.id}: {eng.name}\n"
        f"Target: {target}\n"
        f"Finding #{finding.id}: {finding.title}\n"
        f"Severity: {finding.severity}\n"
        f"SLA due: {finding.sla_due}\n"
        f"Status: {finding.status}\n"
        f"Link: {link}\n"
    )
    html = (
        f"<p><strong>Engagement #{eng.id}</strong>: {escape(eng.name)}</p>"
        f"<p>Target: {escape(str(target or ''))}</p>"
        f"<p>Finding <a href=\"{escape(link)}\">#{finding.id}</a>: "
        f"{escape(finding.title)}</p>"
        f"<p>Severity: {escape(finding.severity)} · SLA due: {escape(str(finding.sla_due))} · "
        f"Status: {escape(finding.status)}</p>"
    )
    ok = _send(
        s,
        tenant_id=eng.tenant_id,
        event=EVENT_SLA_MISSED,
        subject=subject,
        text=text,
        html=html,
        actor=actor,
        count=1,
        entity_type="finding",
        entity_id=finding.id,
    )
    if ok:
        _mark_sent(s, eng.tenant_id, EVENT_SLA_MISSED, "finding", finding.id)
    return ok


def run_sla_missed_alerts(
    s: Session,
    *,
    today: date | None = None,
    actor: str = "system",
) -> dict[str, int]:
    """Send one SLA-missed email per open overdue finding (once). Existing scheduler entrypoint."""
    day = today or date.today()
    checked = alerted = skipped = 0
    rows = list(
        s.scalars(
            select(Finding).where(
                Finding.status.in_(OPEN_STATUSES),
                Finding.sla_due.is_not(None),
                Finding.sla_due < day,
            ).order_by(Finding.id)
        )
    )
    for f in rows:
        checked += 1
        if _already_sent(s, EVENT_SLA_MISSED, "finding", f.id):
            skipped += 1
            continue
        if notify_sla_missed(s, f, actor=actor):
            alerted += 1
        else:
            skipped += 1
    return {"checked": checked, "alerted": alerted, "skipped": skipped}
