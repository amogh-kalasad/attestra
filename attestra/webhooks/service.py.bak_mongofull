"""Endpoints, workflow rules, event emission (queue) and delivery with retry/backoff."""

from __future__ import annotations

import logging
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra import audit
from attestra.models import (
    SEVERITIES,
    Engagement,
    Finding,
    FindingAssignment,
    WebhookDelivery,
    WebhookEndpoint,
    WorkflowRule,
    utcnow,
)
from attestra.webhooks import formats
from attestra.webhooks.guard import WebhookUrlError, check_url
from attestra.webhooks.transport import pinned_request

log = logging.getLogger(__name__)

BACKOFF_SECONDS = (30, 120, 600, 1800, 7200)
MAX_ATTEMPTS = len(BACKOFF_SECONDS) + 1
ACTIONS = ("notify", "assign", "ticket")
# sender(endpoint, body, headers) -> HTTP status code
Sender = Callable[[WebhookEndpoint, bytes, dict[str, str]], int]


class WebhookError(ValueError):
    pass


def _rank(sev: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(sev, 0)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


# ---------------------------------------------------------------- endpoints


def create_endpoint(
    s: Session, tenant_id: int, *, url: str, actor: str, name: str = "", fmt: str = "json",
    events: list[str] | None = None, resolver=None,
) -> WebhookEndpoint:
    if fmt not in formats.FORMATS:
        raise WebhookError(f"format must be one of {', '.join(formats.FORMATS)}")
    events = list(dict.fromkeys(events or []))
    bad = [e for e in events if e not in formats.EVENTS]
    if bad:
        raise WebhookError(f"unknown events: {', '.join(bad)}")
    try:
        check_url(url, **({"resolver": resolver} if resolver else {}))
    except WebhookUrlError as exc:
        raise WebhookError(str(exc)) from exc
    ep = WebhookEndpoint(
        tenant_id=tenant_id, name=name, url=url.strip(), secret=secrets.token_hex(32), format=fmt, events=events, created_by=actor,
    )
    s.add(ep)
    s.flush()
    audit.record(s, actor, "webhook.create", "webhook_endpoint", ep.id, tenant_id=tenant_id, host=urlsplit(url).hostname, events=events)
    return ep


def deactivate_endpoint(s: Session, endpoint_id: int, *, actor: str) -> WebhookEndpoint:
    ep = s.get(WebhookEndpoint, endpoint_id)
    if not ep:
        raise LookupError(f"webhook {endpoint_id} not found")
    ep.active = False
    audit.record(s, actor, "webhook.deactivate", "webhook_endpoint", ep.id)
    return ep


# ---------------------------------------------------------------- rules


def create_rule(
    s: Session, tenant_id: int, *, action: str, actor: str, name: str = "", event: str = "", min_severity: str = "info",
    status: str = "", endpoint_id: int | None = None, assignee: str = "",
) -> WorkflowRule:
    if action not in ACTIONS:
        raise WebhookError(f"action must be one of {', '.join(ACTIONS)}")
    if min_severity not in SEVERITIES:
        raise WebhookError(f"min_severity must be one of {', '.join(SEVERITIES)}")
    if event and event not in formats.EVENTS:
        raise WebhookError(f"unknown event {event}")
    if action == "notify":
        ep = s.get(WebhookEndpoint, endpoint_id) if endpoint_id else None
        if not ep or ep.tenant_id != tenant_id:
            raise WebhookError("notify rules need a webhook endpoint of the same tenant")
    if action == "assign" and not assignee.strip():
        raise WebhookError("assign rules need an assignee")
    rule = WorkflowRule(
        tenant_id=tenant_id, name=name, event=event, min_severity=min_severity, status=status, action=action,
        endpoint_id=endpoint_id if action == "notify" else None, assignee=assignee.strip(), created_by=actor,
    )
    s.add(rule)
    s.flush()
    audit.record(s, actor, "workflow_rule.create", "workflow_rule", rule.id, tenant_id=tenant_id, rule_action=action)
    return rule


def deactivate_rule(s: Session, rule_id: int, *, actor: str) -> WorkflowRule:
    """Soft-deactivate a workflow rule (sets active=False; does not delete the row)."""
    rule = s.get(WorkflowRule, rule_id)
    if not rule:
        raise LookupError(f"rule {rule_id} not found")
    rule.active = False
    audit.record(s, actor, "workflow_rule.deactivate", "workflow_rule", rule.id)
    return rule


def rule_matches(rule: WorkflowRule, event: str, finding: Finding) -> bool:
    if not rule.active or (rule.event and rule.event != event):
        return False
    if _rank(finding.severity) < _rank(rule.min_severity):
        return False
    return not rule.status or rule.status == finding.status


# ---------------------------------------------------------------- emit


def _queue(s: Session, ep: WebhookEndpoint, event: str, data: dict) -> WebhookDelivery:
    d = WebhookDelivery(tenant_id=ep.tenant_id, endpoint_id=ep.id, event=event, payload=data, next_attempt_at=utcnow(), last_error="")
    s.add(d)
    return d


def finding_data(f: Finding, **extra) -> dict:
    return {
        "finding_id": f.id, "engagement_id": f.engagement_id, "title": f.title, "severity": f.severity,
        "status": f.status, "risk_score": f.risk_score, "location": f.location, **extra,
    }


def emit(s: Session, event: str, *, tenant_id: int, data: dict, finding: Finding | None = None, actor: str = "system") -> list[WebhookDelivery]:
    """Queue deliveries for subscribed endpoints and run matching workflow rules."""
    out: list[WebhookDelivery] = []
    queued: set[int] = set()
    for ep in s.scalars(select(WebhookEndpoint).where(WebhookEndpoint.tenant_id == tenant_id, WebhookEndpoint.active.is_(True))):
        if not ep.events or event in ep.events:
            out.append(_queue(s, ep, event, data))
            queued.add(ep.id)
    if finding is not None:
        rules = s.scalars(select(WorkflowRule).where(WorkflowRule.tenant_id == tenant_id, WorkflowRule.active.is_(True)).order_by(WorkflowRule.id))
        for rule in rules:
            if not rule_matches(rule, event, finding):
                continue
            if rule.action == "notify" and rule.endpoint_id and rule.endpoint_id not in queued:
                ep = s.get(WebhookEndpoint, rule.endpoint_id)
                if ep and ep.active and ep.tenant_id == tenant_id:
                    out.append(_queue(s, ep, event, {**data, "rule_id": rule.id}))
                    queued.add(ep.id)
            elif rule.action == "assign":
                s.add(FindingAssignment(finding_id=finding.id, assignee=rule.assignee, rule_id=rule.id, assigned_by=f"rule:{rule.id}"))
                audit.record(s, actor, "finding.assigned", "finding", finding.id, assignee=rule.assignee, rule_id=rule.id)
            elif rule.action == "ticket":
                _ticket(s, finding, rule, actor)
    s.flush()
    return out


def _ticket(s: Session, finding: Finding, rule: WorkflowRule, actor: str) -> None:
    from attestra.integrations.tickets import TicketError, sync_ticket

    try:
        sync_ticket(s, finding.id, actor=f"rule:{rule.id}")
    except (TicketError, OSError) as exc:
        audit.record(s, actor, "workflow.ticket_skipped", "finding", finding.id, rule_id=rule.id, reason=str(exc)[:300])


def safe_emit_finding(s: Session, finding: Finding, event: str, *, actor: str = "system", **extra) -> None:
    """Hook used by services/retest; never breaks the calling business operation."""
    try:
        s.flush()
        eng = s.get(Engagement, finding.engagement_id)
        if eng is not None:
            emit(s, event, tenant_id=eng.tenant_id, data=finding_data(finding, **extra), finding=finding, actor=actor)
    except Exception:  # noqa: BLE001
        log.exception("webhook emit failed for %s", event)


def safe_emit_report(s: Session, report, *, actor: str = "system") -> None:
    try:
        eng = s.get(Engagement, report.engagement_id)
        if eng is not None:
            data = {"report_id": report.id, "engagement_id": report.engagement_id, "kind": report.kind, "version": report.version,
                    "sha256": report.sha256, "signed_by": report.approved_by}
            emit(s, "report.signed", tenant_id=eng.tenant_id, data=data, actor=actor)
    except Exception:  # noqa: BLE001
        log.exception("webhook emit failed for report.signed")


def safe_emit_scan(s: Session, run, event: str, *, actor: str = "system", **extra) -> None:
    """Emit a scan lifecycle webhook; never breaks the caller. Cancelled scans must not use scan.finished."""
    try:
        if event == "scan.finished" and getattr(run, "status", "") != "done":
            return
        s.flush()
        eng = s.get(Engagement, run.engagement_id)
        if eng is None:
            return
        data = {
            "scan_id": run.id,
            "engagement_id": run.engagement_id,
            "asset_id": run.asset_id,
            "tool": run.tool,
            "profile": run.profile,
            "status": run.status,
            **extra,
        }
        emit(s, event, tenant_id=eng.tenant_id, data=data, actor=actor)
        if event == "scan.finished":
            from attestra.alerts.service import safe_notify_header_change

            safe_notify_header_change(s, run, actor=actor)
    except Exception:  # noqa: BLE001
        log.exception("webhook emit failed for %s", event)


# ---------------------------------------------------------------- delivery


def default_sender(ep: WebhookEndpoint, body: bytes, headers: dict[str, str]) -> int:
    pin = check_url(ep.url)  # re-validated at send time; connect to the validated IP only
    parts = urlsplit(ep.url)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    return pinned_request(pin, "POST", path, headers=headers, body=body, timeout=10.0, max_body=10_000).status


def deliver(s: Session, d: WebhookDelivery, *, sender: Sender | None = None, now: datetime | None = None) -> WebhookDelivery:
    now = now or utcnow()
    ep = s.get(WebhookEndpoint, d.endpoint_id)
    if not ep or not ep.active:
        d.status, d.last_error = "failed", "endpoint inactive"
        return d
    body = formats.encode(formats.render(ep.format, d.event, d.payload, d.id))
    ts, sig = formats.sign(ep.secret, body)
    headers = {
        "Content-Type": "application/json", "User-Agent": "attestra-webhooks/1", formats.TS_HEADER: ts,
        formats.SIG_HEADER: sig, "X-Attestra-Event": d.event, "X-Attestra-Delivery": str(d.id),
    }
    d.attempts += 1
    try:
        code = (sender or default_sender)(ep, body, headers)
        d.last_status_code, d.last_error = code, ""
        ok = 200 <= code < 300
        if not ok:
            d.last_error = f"HTTP {code}"
    except (OSError, WebhookUrlError) as exc:
        ok, d.last_error = False, str(exc)[:500]
    if ok:
        d.status, d.delivered_at = "delivered", now
    elif d.attempts >= MAX_ATTEMPTS:
        d.status = "failed"
    else:
        d.next_attempt_at = now + timedelta(seconds=BACKOFF_SECONDS[d.attempts - 1])
    return d


def dispatch_due(s: Session, *, sender: Sender | None = None, now: datetime | None = None, limit: int = 50, tenant_ids=None) -> list[WebhookDelivery]:
    now = now or utcnow()
    q = select(WebhookDelivery).where(WebhookDelivery.status == "pending").order_by(WebhookDelivery.id)
    if tenant_ids is not None:
        q = q.where(WebhookDelivery.tenant_id.in_(tenant_ids))
    due = [d for d in s.scalars(q) if _aware(d.next_attempt_at) <= now][:limit]
    for d in due:
        deliver(s, d, sender=sender, now=now)
    s.flush()
    return due
