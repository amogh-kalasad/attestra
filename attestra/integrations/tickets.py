"""Ticket sync for ``Finding.ticket_ref`` (Jira, GitHub Issues).

Off by default: nothing leaves the box until ``ATTESTRA_TICKETS_BACKEND`` is
set to ``jira`` or ``github`` and the matching credentials are configured.
``ticket_ref`` is stored as ``<backend>:<key>`` (``jira:SEC-12``,
``github:acme/app#34``) so status webhooks can find the finding again.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import urllib.request
from collections.abc import Callable
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra import audit
from attestra.models import TRANSITIONS, Finding

BACKENDS = ("jira", "github")
# Called as http(method, url, headers, body) -> parsed JSON response.
HttpCall = Callable[[str, str, dict[str, str], dict[str, Any] | None], dict[str, Any]]


class TicketError(RuntimeError):
    pass


class TicketClient(Protocol):
    name: str

    def create(self, finding: Finding) -> str: ...


def http_json(method: str, url: str, headers: dict[str, str], body: dict[str, Any] | None, *, timeout: float = 10.0) -> dict[str, Any]:
    if not url.startswith("https://"):
        raise TicketError("ticket backends must use https")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - https enforced above
        raw = resp.read()
    return json.loads(raw) if raw else {}


def summary(f: Finding) -> str:
    return f"[{f.severity.upper()}] {f.title}"[:250]


def body_text(f: Finding) -> str:
    lines = [
        f"Attestra finding #{f.id} (engagement {f.engagement_id})",
        f"Severity: {f.severity}  Risk score: {f.risk_score}",
        f"Location: {f.location}",
    ]
    if f.cves:
        lines.append("CVEs: " + ", ".join(f.cves))
    if f.cwe:
        lines.append(f"CWE-{f.cwe}")
    if f.sla_due:
        lines.append(f"SLA due: {f.sla_due}")
    lines += ["", f.description or "", "", "Recommendation:", f.recommendation or ""]
    return "\n".join(lines).strip()


def client_from_env(env: dict[str, str] | None = None, *, http: HttpCall | None = None) -> TicketClient | None:
    """Return the configured client, or None when ticket sync is disabled."""
    env = dict(os.environ) if env is None else env
    backend = env.get("ATTESTRA_TICKETS_BACKEND", "").strip().lower()
    if not backend:
        return None
    if backend == "jira":
        from attestra.integrations.jira import JiraClient

        return JiraClient.from_env(env, http=http)
    if backend == "github":
        from attestra.integrations.github import GitHubIssuesClient

        return GitHubIssuesClient.from_env(env, http=http)
    raise TicketError(f"unknown ticket backend '{backend}'; supported: {', '.join(BACKENDS)}")


def sync_ticket(s: Session, finding_id: int, *, actor: str, client: TicketClient | None = None) -> Finding:
    """Open a ticket for the finding (idempotent: an existing ticket_ref is kept)."""
    f = s.get(Finding, finding_id)
    if not f:
        raise LookupError(f"finding {finding_id} not found")
    if f.ticket_ref:
        return f
    client = client or client_from_env()
    if client is None:
        raise TicketError("ticket sync is disabled; set ATTESTRA_TICKETS_BACKEND")
    key = client.create(f)
    f.ticket_ref = f"{client.name}:{key}"
    audit.record(s, actor, "finding.ticket_created", "finding", f.id, ticket_ref=f.ticket_ref)
    return f


# Ticket state -> finding status we try to move to (only along allowed TRANSITIONS).
_STATE_TARGET = {"closed": "fixed", "done": "fixed", "resolved": "fixed", "reopened": "validated", "open": "validated"}


def apply_ticket_state(s: Session, ticket_ref: str, state: str, *, actor: str) -> Finding | None:
    """Back-sync from a tracker webhook. Never skips the workflow: if the move
    is not an allowed transition the event is only audited."""
    f = s.scalars(select(Finding).where(Finding.ticket_ref == ticket_ref)).first()
    if not f:
        return None
    target = _STATE_TARGET.get(state.strip().lower())
    if target and target != f.status and target in TRANSITIONS.get(f.status, set()):
        prev = f.status
        f.status = target
        audit.record(s, actor, "finding.transition", "finding", f.id, frm=prev, to=target, note=f"ticket {ticket_ref} {state}")
    else:
        audit.record(s, actor, "finding.ticket_state", "finding", f.id, ticket_ref=ticket_ref, state=state, applied=False)
    return f


def verify_signature(secret: str, body: bytes, signature: str) -> bool:
    """HMAC-SHA256 over the raw body; accepts ``sha256=<hex>`` (GitHub style) or bare hex."""
    if not secret or not signature:
        return False
    sig = signature.split("=", 1)[1] if signature.startswith("sha256=") else signature
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig.strip())


def parse_webhook(backend: str, payload: dict[str, Any]) -> tuple[str, str] | None:
    """Return (ticket_ref, state) from a Jira or GitHub webhook payload."""
    if backend == "jira":
        issue = payload.get("issue") or {}
        key = issue.get("key")
        status = (((issue.get("fields") or {}).get("status") or {}).get("name") or "")
        return (f"jira:{key}", status) if key and status else None
    if backend == "github":
        issue = payload.get("issue") or {}
        repo = (payload.get("repository") or {}).get("full_name")
        action = payload.get("action", "")
        if not (repo and issue.get("number")):
            return None
        state = "reopened" if action == "reopened" else issue.get("state", "")
        return f"github:{repo}#{issue['number']}", state
    return None
