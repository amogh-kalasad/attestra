"""Replay saved proof on retest: authorized scope only, pinned IP, safe methods by default.

The comparison only *suggests* fixed / still_open / inconclusive. A tester confirms,
which finalizes a Retest through the existing false-close guarded workflow.
"""

from __future__ import annotations

import difflib
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from attestra import audit, retest, services
from attestra.models import Finding, ProofReplay, Retest, utcnow
from attestra.proof.pair import SAFE_METHODS, HttpPair
from attestra.proof.redact import REDACTED, redact_body, redact_headers
from attestra.proof.store import attach_http_pair, load_pair
from attestra.runner.authorization import AuthorizationError, authorize_target, scope_for_engagement
from attestra.runner.dns_pin import PinnedTarget, pin_url
from attestra.webhooks.transport import pinned_request

UNSAFE_ROLES = ("lead", "admin")
SIMILAR = 0.9


def compare(original: HttpPair, status: int | None, body: str) -> tuple[str, str]:
    """Return (suggested result, reason)."""
    if status is None:
        return "inconclusive", "no response"
    if original.match:
        if original.match in body:
            return "still_open", "proof marker still present in response"
        return "fixed", f"proof marker absent (status {status})"
    if original.status is not None and status != original.status:
        return "fixed", f"status changed {original.status} -> {status}"
    ratio = difflib.SequenceMatcher(None, original.response_body[:20000], body[:20000]).ratio()
    if ratio >= SIMILAR:
        return "still_open", f"same status and response {ratio:.0%} similar"
    return "inconclusive", f"same status, response only {ratio:.0%} similar; review manually"


def replay(
    s: Session,
    finding_id: int,
    evidence_id: int,
    *,
    actor: str,
    role: str | None = None,
    allow_unsafe: bool = False,
    retest_id: int | None = None,
    pin: PinnedTarget | None = None,
    resolver=None,
    timeout: float = 10.0,
) -> ProofReplay:
    """Replay one saved request. ``pin`` / ``resolver`` exist for tests only (not exposed by the API)."""
    f = s.get(Finding, finding_id)
    if not f:
        raise LookupError(f"finding {finding_id} not found")
    eng = services.get_engagement(s, f.engagement_id)
    if eng.status == "halted":
        raise services.ServiceError("engagement is halted; replay not allowed")
    if retest_id is not None:
        rt = s.get(Retest, retest_id)
        if not rt or rt.finding_id != f.id:
            raise LookupError(f"retest {retest_id} not found on finding")
    original = load_pair(s, evidence_id, f)
    method = original.method.upper()
    unsafe_by = ""
    if method not in SAFE_METHODS:
        if not allow_unsafe:
            raise services.ServiceError(f"method {method} not allowed for replay; a lead must explicitly allow unsafe methods")
        if role not in UNSAFE_ROLES:
            raise services.ServiceError(f"only lead or admin may allow {method} replay")
        unsafe_by = actor

    try:
        scope = scope_for_engagement(s, f.engagement_id)
        authorize_target(scope, original.url, "url")
        target = pin or pin_url(original.url, scope, **({"resolver": resolver} if resolver else {}))
        if target.host != (urlsplit(original.url).hostname or "").lower():
            raise AuthorizationError("pinned host does not match proof URL")
    except AuthorizationError as exc:
        audit.record(s, actor, "proof.replay_refused", "finding", f.id, url=original.url, reason=str(exc))
        raise services.ServiceError(f"replay target not in scope: {exc}") from exc

    parts = urlsplit(original.url)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    headers = {k: v for k, v in original.request_headers.items() if REDACTED not in v}
    headers.setdefault("User-Agent", "attestra-replay/1")
    body = original.request_body.encode() if method not in SAFE_METHODS and original.request_body else None

    row = ProofReplay(
        finding_id=f.id, evidence_id=evidence_id, retest_id=retest_id, method=method, url=original.url,
        replayed_by=actor, unsafe_allowed_by=unsafe_by,
    )
    try:
        resp = pinned_request(target, method, path, headers=headers, body=body, timeout=timeout)
        text = resp.body.decode("utf-8", "replace")
        row.status_code = resp.status
        row.suggested, row.reason = compare(original, resp.status, text)
        got = HttpPair(
            method=method, url=original.url, request_headers=redact_headers(headers), request_body=redact_body(body.decode() if body else ""),
            status=resp.status, response_headers=resp.headers, response_body=text, match=original.match, source="replay",
        )
    except OSError as exc:
        row.error = str(exc)[:500]
        row.suggested, row.reason = "inconclusive", "request failed"
        got = None
    s.add(row)
    s.flush()
    if got is not None:
        ev = attach_http_pair(s, f.id, got, actor=actor, note=f"replay #{row.id} of evidence {evidence_id}")
        row.response_evidence_id = ev.id
    audit.record(
        s, actor, "proof.replay", "proof_replay", row.id, finding_id=f.id, method=method, url=original.url,
        status=row.status_code, suggested=row.suggested, unsafe_allowed_by=unsafe_by,
    )
    return row


def confirm(s: Session, replay_id: int, *, result: str, actor: str, user_id: int | None = None, note: str = "") -> ProofReplay:
    """Tester confirms (or overrides) the suggestion; finalizes a Retest."""
    row = s.get(ProofReplay, replay_id)
    if not row:
        raise LookupError(f"replay {replay_id} not found")
    if row.confirmed_at is not None:
        raise services.ServiceError("replay already confirmed")
    if result not in ("fixed", "still_open", "inconclusive"):
        raise services.ServiceError("result must be fixed | still_open | inconclusive")
    rid = row.retest_id
    if rid is None:
        rid = retest.request_retest(s, row.finding_id, actor=actor, user_id=user_id, note=f"proof replay #{row.id}").id
        row.retest_id = rid
    reached = row.status_code is not None
    retest.finalize_retest(
        s, rid, result=result, actor=actor, force_asset_reached=reached,
        note=(note or f"proof replay #{row.id}: suggested {row.suggested} ({row.reason})"),
    )
    row.confirmed_result, row.confirmed_by, row.confirmed_at = result, actor, utcnow()
    audit.record(s, actor, "proof.replay_confirm", "proof_replay", row.id, result=result, suggested=row.suggested, retest_id=rid)
    return row
