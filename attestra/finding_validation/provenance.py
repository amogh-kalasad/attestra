"""Validation and evidence provenance (H-02).

:func:`build` returns a JSON-safe dict that INT stores in ``Evidence.provenance_json``
(see WIRING_WP3.md). It is metadata *about* evidence: it never reads, rewrites or
re-hashes the evidence bytes, so the original sha256 stays the integrity anchor.

Confidence is never presented as certainty: the numeric value is capped below 1.0 and
the label vocabulary stops at ``high``.
"""
# @lat: [[intel-and-reporting#Evidence provenance]]

from __future__ import annotations

import json
from datetime import UTC, datetime

PROVENANCE_VERSION = "prov1"
MAX_CONFIDENCE = 0.95
CONFIDENCE_LABELS = ("low", "medium", "high")  # never "certain" / "confirmed"
_RUN_VALIDITY_STATES = frozenset(
    {"VALID", "PARTIALLY_BLOCKED", "CHALLENGE_DETECTED", "RATE_LIMITED", "AUTH_EXPIRED",
     "NETWORK_FAILED", "INCONCLUSIVE"}
)
# A non-VALID run lowers confidence; the evidence itself is still kept as-is.
_VALIDITY_PENALTY = {
    "VALID": 1.0, "PARTIALLY_BLOCKED": 0.8, "RATE_LIMITED": 0.7, "CHALLENGE_DETECTED": 0.5,
    "AUTH_EXPIRED": 0.5, "NETWORK_FAILED": 0.4, "INCONCLUSIVE": 0.5,
}


def confidence_label(value: float | None) -> str:
    if value is None:
        return "unknown"
    if value >= 0.75:
        return "high"
    if value >= 0.45:
        return "medium"
    return "low"


def _ts(value) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def normalize_run_validity(run_validity) -> str:
    """Accept a state string or the ``result_json.run_validity`` dict (PHASE2 §3.2)."""
    if isinstance(run_validity, dict):
        run_validity = run_validity.get("state")
    state = str(run_validity or "").strip().upper()
    return state if state in _RUN_VALIDITY_STATES else ("NOT_COMPUTED" if not state else "INCONCLUSIVE")


def build(
    *,
    confidence: float | None = None,
    captured_at=None,
    now: datetime | None = None,
    tool: str = "",
    rule_id: str = "",
    rule_version: str = "",
    template_version: str = "",
    run_validity=None,
    identity_label: str = "",
    asset_snapshot_id: str | int | None = None,
    execution_id: int | None = None,
    evidence_sha256: str = "",
    validation_status: str = "",
) -> dict:
    """Build the provenance dict for one piece of evidence / one validation decision.

    ``identity_label`` must be a role label (e.g. ``"tenant-a:standard-user"``), never a
    username, token or password; values that look like secrets are dropped.
    """
    now = now or datetime.now(UTC)
    state = normalize_run_validity(run_validity)
    raw_conf = None if confidence is None else max(0.0, min(float(confidence), 1.0))
    adj = None
    if raw_conf is not None:
        adj = raw_conf * _VALIDITY_PENALTY.get(state, 0.6)
        adj = round(min(adj, MAX_CONFIDENCE), 3)
    cap_ts = _ts(captured_at)
    age = None if cap_ts is None else max(int((now - cap_ts).total_seconds()), 0)
    ident = (identity_label or "").strip()[:80]
    if any(tok in ident.lower() for tok in ("bearer", "token", "password", "secret", "cookie", "eyj")):
        ident = "[redacted-identity-label]"
    notes: list[str] = ["confidence is an estimate, not certainty"]
    if state not in ("VALID",):
        notes.append(f"run validity {state}: confidence reduced; zero findings in this run do not imply absence")
    return {
        "version": PROVENANCE_VERSION,
        "confidence": adj,
        "confidence_input": raw_conf,
        "confidence_label": confidence_label(adj),
        "evidence_captured_at": cap_ts.isoformat() if cap_ts else None,
        "evidence_age_seconds": age,
        "tool": tool or "",
        "rule_id": rule_id or "",
        "rule_version": rule_version or "",
        "template_version": template_version or "",
        "run_validity": state,
        "identity_label": ident,
        "asset_snapshot_id": None if asset_snapshot_id in (None, "") else str(asset_snapshot_id),
        "execution_id": execution_id,
        "evidence_sha256": evidence_sha256 or "",
        "validation_status": validation_status or "",
        "notes": notes,
    }


def dumps(prov: dict) -> str:
    """Deterministic JSON for ``Evidence.provenance_json``."""
    return json.dumps(prov, sort_keys=True, separators=(",", ":"))


def loads(text: str | None) -> dict:
    if not text:
        return {}
    try:
        doc = json.loads(text)
    except (TypeError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}
