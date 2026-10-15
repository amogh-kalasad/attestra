"""Import hook: emit finding.created and auto-capture proof. Never fails the import."""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

log = logging.getLogger(__name__)


def after_import(s: Session, engagement_id: int, tool: str, data: bytes, new_findings: list, *, actor: str) -> None:
    from attestra.proof.capture import capture_from_import
    from attestra.webhooks.service import safe_emit_finding

    try:
        with s.begin_nested():
            capture_from_import(s, engagement_id, tool, data, actor=actor)
    except Exception:  # noqa: BLE001
        log.exception("proof auto-capture failed for %s import", tool)
    for f in new_findings:
        safe_emit_finding(s, f, "finding.created", actor=actor)
