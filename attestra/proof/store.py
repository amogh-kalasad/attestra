"""Attach proof to a finding through the existing tamper-evident evidence store."""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra import services
from attestra.models import Evidence, Finding
from attestra.proof.pair import HttpPair

# The evidence masker may rewrite IP-like text (e.g. 127.0.0.1:8080) inside the JSON, so the
# redacted target URL is also kept verbatim in the first line of the evidence note.
URL_PREFIX = "proof: "
_IMAGE_MAGIC = (b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"RIFF")


def attach_http_pair(s: Session, finding_id: int, pair: HttpPair, *, actor: str, note: str = "") -> Evidence:
    """Redact credentials, then store as ``http_pair`` evidence (hashed + audited)."""
    safe = pair.redacted()
    return services.add_evidence(
        s, finding_id, kind="http_pair", filename="http_pair.json", data=safe.to_bytes(), note=f"{URL_PREFIX}{safe.method} {safe.url}" + (f"\n{note}" if note else ""), actor=actor
    )


def attach_screenshot(
    s: Session,
    finding_id: int,
    *,
    filename: str,
    data: bytes,
    actor: str,
    note: str = "",
    source_tool: str = "",
    observation_id: int | None = None,
    import_run_id: int | None = None,
    redaction_status: str = "",
) -> Evidence:
    if not data.startswith(_IMAGE_MAGIC):
        raise services.ServiceError("screenshot must be a PNG, JPEG, GIF or WebP image")
    status = redaction_status
    if not status:
        for line in (note or "").splitlines():
            if line.strip().startswith("redaction_status="):
                status = line.strip().split("=", 1)[1].strip()
                break
    return services.add_evidence(
        s,
        finding_id,
        kind="screenshot",
        filename=filename or "screenshot.png",
        data=data,
        note=note,
        actor=actor,
        content_type="image/png" if data.startswith(b"\x89PNG") else "application/octet-stream",
        source_tool=source_tool,
        observation_id=observation_id,
        import_run_id=import_run_id,
        role="original",
        redaction_status=status or "none",
        capture_status="success",
    )


def proof_items(s: Session, finding_id: int) -> list[Evidence]:
    return list(
        s.scalars(
            select(Evidence)
            .where(Evidence.finding_id == finding_id, Evidence.kind.in_(("http_pair", "screenshot")))
            .order_by(Evidence.id)
        )
    )


def load_pair(s: Session, evidence_id: int, finding: Finding) -> HttpPair:
    ev = s.get(Evidence, evidence_id)
    if not ev or ev.finding_id != finding.id or ev.kind != "http_pair":
        raise LookupError(f"http_pair evidence {evidence_id} not found on finding {finding.id}")
    data = Path(ev.path).read_bytes()
    if services._sha256(data) != ev.sha256:
        raise services.ServiceError("evidence hash mismatch; refusing to replay tampered proof")
    doc = json.loads(data.decode("utf-8", "replace"))
    first = (ev.note or "").split("\n", 1)[0]
    if first.startswith(URL_PREFIX):
        method, _, url = first[len(URL_PREFIX):].partition(" ")
        if method.upper() == str(doc.get("method", "")).upper() and url:
            doc["url"] = url
    return HttpPair.from_dict(doc)


def has_http_pair(s: Session, finding_id: int) -> bool:
    return s.scalar(select(Evidence.id).where(Evidence.finding_id == finding_id, Evidence.kind == "http_pair").limit(1)) is not None
