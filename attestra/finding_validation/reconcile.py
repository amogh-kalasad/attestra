# @lat: [[findings#Lifecycle#Validation class vs workflow status]]
"""Re-apply validation using engagement HTTP and cross-finding evidence after import."""

from __future__ import annotations

import json
import logging
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra.finding_validation.classify import apply_classification_to_finding, classify_observation
from attestra.finding_validation.headers import finding_claims_header_missing
from attestra.finding_validation.statuses import INFORMATIONAL, NOT_REPRODUCIBLE, UNVALIDATED
from attestra.models import Engagement, Evidence, Finding
from attestra.proof.pair import HttpPair

log = logging.getLogger(__name__)


def _origin(url: str) -> str:
    try:
        p = urlparse((url or "").strip())
        if not p.scheme or not p.netloc:
            return ""
        return f"{p.scheme.lower()}://{p.netloc.lower()}"
    except Exception:  # noqa: BLE001
        return ""


def _pair_to_text(pair: HttpPair) -> str:
    parts = [
        pair.url or "",
        "\n".join(f"{k}: {v}" for k, v in (pair.request_headers or {}).items()),
        pair.request_body or "",
        "\n".join(f"{k}: {v}" for k, v in (pair.response_headers or {}).items()),
        pair.response_body or "",
        pair.match or "",
    ]
    return "\n".join(p for p in parts if p)


def _load_http_pair_texts(s: Session, findings: list[Finding], *, tenant_id: int) -> list[tuple[str, str]]:
    """Return (origin, raw_text) for http_pair evidence on these findings."""
    from attestra import services

    ids = [f.id for f in findings if f.id is not None]
    if not ids:
        return []
    rows = list(
        s.scalars(select(Evidence).where(Evidence.finding_id.in_(ids), Evidence.kind == "http_pair"))
    )
    out: list[tuple[str, str]] = []
    for ev in rows:
        try:
            data = services.read_evidence_bytes(ev.path, tenant_id)
            pair = HttpPair.from_bytes(data)
        except Exception:  # noqa: BLE001
            log.debug("skip unreadable http_pair evidence %s", ev.id, exc_info=True)
            continue
        text = _pair_to_text(pair)
        if not text.strip():
            continue
        out.append((_origin(pair.url or ""), text))
        try:
            out.append((_origin(pair.url or ""), json.dumps(json.loads(data.decode("utf-8", "replace")))))
        except Exception:  # noqa: BLE001
            pass
    return out


def _finding_description_texts(findings: list[Finding]) -> list[str]:
    """Cross-finding description/recommendation blobs (ORM findings already in session)."""
    out: list[str] = []
    for f in findings:
        for attr in ("description", "recommendation"):
            v = getattr(f, attr, None)
            if v:
                out.append(str(v))
    return out


def _load_evidence_note_texts(s: Session, findings: list[Finding]) -> list[str]:
    """Evidence.note text from any kind (headers often pasted into notes)."""
    ids = [f.id for f in findings if f.id is not None]
    if not ids:
        return []
    rows = list(s.scalars(select(Evidence).where(Evidence.finding_id.in_(ids))))
    out: list[str] = []
    for ev in rows:
        note = getattr(ev, "note", None) or ""
        if note.strip():
            out.append(str(note))
    return out


def reconcile_validation_from_evidence(s: Session, engagement_id: int) -> int:
    """Reclassify findings that claim missing headers using engagement evidence.

    Uses http_pair bodies, evidence notes, and cross-finding description text so
    existing ORM findings are corrected when *any* engagement evidence shows the
    claimed header (HSTS max-age, XFO/frame-ancestors, Permissions-Policy).

    Returns the number of findings whose validation_status changed.
    """
    eng = s.get(Engagement, engagement_id)
    if eng is None:
        return 0
    findings = list(s.scalars(select(Finding).where(Finding.engagement_id == engagement_id)))
    if not findings:
        return 0

    pair_texts = _load_http_pair_texts(s, findings, tenant_id=eng.tenant_id)
    desc_texts = _finding_description_texts(findings)
    note_texts = _load_evidence_note_texts(s, findings)
    if not pair_texts and not desc_texts and not note_texts:
        return 0

    by_origin: dict[str, list[str]] = {}
    all_pair_texts: list[str] = []
    for origin, text in pair_texts:
        all_pair_texts.append(text)
        if origin:
            by_origin.setdefault(origin, []).append(text)

    # Shared cross-finding evidence available to every header-missing claim.
    cross_texts = list(desc_texts) + list(note_texts)

    changed = 0
    for f in findings:
        claim = finding_claims_header_missing(f.title or "", f.description or "")
        if not claim:
            continue
        current = getattr(f, "validation_status", None) or UNVALIDATED
        if current in (NOT_REPRODUCIBLE, INFORMATIONAL):
            continue
        loc_origin = _origin(f.location or "")
        texts = list(by_origin.get(loc_origin) or [])
        for url in f.affected_urls or []:
            o = _origin(str(url).split(" [param:", 1)[0])
            if o and o in by_origin:
                texts.extend(by_origin[o])
        if not texts:
            texts = list(all_pair_texts)
        texts.extend(cross_texts)
        if not texts:
            continue
        result = classify_observation(
            title=f.title or "",
            description=f.description or "",
            location=f.location or "",
            severity=f.severity or "",
            cwe=f.cwe,
            rule_ids=list(f.rule_ids or []),
            evidence_texts=texts,
            tools=list(f.tools or []),
        )
        apply_classification_to_finding(f, result)
        if f.validation_status != current:
            changed += 1
            log.info(
                "validation reconcile finding=%s %s -> %s",
                f.id,
                current,
                f.validation_status,
            )
    return changed


# Alias for callers / docs that name the engagement-scoped batch reconcile.
reconcile_engagement_validation = reconcile_validation_from_evidence
