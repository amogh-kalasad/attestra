"""Group finding evidence for gallery display (original vs annotated, failures)."""
# @lat: [[authorization#Evidence gallery]]

from __future__ import annotations

from typing import Any

from attestra.dedup import tool_display_name


def _redaction_from_note(note: str) -> str:
    for part in (note or "").splitlines():
        if part.strip().startswith("redaction_status="):
            return part.strip().split("=", 1)[1].strip()
    return ""


def evidence_card(ev: Any) -> dict[str, Any]:
    """Public card payload for one evidence row (no storage path)."""
    redaction = getattr(ev, "redaction_status", "") or _redaction_from_note(getattr(ev, "note", "") or "")
    return {
        "id": ev.id,
        "kind": ev.kind,
        "filename": ev.filename,
        "sha256": ev.sha256,
        "note": ev.note or "",
        "role": getattr(ev, "role", None) or "original",
        "content_type": getattr(ev, "content_type", "") or "",
        "source_tool": getattr(ev, "source_tool", "") or "",
        "source_tool_label": tool_display_name(getattr(ev, "source_tool", "") or "")
        if getattr(ev, "source_tool", "")
        else "",
        "observation_id": getattr(ev, "observation_id", None),
        "import_run_id": getattr(ev, "import_run_id", None),
        "parent_evidence_id": getattr(ev, "parent_evidence_id", None),
        "redaction_status": redaction,
        "capture_status": getattr(ev, "capture_status", None) or "success",
        "capture_failure_reason": getattr(ev, "capture_failure_reason", "") or "",
        "annotation_meta": dict(getattr(ev, "annotation_meta", None) or {}),
        "captured_by": ev.captured_by,
        "captured_at": ev.captured_at,
        # Never expose path in gallery APIs.
    }


def build_gallery(evidence_rows: list[Any]) -> dict[str, Any]:
    """Partition evidence into gallery sections for the finding detail UI."""
    cards = [evidence_card(ev) for ev in evidence_rows]
    originals = [c for c in cards if c["role"] == "original" and c["kind"] != "capture_failure"]
    annotated = [c for c in cards if c["role"] == "annotated"]
    excerpts = [c for c in cards if c["role"] == "excerpt"]
    failures = [c for c in cards if c["kind"] == "capture_failure" or c["capture_status"] in ("failed", "unavailable")]
    screenshots = [c for c in cards if c["kind"] == "screenshot"]
    http_pairs = [c for c in cards if c["kind"] == "http_pair"]
    logs = [c for c in cards if c["kind"] == "log"]
    code = [c for c in cards if c["kind"] == "code"]
    packages = [c for c in cards if c["kind"] == "package"]
    return {
        "items": cards,
        "originals": originals,
        "annotated": annotated,
        "excerpts": excerpts,
        "screenshots": screenshots,
        "http_pairs": http_pairs,
        "logs": logs,
        "code": code,
        "packages": packages,
        "capture_failures": failures,
        "counts": {
            "total": len(cards),
            "screenshots": len(screenshots),
            "annotated": len(annotated),
            "failures": len(failures),
        },
        "visually_verified": any(
            c["kind"] == "screenshot" and c["capture_status"] == "success" and c["role"] in ("original", "annotated")
            for c in cards
        ),
    }
