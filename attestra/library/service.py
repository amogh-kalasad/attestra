"""Reusable findings library (per-tenant writeups): CRUD, search, apply, suggest, seed.

Applying a writeup only fills empty fields on a finding; a tester's own text is
never overwritten. Every change is written to the audit log.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra import audit, services
from attestra.library.fix_snippets import (
    EFFORT_VALUES,
    FIX_FIELD_KEYS,
    IMPORTANCE_VALUES,
    api_fix_fields,
    detect_server_type,
    enrich,
    guidance_from_mapping,
    has_fix_content,
    is_fix_target,
    match_seed_guidance,
    snippets_for_report,
)
from attestra.models import SEVERITIES, Engagement, Finding, LibraryEntry, utcnow

FIELDS = (
    "title", "description", "impact", "remediation", "references", "cwe", "default_severity", "tags", "rule_ids",
    *FIX_FIELD_KEYS,
)
MAX_TEXT = 20000


class LibraryError(services.ServiceError):
    pass


def _clean_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = value.replace("\n", ",").split(",")
    out: list[str] = []
    for v in value:
        v = str(v).strip()
        if v and v not in out:
            out.append(v[:200])
    return out


def _validate(data: dict) -> dict:
    out: dict = {}
    for k in FIELDS:
        if k not in data:
            continue
        v = data[k]
        if k in ("tags", "rule_ids", "references"):
            out[k] = _clean_list(v)
        elif k == "cwe":
            if v in (None, ""):
                out[k] = None
            else:
                try:
                    out[k] = int(str(v).upper().removeprefix("CWE-"))
                except ValueError:
                    raise LibraryError("cwe must be a number like 79 or CWE-79") from None
                if out[k] <= 0:
                    raise LibraryError("cwe must be positive")
        elif k == "default_severity":
            v = (v or "medium").strip().lower()
            if v not in SEVERITIES:
                raise LibraryError(f"default_severity must be one of {SEVERITIES}")
            out[k] = v
        elif k == "importance":
            v = (v or "").strip()
            if v and v not in IMPORTANCE_VALUES:
                raise LibraryError(f"importance must be one of {IMPORTANCE_VALUES}")
            out[k] = v
        elif k == "effort":
            v = (v or "").strip()
            if v and v not in EFFORT_VALUES:
                raise LibraryError(f"effort must be one of {EFFORT_VALUES}")
            out[k] = v
        else:
            v = (v or "").strip()
            if len(v) > MAX_TEXT:
                raise LibraryError(f"{k} is too long")
            out[k] = v
    if "title" in out and not out["title"]:
        raise LibraryError("title is required")
    if "title" in out and len(out["title"]) > 300:
        raise LibraryError("title is too long")
    return out


def entry_dict(e: LibraryEntry) -> dict:
    return {
        "id": e.id, "tenant_id": e.tenant_id, "title": e.title, "description": e.description,
        "impact": e.impact, "remediation": e.remediation, "references": list(e.references or []),
        "cwe": e.cwe, "default_severity": e.default_severity, "tags": list(e.tags or []),
        "rule_ids": list(e.rule_ids or []),
        "importance": e.importance or "", "effort": e.effort or "", "fix_steps": e.fix_steps or "",
        "snippet_nginx": e.snippet_nginx or "", "snippet_apache": e.snippet_apache or "",
        "snippet_iis": e.snippet_iis or "", "snippet_cloudflare": e.snippet_cloudflare or "",
        "updated_by": e.updated_by, "updated_at": e.updated_at,
    }


def list_entries(s: Session, tenant_id: int, q: str = "") -> list[LibraryEntry]:
    rows = list(s.scalars(select(LibraryEntry).where(LibraryEntry.tenant_id == tenant_id).order_by(LibraryEntry.title)))
    q = (q or "").strip().lower()
    if not q:
        return rows
    terms = q.split()

    def hay(e: LibraryEntry) -> str:
        return " ".join([
            e.title, e.description, e.impact, e.remediation, " ".join(e.tags or []),
            " ".join(e.rule_ids or []), f"cwe-{e.cwe}" if e.cwe else "",
        ]).lower()

    hits = [e for e in rows if all(t in hay(e) for t in terms)]
    return sorted(hits, key=lambda e: (not all(t in e.title.lower() for t in terms), e.title))


def get_entry(s: Session, entry_id: int, tenant_ids: set[int] | None = None) -> LibraryEntry:
    e = s.get(LibraryEntry, entry_id)
    if e is None or (tenant_ids is not None and e.tenant_id not in tenant_ids):
        raise LookupError(f"library entry {entry_id} not found")
    return e


def create_entry(s: Session, tenant_id: int, data: dict, *, actor: str) -> LibraryEntry:
    clean = _validate({"default_severity": "medium", **data})
    if "title" not in clean:
        raise LibraryError("title is required")
    dup = s.scalars(select(LibraryEntry).where(LibraryEntry.tenant_id == tenant_id, LibraryEntry.title == clean["title"])).first()
    if dup:
        raise LibraryError(f"a writeup titled '{clean['title']}' already exists")
    e = LibraryEntry(tenant_id=tenant_id, updated_by=actor, updated_at=utcnow(), **clean)
    s.add(e)
    s.flush()
    audit.record(s, actor, "library.create", "library_entry", e.id, title=e.title)
    return e


def update_entry(s: Session, entry: LibraryEntry, data: dict, *, actor: str) -> LibraryEntry:
    clean = _validate(data)
    if "title" in clean and clean["title"] != entry.title:
        dup = s.scalars(select(LibraryEntry).where(
            LibraryEntry.tenant_id == entry.tenant_id, LibraryEntry.title == clean["title"])).first()
        if dup:
            raise LibraryError(f"a writeup titled '{clean['title']}' already exists")
    for k, v in clean.items():
        setattr(entry, k, v)
    entry.updated_by, entry.updated_at = actor, utcnow()
    audit.record(s, actor, "library.update", "library_entry", entry.id, fields=sorted(clean))
    return entry


def delete_entry(s: Session, entry: LibraryEntry, *, actor: str) -> None:
    audit.record(s, actor, "library.delete", "library_entry", entry.id, title=entry.title)
    s.delete(entry)


def _backfill_fix_fields(entry: LibraryEntry, data: dict) -> bool:
    """Fill empty fix-snippet columns from seed data; never overwrite custom text."""
    changed = False
    for key in FIX_FIELD_KEYS:
        new = (data.get(key) or "").strip()
        if not new:
            continue
        if (getattr(entry, key, "") or "").strip():
            continue
        setattr(entry, key, new)
        changed = True
    return changed


def seed_defaults(s: Session, tenant_id: int, *, actor: str) -> int:
    """Add the built-in writeups the tenant does not have yet (matched by title).

    Also backfills empty importance / effort / fix-steps / snippet fields on existing
    rows that match a seed title, without overwriting custom text.
    """
    from attestra.library.seed import SEED

    existing = {
        e.title: e
        for e in s.scalars(select(LibraryEntry).where(LibraryEntry.tenant_id == tenant_id))
    }
    added = 0
    backfilled = 0
    for item in SEED:
        data = _validate(enrich(item))
        title = data["title"]
        if title in existing:
            if _backfill_fix_fields(existing[title], data):
                existing[title].updated_by = actor
                existing[title].updated_at = utcnow()
                backfilled += 1
            continue
        s.add(LibraryEntry(tenant_id=tenant_id, updated_by=actor, updated_at=utcnow(), **data))
        added += 1
    s.flush()
    if added or backfilled:
        audit.record(s, actor, "library.seed", "tenant", tenant_id, added=added, backfilled=backfilled)
    return added


def import_template_entries(
    s: Session, tenant_id: int, data: bytes, *, fmt: str | None = None, actor: str
) -> dict:
    """Create library entries from an onboarding JSON/CSV template.

    Existing titles for the tenant are skipped. Audited as ``library.import``.
    """
    from attestra.library.import_convert import convert_library_template

    rows = convert_library_template(data, fmt)
    existing = {
        e.title
        for e in s.scalars(select(LibraryEntry).where(LibraryEntry.tenant_id == tenant_id))
    }
    created: list[LibraryEntry] = []
    skipped = 0
    for data_row in rows:
        if data_row["title"] in existing:
            skipped += 1
            continue
        e = LibraryEntry(tenant_id=tenant_id, updated_by=actor, updated_at=utcnow(), **data_row)
        s.add(e)
        created.append(e)
        existing.add(data_row["title"])
    s.flush()
    audit.record(
        s, actor, "library.import", "tenant", tenant_id,
        added=len(created), skipped=skipped, total=len(rows),
    )
    return {
        "added": len(created),
        "skipped": skipped,
        "total": len(rows),
        "entries": [entry_dict(e) for e in created],
    }


# ---------------------------------------------------------------- findings


def _tenant_of(s: Session, f: Finding) -> int:
    return s.get(Engagement, f.engagement_id).tenant_id


def suggest(s: Session, f: Finding, limit: int = 3) -> list[LibraryEntry]:
    """Writeups matching a finding's tool rule ids first, then its CWE."""
    rows = list(s.scalars(select(LibraryEntry).where(LibraryEntry.tenant_id == _tenant_of(s, f))))
    rules = {str(r).lower() for r in (f.rule_ids or [])}
    tools = {str(t).lower() for t in (f.tools or [])}
    keys = rules | {f"{t}:{r}" for t in tools for r in rules}
    scored = []
    for e in rows:
        score = 0
        if keys and keys & {r.lower() for r in (e.rule_ids or [])}:
            score += 2
        if f.cwe and e.cwe == f.cwe:
            score += 1
        if score:
            scored.append((-score, e.title, e))
    return [e for *_, e in sorted(scored, key=lambda t: (t[0], t[1]))[:limit]]


def guidance_for_finding(s: Session, f: Finding) -> dict | None:
    """Library (or built-in seed) fix guidance for a finding, if any."""
    for entry in suggest(s, f, limit=3):
        g = guidance_from_mapping(entry)
        if has_fix_content(g) and is_fix_target(entry.tags, entry.title):
            return g
        if has_fix_content(g):
            return g
    return match_seed_guidance(f)


def server_type_for_findings(findings: list[Finding]) -> str | None:
    """Infer nginx/apache/iis/cloudflare from finding text when unambiguous."""
    parts = []
    for f in findings:
        parts.append(f.title or "")
        parts.append(f.description or "")
        parts.append(f.location or "")
    return detect_server_type(*parts)


def fix_context_for_engagement(s: Session, findings: list[Finding]) -> dict:
    """Maps finding id → guidance and report snippet pairs; plus detected server type."""
    server_type = server_type_for_findings(findings)
    by_id: dict[int, dict] = {}
    report_snips: dict[int, list[tuple[str, str]]] = {}
    for f in findings:
        g = guidance_for_finding(s, f)
        if not g:
            continue
        by_id[f.id] = g
        report_snips[f.id] = snippets_for_report(g, server_type)
    return {"server_type": server_type, "fix_by_id": by_id, "report_snippets_by_id": report_snips}


def finding_api_fix_fields(s: Session, f: Finding) -> dict[str, str]:
    """Flat fix fields for API finding output (empty strings when unknown)."""
    return api_fix_fields(guidance_for_finding(s, f))


def suggestions_for_engagement(s: Session, engagement_id: int) -> dict[int, list[LibraryEntry]]:
    out = {}
    for f in services.list_findings(s, engagement_id):
        hits = suggest(s, f)
        if hits:
            out[f.id] = hits
    return out


def _compose_description(e: LibraryEntry) -> str:
    parts = [e.description.strip()]
    if e.impact.strip():
        parts.append("Impact: " + e.impact.strip())
    return "\n\n".join(p for p in parts if p)


def _compose_recommendation(e: LibraryEntry) -> str:
    parts = [e.remediation.strip()]
    if e.references:
        parts.append("References:\n" + "\n".join(f"- {r}" for r in e.references))
    return "\n\n".join(p for p in parts if p)


def apply_to_finding(s: Session, f: Finding, entry: LibraryEntry, *, actor: str) -> list[str]:
    """Fill only the empty fields of ``f`` from ``entry``. Returns the fields that changed."""
    if entry.tenant_id != _tenant_of(s, f):
        raise LibraryError("writeup belongs to another tenant")
    changed: list[str] = []
    if not (f.impact or "").strip() and (entry.impact or "").strip():
        f.impact = entry.impact.strip()
        changed.append("impact")
    if not (f.references or []) and entry.references:
        f.references = list(entry.references)
        changed.append("references")
    # Keep compose fallback for older consumers that only read description/recommendation.
    if not (f.description or "").strip():
        text = _compose_description(entry)
        if text:
            f.description = text
            changed.append("description")
    if not (f.recommendation or "").strip():
        text = _compose_recommendation(entry)
        if text:
            f.recommendation = text
            changed.append("recommendation")
    if f.cwe is None and entry.cwe:
        f.cwe = entry.cwe
        changed.append("cwe")
    if not (f.severity or "").strip():
        f.severity = entry.default_severity
        changed.append("severity")
    audit.record(s, actor, "library.apply", "finding", f.id, entry_id=entry.id, fields=changed)
    return changed
