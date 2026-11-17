"""Discovery candidate model and tenant-scoped store (A-01, A-07).

A candidate is a hostname seen by a passive source under an apex that is itself in the
engagement's signed scope. It carries provenance (which sources, when, what they saw),
a confidence score, a DNS resolution status and an approval state. Candidates are never
scannable: only an Asset created by an explicit approval can be scanned, and that goes
through the normal gate.
"""
# @lat: [[attack-surface-and-platform#Candidate store and approval]]

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from attestra.discovery.normalize import candidate_key
from attestra.persistence.mongo.tenant import TenantAccessDenied, TenantIds, effective_scope, tenant_filter

COLLECTION = "discovery_candidates"

PENDING, APPROVED, REJECTED = "pending", "approved", "rejected"
STATUSES = (PENDING, APPROVED, REJECTED)

RESOLUTION = ("unknown", "resolved", "nxdomain", "servfail", "timeout", "wildcard", "nodata")

# Independent-evidence weights per passive source (combined as 1 - Π(1 - w)).
SOURCE_WEIGHTS: dict[str, float] = {
    "ct": 0.55,  # a certificate was issued for the name
    "subfinder": 0.45,  # passive aggregators
    "dnsx": 0.35,  # it resolves
    "httpx": 0.25,  # something answers HTTP
    "manual": 0.5,
}
MAX_PROVENANCE = 50


class CandidateError(ValueError):
    pass


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(v: Any) -> str:
    if isinstance(v, datetime):
        return (v if v.tzinfo else v.replace(tzinfo=UTC)).isoformat()
    return str(v or "")


@dataclass(frozen=True)
class Observation:
    """One source saying "I saw this name" (normalized name, never a raw tool line)."""

    name: str
    source: str
    seen_at: str = ""
    detail: dict = field(default_factory=dict)


@dataclass
class Candidate:
    name: str
    apex: str
    sources: tuple[str, ...] = ()
    first_seen: str = ""
    last_seen: str = ""
    confidence: float = 0.0
    resolution: str = "unknown"
    addresses: tuple[str, ...] = ()
    cnames: tuple[str, ...] = ()
    http: dict = field(default_factory=dict)
    takeover: dict = field(default_factory=dict)
    cloud: dict = field(default_factory=dict)
    provenance: list = field(default_factory=list)
    in_scope: bool = False
    status: str = PENDING

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["sources"] = list(self.sources)
        d["addresses"] = list(self.addresses)
        d["cnames"] = list(self.cnames)
        return d


def score_confidence(sources, resolution: str = "unknown") -> float:
    """Deterministic 0..1 confidence from distinct sources and resolution state."""
    miss = 1.0
    for src in sorted(set(sources or ())):
        miss *= 1.0 - SOURCE_WEIGHTS.get(src, 0.2)
    conf = 1.0 - miss
    if resolution == "resolved":
        conf = min(1.0, conf + 0.1)
    elif resolution in ("nxdomain", "nodata"):
        conf *= 0.5
    elif resolution == "wildcard":
        conf = min(conf, 0.3)
    return round(conf, 2)


def is_scannable(doc: dict | None) -> bool:
    """Candidates are never scan targets; only the Asset an approval created is."""
    return False


# ---------------------------------------------------------------- store


def _scope(tenant_ids: TenantIds) -> TenantIds:
    return effective_scope(tenant_ids, where="discovery_candidates")


def upsert_candidates(
    db,
    *,
    tenant_id: int,
    engagement_id: int,
    candidates: list[Candidate],
    actor: str,
    tenant_ids: TenantIds = None,
) -> dict[str, int]:
    """Insert new candidates and merge provenance into existing ones (idempotent).

    Review state is never changed here: an approved or rejected candidate stays so.
    Out-of-scope candidates are refused (the pipeline already drops them).
    """
    allowed = _scope(tenant_ids)
    if allowed is not None and int(tenant_id) not in allowed:
        raise TenantAccessDenied("not found")
    col = db[COLLECTION]
    created = updated = 0
    now = _iso(_now())
    for c in candidates:
        if not c.in_scope:
            continue
        key = candidate_key(tenant_id, engagement_id, c.name)
        existing = col.find_one({"_id": key})
        if existing is None:
            doc = {
                "_id": key,
                "tenant_id": int(tenant_id),
                "engagement_id": int(engagement_id),
                **c.as_dict(),
                "status": PENDING,
                "asset_id": None,
                "created_at": now,
                "created_by": actor,
                "updated_at": now,
                "review": {},
            }
            doc["provenance"] = list(doc["provenance"])[-MAX_PROVENANCE:]
            col.insert_one(doc)
            created += 1
            continue
        if int(existing.get("tenant_id", -1)) != int(tenant_id):
            raise TenantAccessDenied("not found")
        sources = sorted(set(existing.get("sources") or []) | set(c.sources))
        resolution = c.resolution if c.resolution != "unknown" else existing.get("resolution", "unknown")
        prov = list(existing.get("provenance") or [])
        seen = {(p.get("source"), p.get("seen_at")) for p in prov if isinstance(p, dict)}
        for p in c.provenance:
            if (p.get("source"), p.get("seen_at")) not in seen:
                prov.append(p)
        firsts = [x for x in (existing.get("first_seen"), c.first_seen) if x]
        merged = dict(existing)
        merged.update(
            {
                "sources": sources,
                "first_seen": min(firsts) if firsts else "",
                "last_seen": max(existing.get("last_seen") or "", c.last_seen or ""),
                "resolution": resolution,
                "addresses": list(c.addresses) or list(existing.get("addresses") or []),
                "cnames": list(c.cnames) or list(existing.get("cnames") or []),
                "http": c.http or existing.get("http") or {},
                "takeover": c.takeover or existing.get("takeover") or {},
                "cloud": c.cloud or existing.get("cloud") or {},
                "provenance": prov[-MAX_PROVENANCE:],
                "confidence": score_confidence(sources, resolution),
                "updated_at": now,
            }
        )
        col.replace_one({"_id": key}, merged)
        updated += 1
    return {"created": created, "updated": updated}


def list_candidates(db, *, tenant_ids: TenantIds, engagement_id: int, status: str | None = None) -> list[dict]:
    q: dict[str, Any] = {"engagement_id": int(engagement_id)}
    q.update(tenant_filter("tenant_id", tenant_ids))
    if status:
        if status not in STATUSES:
            raise CandidateError(f"status must be one of {STATUSES}")
        q["status"] = status
    rows = list(db[COLLECTION].find(q))
    rows.sort(key=lambda d: (-float(d.get("confidence") or 0), d.get("name") or ""))
    return [public_dict(d) for d in rows]


def get_candidate(db, candidate_id: str, *, tenant_ids: TenantIds, engagement_id: int | None = None) -> dict:
    doc = db[COLLECTION].find_one({"_id": str(candidate_id)})
    if not doc:
        raise LookupError("candidate not found")
    allowed = _scope(tenant_ids)
    if allowed is not None and int(doc.get("tenant_id", -1)) not in allowed:
        raise TenantAccessDenied("not found")
    if engagement_id is not None and int(doc.get("engagement_id", -1)) != int(engagement_id):
        raise LookupError("candidate not found")
    return doc


def set_review(
    db,
    candidate_id: str,
    *,
    tenant_ids: TenantIds,
    engagement_id: int,
    status: str,
    actor: str,
    reason: str = "",
    asset_id: int | None = None,
) -> dict:
    """pending → approved | rejected. Approve requires in_scope and the created asset id."""
    if status not in (APPROVED, REJECTED):
        raise CandidateError("status must be approved or rejected")
    doc = get_candidate(db, candidate_id, tenant_ids=tenant_ids, engagement_id=engagement_id)
    if doc.get("status") != PENDING:
        raise CandidateError(f"candidate already {doc.get('status')}")
    if status == APPROVED:
        if not doc.get("in_scope"):
            raise CandidateError("candidate is outside the signed scope and cannot be approved")
        if asset_id is None:
            raise CandidateError("approval needs the created asset id")
    res = db[COLLECTION].update_one(
        {"_id": doc["_id"], "status": PENDING},
        {
            "$set": {
                "status": status,
                "asset_id": int(asset_id) if asset_id is not None else None,
                "review": {"by": actor, "at": _iso(_now()), "reason": (reason or "")[:500]},
                "updated_at": _iso(_now()),
            }
        },
    )
    if getattr(res, "matched_count", 1) == 0:
        raise CandidateError("candidate was reviewed concurrently")
    return public_dict(db[COLLECTION].find_one({"_id": doc["_id"]}))


def public_dict(doc: dict) -> dict:
    out = {k: v for k, v in doc.items() if k != "_id"}
    out["id"] = str(doc.get("_id"))
    out["scannable"] = is_scannable(doc)
    return out
