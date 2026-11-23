"""Tenant-scoped Mongo helpers for AASI attack-path graph nodes and edges.

Collections ``aasi_graph_nodes`` / ``aasi_graph_edges`` (migration 0006).
Edge provenance is ``observed`` | ``inferred`` | ``demonstrated``. Risk scoring
helpers never raise risk solely from inferred edge count; demonstrated edges
require proof/evidence references.
"""
# @lat: [[aasi#Phase 6 attack-path graph]]

from __future__ import annotations

from typing import Any

from attestra.persistence.mongo import collections as C
from attestra.persistence.mongo.serialization import utcnow, with_id
from attestra.persistence.mongo.sequences import next_id
from attestra.persistence.mongo.tenant import TenantAccessDenied, require_tenant_access

SCHEMA_VERSION = 1

PROVENANCE_LABELS = frozenset({"observed", "inferred", "demonstrated"})

# Node kinds are soft-typed; callers may extend with domain labels.
NODE_KINDS = frozenset(
    {
        "asset",
        "finding",
        "observation",
        "capability",
        "actor",
        "data",
        "control",
        "other",
    }
)


class GraphValidationError(ValueError):
    """Invalid graph node or edge payload."""


def _db():
    from attestra.persistence.mongo.adapters import _db as get

    return get()


def normalize_provenance(label: str) -> str:
    """Return a canonical provenance label or raise."""
    value = (label or "").strip().lower()
    if value not in PROVENANCE_LABELS:
        raise GraphValidationError(
            f"invalid provenance {label!r}; expected one of {sorted(PROVENANCE_LABELS)}"
        )
    return value


def risk_delta_for_edge(provenance: str, *, base_delta: float = 0.0) -> float:
    """Risk contribution for one edge.

    Inferred edges never contribute risk by count alone (always 0). Observed and
    demonstrated may apply ``base_delta`` supplied by the caller; this helper does
    not invent severity from edge cardinality.
    """
    label = normalize_provenance(provenance)
    if label == "inferred":
        return 0.0
    return float(base_delta)


def aggregate_path_risk(
    edges: list[dict[str, Any]],
    *,
    observed_delta: float = 0.0,
    demonstrated_delta: float = 0.0,
) -> dict[str, Any]:
    """Summarize path risk without inflating from inferred edge count.

    Returns counts by provenance and a ``risk_delta`` that ignores inferred edges.
    """
    counts = {p: 0 for p in PROVENANCE_LABELS}
    risk = 0.0
    for edge in edges:
        label = normalize_provenance(str(edge.get("provenance") or ""))
        counts[label] = counts.get(label, 0) + 1
        if label == "observed":
            risk += risk_delta_for_edge(label, base_delta=observed_delta)
        elif label == "demonstrated":
            risk += risk_delta_for_edge(label, base_delta=demonstrated_delta)
        else:
            risk += risk_delta_for_edge(label, base_delta=0.0)
    return {
        "edge_count": sum(counts.values()),
        "counts": counts,
        "inferred_count": counts["inferred"],
        "risk_delta": risk,
        "inferred_excluded_from_risk": True,
    }


class AasiGraphStore:
    """Mongo-backed attack-path graph (tenant-scoped)."""

    def __init__(self, db=None, *, tenant_ids: frozenset[int] | None = None):
        self.db = db if db is not None else _db()
        self.tenant_ids = tenant_ids
        self.nodes = self.db[C.AASI_GRAPH_NODES]
        self.edges = self.db[C.AASI_GRAPH_EDGES]

    def _require_tenant(self, tenant_id: int) -> int:
        tid = int(tenant_id)
        require_tenant_access(tid, self.tenant_ids)
        return tid

    def upsert_node(
        self,
        tenant_id: int,
        engagement_id: int,
        key: str,
        *,
        kind: str = "other",
        label: str = "",
        attrs: dict[str, Any] | None = None,
        source: str = "",
    ) -> dict[str, Any]:
        """Create or update a graph node unique on ``(tenant_id, engagement_id, key)``."""
        tid = self._require_tenant(tenant_id)
        node_key = (key or "").strip()
        if not node_key:
            raise GraphValidationError("node key is required")
        kind_norm = (kind or "other").strip().lower() or "other"
        if kind_norm not in NODE_KINDS:
            kind_norm = "other"

        existing = self.nodes.find_one(
            {"tenant_id": tid, "engagement_id": int(engagement_id), "key": node_key}
        )
        now = utcnow()
        if existing:
            update = {
                "kind": kind_norm,
                "label": label or existing.get("label") or node_key,
                "attrs": dict(attrs if attrs is not None else existing.get("attrs") or {}),
                "source": source or existing.get("source") or "",
                "updated_at": now,
            }
            self.nodes.update_one({"_id": existing["_id"], "tenant_id": tid}, {"$set": update})
            doc = {**existing, **update}
            return with_id(doc)

        node_id = next_id(self.db, C.AASI_GRAPH_NODES)
        doc: dict[str, Any] = {
            "_id": node_id,
            "tenant_id": tid,
            "engagement_id": int(engagement_id),
            "key": node_key,
            "kind": kind_norm,
            "label": label or node_key,
            "attrs": dict(attrs or {}),
            "source": source or "",
            "schema_version": SCHEMA_VERSION,
            "created_at": now,
            "updated_at": now,
        }
        self.nodes.insert_one(doc)
        try:
            from attestra.persistence.mongo.adapters import mongo_audit_record

            mongo_audit_record(
                "aasi",
                "aasi.graph.node.upsert",
                "aasi_graph_node",
                node_id,
                tenant_id=tid,
                engagement_id=int(engagement_id),
                key=node_key,
            )
        except Exception:  # noqa: BLE001
            pass
        return with_id(doc)

    def get_node(self, node_id: int, tenant_id: int) -> dict[str, Any] | None:
        tid = self._require_tenant(tenant_id)
        doc = self.nodes.find_one({"_id": int(node_id), "tenant_id": tid})
        return with_id(doc) if doc else None

    def list_nodes(
        self,
        tenant_id: int,
        engagement_id: int,
        *,
        kind: str | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        tid = self._require_tenant(tenant_id)
        q: dict[str, Any] = {"tenant_id": tid, "engagement_id": int(engagement_id)}
        if kind is not None:
            q["kind"] = (kind or "").strip().lower()
        cursor = self.nodes.find(q).sort("created_at", 1)
        if limit is not None:
            cursor = cursor.limit(int(limit))
        return [with_id(d) for d in cursor]

    def add_edge(
        self,
        tenant_id: int,
        engagement_id: int,
        from_node_id: int,
        to_node_id: int,
        *,
        provenance: str,
        source: str,
        evidence_citations: list[str] | None = None,
        proof_refs: list[str] | None = None,
        relation: str = "leads_to",
        attrs: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Insert an edge with required provenance, source, timestamps, and citations.

        - ``inferred`` must be labelled ``inferred`` (enforced via normalize).
        - ``demonstrated`` requires non-empty ``proof_refs`` (and typically citations).
        - Every edge stores ``evidence_citations``, ``source``, ``created_at`` / ``updated_at``.
        """
        tid = self._require_tenant(tenant_id)
        label = normalize_provenance(provenance)
        src = (source or "").strip()
        if not src:
            raise GraphValidationError("edge source is required")

        cites = [str(c).strip() for c in (evidence_citations or []) if str(c).strip()]
        proofs = [str(p).strip() for p in (proof_refs or []) if str(p).strip()]

        if label == "demonstrated" and not proofs:
            raise GraphValidationError(
                "demonstrated edges require proof_refs (replay / evidence proof ids)"
            )
        # Inferred is accepted only as the literal label ``inferred`` (via normalize_provenance).

        # Endpoints must exist in-tenant / engagement.
        for nid, role in ((from_node_id, "from"), (to_node_id, "to")):
            node = self.nodes.find_one(
                {
                    "_id": int(nid),
                    "tenant_id": tid,
                    "engagement_id": int(engagement_id),
                }
            )
            if not node:
                raise TenantAccessDenied(f"{role} node not found")

        now = utcnow()
        edge_id = next_id(self.db, C.AASI_GRAPH_EDGES)
        doc: dict[str, Any] = {
            "_id": edge_id,
            "tenant_id": tid,
            "engagement_id": int(engagement_id),
            "from_node_id": int(from_node_id),
            "to_node_id": int(to_node_id),
            "relation": (relation or "leads_to").strip() or "leads_to",
            "provenance": label,
            "source": src,
            "evidence_citations": cites,
            "proof_refs": proofs,
            "attrs": dict(attrs or {}),
            "schema_version": SCHEMA_VERSION,
            "created_at": now,
            "updated_at": now,
        }
        self.edges.insert_one(doc)
        try:
            from attestra.persistence.mongo.adapters import mongo_audit_record

            mongo_audit_record(
                "aasi",
                "aasi.graph.edge.add",
                "aasi_graph_edge",
                edge_id,
                tenant_id=tid,
                engagement_id=int(engagement_id),
                provenance=label,
                source=src,
            )
        except Exception:  # noqa: BLE001
            pass
        return with_id(doc)

    def get_edge(self, edge_id: int, tenant_id: int) -> dict[str, Any] | None:
        tid = self._require_tenant(tenant_id)
        doc = self.edges.find_one({"_id": int(edge_id), "tenant_id": tid})
        return with_id(doc) if doc else None

    def list_edges(
        self,
        tenant_id: int,
        engagement_id: int,
        *,
        provenance: str | None = None,
        from_node_id: int | None = None,
        to_node_id: int | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        tid = self._require_tenant(tenant_id)
        q: dict[str, Any] = {"tenant_id": tid, "engagement_id": int(engagement_id)}
        if provenance is not None:
            q["provenance"] = normalize_provenance(provenance)
        if from_node_id is not None:
            q["from_node_id"] = int(from_node_id)
        if to_node_id is not None:
            q["to_node_id"] = int(to_node_id)
        cursor = self.edges.find(q).sort("created_at", 1)
        if limit is not None:
            cursor = cursor.limit(int(limit))
        return [with_id(d) for d in cursor]

    def path_risk_summary(
        self,
        tenant_id: int,
        engagement_id: int,
        *,
        observed_delta: float = 0.0,
        demonstrated_delta: float = 0.0,
    ) -> dict[str, Any]:
        """Aggregate risk for all edges in an engagement without inferred inflation."""
        edges = self.list_edges(tenant_id, engagement_id)
        summary = aggregate_path_risk(
            edges,
            observed_delta=observed_delta,
            demonstrated_delta=demonstrated_delta,
        )
        summary["tenant_id"] = int(tenant_id)
        summary["engagement_id"] = int(engagement_id)
        return summary


__all__ = [
    "SCHEMA_VERSION",
    "PROVENANCE_LABELS",
    "NODE_KINDS",
    "GraphValidationError",
    "AasiGraphStore",
    "normalize_provenance",
    "risk_delta_for_edge",
    "aggregate_path_risk",
]
