"""Unit tests for AASI Phase 6 attack-path graph Mongo helpers."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

import pytest
from pymongo.errors import DuplicateKeyError

from attestra.persistence.mongo import collections as C

# @lat: [[aasi#Phase 6 attack-path graph]]


class _Cursor:
    def __init__(self, docs: list[dict[str, Any]]):
        self._docs = docs

    def sort(self, key: str, direction: int = 1):
        reverse = direction < 0
        self._docs = sorted(
            self._docs,
            key=lambda d: d.get(key) or datetime.min.replace(tzinfo=UTC),
            reverse=reverse,
        )
        return self

    def limit(self, n: int):
        self._docs = self._docs[: int(n)]
        return self

    def __iter__(self):
        return iter(deepcopy(self._docs))


class _FakeCollection:
    def __init__(self, name: str):
        self.name = name
        self._docs: list[dict[str, Any]] = []

    def _match(self, doc: dict[str, Any], flt: dict[str, Any]) -> bool:
        for k, v in flt.items():
            if doc.get(k) != v:
                return False
        return True

    def find_one(self, flt: dict[str, Any], *args, **kwargs):
        for d in self._docs:
            if self._match(d, flt):
                return deepcopy(d)
        return None

    def find(self, flt: dict[str, Any] | None = None, *args, **kwargs):
        flt = flt or {}
        return _Cursor([deepcopy(d) for d in self._docs if self._match(d, flt)])

    def insert_one(self, doc: dict[str, Any], *args, **kwargs):
        if any(d.get("_id") == doc.get("_id") for d in self._docs):
            raise DuplicateKeyError("E11000 duplicate _id")
        self._docs.append(deepcopy(doc))
        return type("R", (), {"inserted_id": doc.get("_id")})()

    def update_one(self, flt, update, *, upsert=False, **kwargs):
        doc = self.find_one(flt)
        if doc is None:
            return type("R", (), {"matched_count": 0})()
        for op, fields in (update or {}).items():
            if op == "$set":
                for k, v in fields.items():
                    doc[k] = v
        for i, d in enumerate(self._docs):
            if d.get("_id") == doc.get("_id"):
                self._docs[i] = doc
                break
        return type("R", (), {"matched_count": 1})()

    def find_one_and_update(self, flt, update, *, upsert=False, return_document=None, **kwargs):
        doc = self.find_one(flt)
        if doc is None and upsert:
            doc = {"_id": flt.get("_id"), "value": 0}
            self._docs.append(doc)
        if doc is None:
            return None
        inc = (update or {}).get("$inc") or {}
        for k, v in inc.items():
            doc[k] = int(doc.get(k) or 0) + int(v)
        for i, d in enumerate(self._docs):
            if d.get("_id") == doc.get("_id"):
                self._docs[i] = doc
                break
        return deepcopy(doc)


class _FakeDB:
    def __init__(self):
        self._cols: dict[str, _FakeCollection] = {
            C.AASI_GRAPH_NODES: _FakeCollection(C.AASI_GRAPH_NODES),
            C.AASI_GRAPH_EDGES: _FakeCollection(C.AASI_GRAPH_EDGES),
            C.ID_SEQUENCES: _FakeCollection(C.ID_SEQUENCES),
        }

    def __getitem__(self, name: str) -> _FakeCollection:
        if name not in self._cols:
            self._cols[name] = _FakeCollection(name)
        return self._cols[name]


@pytest.fixture
def graph(monkeypatch):
    from attestra.aasi.graph import AasiGraphStore

    monkeypatch.setattr(
        "attestra.persistence.mongo.adapters.mongo_audit_record",
        lambda *a, **k: {"id": 0},
        raising=False,
    )
    return AasiGraphStore(_FakeDB())


# @lat: [[tests#AASI Phase 6 attack-path graph#Migration 0006 registered]]
def test_migration_0006_registered():
    from attestra.persistence.mongo import collections as cols
    from attestra.persistence.mongo.migrations import MIGRATIONS

    ids = [rev for rev, _desc, _fn in MIGRATIONS]
    assert "0006_aasi_graph" in ids
    assert ids.index("0006_aasi_graph") > ids.index("0005_aasi_collections")
    assert cols.AASI_GRAPH_NODES == "aasi_graph_nodes"
    assert cols.AASI_GRAPH_EDGES == "aasi_graph_edges"
    assert cols.AASI_GRAPH_NODES in cols.DOMAIN_COLLECTIONS
    assert cols.AASI_GRAPH_EDGES in cols.DOMAIN_COLLECTIONS


# @lat: [[tests#AASI Phase 6 attack-path graph#Nodes and edges are tenant-scoped]]
def test_nodes_and_edges_tenant_scoped(graph):
    a = graph.upsert_node(1, 10, "asset:web", kind="asset", label="Web", source="catalogue")
    b = graph.upsert_node(1, 10, "finding:1", kind="finding", source="import")
    edge = graph.add_edge(
        1,
        10,
        a["id"],
        b["id"],
        provenance="observed",
        source="scanner:garak",
        evidence_citations=["ev-1"],
    )
    assert edge["provenance"] == "observed"
    assert edge["evidence_citations"] == ["ev-1"]
    assert edge["source"] == "scanner:garak"
    assert "created_at" in edge and "updated_at" in edge

    assert graph.get_node(a["id"], 1) is not None
    assert graph.get_node(a["id"], 2) is None
    assert graph.get_edge(edge["id"], 2) is None
    assert len(graph.list_edges(1, 10)) == 1
    assert graph.list_edges(2, 10) == []


# @lat: [[tests#AASI Phase 6 attack-path graph#Inferred labelled; demonstrated needs proof]]
def test_inferred_and_demonstrated_rules(graph):
    from attestra.aasi.graph import GraphValidationError

    a = graph.upsert_node(1, 10, "n1", kind="asset")
    b = graph.upsert_node(1, 10, "n2", kind="capability")

    inferred = graph.add_edge(
        1,
        10,
        a["id"],
        b["id"],
        provenance="inferred",
        source="aasi:hypothesis",
        evidence_citations=["obs-9"],
    )
    assert inferred["provenance"] == "inferred"

    with pytest.raises(GraphValidationError, match="proof_refs"):
        graph.add_edge(
            1,
            10,
            a["id"],
            b["id"],
            provenance="demonstrated",
            source="retest:replay",
            evidence_citations=["ev-2"],
        )

    demo = graph.add_edge(
        1,
        10,
        a["id"],
        b["id"],
        provenance="demonstrated",
        source="retest:replay",
        evidence_citations=["ev-2"],
        proof_refs=["proof-replay-1"],
    )
    assert demo["provenance"] == "demonstrated"
    assert demo["proof_refs"] == ["proof-replay-1"]

    with pytest.raises(GraphValidationError, match="provenance"):
        graph.add_edge(
            1,
            10,
            a["id"],
            b["id"],
            provenance="guessed",
            source="x",
        )


# @lat: [[tests#AASI Phase 6 attack-path graph#Risk ignores inferred edge count]]
def test_risk_ignores_inferred_count(graph):
    from attestra.aasi.graph import aggregate_path_risk, risk_delta_for_edge

    assert risk_delta_for_edge("inferred", base_delta=5.0) == 0.0
    assert risk_delta_for_edge("observed", base_delta=2.0) == 2.0

    a = graph.upsert_node(1, 10, "a")
    b = graph.upsert_node(1, 10, "b")
    c = graph.upsert_node(1, 10, "c")
    graph.add_edge(1, 10, a["id"], b["id"], provenance="inferred", source="corr", evidence_citations=["e1"])
    graph.add_edge(1, 10, b["id"], c["id"], provenance="inferred", source="corr", evidence_citations=["e2"])
    graph.add_edge(
        1,
        10,
        a["id"],
        c["id"],
        provenance="observed",
        source="scan",
        evidence_citations=["e3"],
    )

    summary = graph.path_risk_summary(1, 10, observed_delta=1.5, demonstrated_delta=3.0)
    assert summary["inferred_count"] == 2
    assert summary["edge_count"] == 3
    assert summary["risk_delta"] == 1.5
    assert summary["inferred_excluded_from_risk"] is True

    bare = aggregate_path_risk(
        [{"provenance": "inferred"}, {"provenance": "inferred"}, {"provenance": "inferred"}],
        observed_delta=10.0,
    )
    assert bare["risk_delta"] == 0.0
    assert bare["inferred_count"] == 3
