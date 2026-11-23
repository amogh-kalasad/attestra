"""Unit tests for AASI Phase 3 tenant-scoped Mongo store."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pymongo.errors import DuplicateKeyError

from attestra.persistence.mongo import collections as C

# @lat: [[aasi#Phase 3 Mongo persistence]]


class _Cursor:
    def __init__(self, docs: list[dict[str, Any]]):
        self._docs = docs

    def sort(self, key: str, direction: int = 1):
        reverse = direction < 0
        self._docs = sorted(self._docs, key=lambda d: d.get(key) or datetime.min.replace(tzinfo=UTC), reverse=reverse)
        return self

    def limit(self, n: int):
        self._docs = self._docs[: int(n)]
        return self

    def __iter__(self):
        return iter(deepcopy(self._docs))


class _FakeCollection:
    def __init__(self, name: str, unique_tenant_idempotency: bool = False):
        self.name = name
        self._docs: list[dict[str, Any]] = []
        self._unique_tenant_idempotency = unique_tenant_idempotency

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
        if self._unique_tenant_idempotency:
            key = doc.get("idempotency_key")
            tid = doc.get("tenant_id")
            if key is not None and any(
                d.get("tenant_id") == tid and d.get("idempotency_key") == key for d in self._docs
            ):
                raise DuplicateKeyError("E11000 duplicate key")
        if any(d.get("_id") == doc.get("_id") for d in self._docs):
            raise DuplicateKeyError("E11000 duplicate _id")
        self._docs.append(deepcopy(doc))
        return type("R", (), {"inserted_id": doc.get("_id")})()

    def find_one_and_update(self, flt, update, *, upsert=False, return_document=None, **kwargs):
        # Sequence allocator support.
        doc = self.find_one(flt)
        if doc is None and upsert:
            doc = {"_id": flt.get("_id"), "value": 0}
            self._docs.append(doc)
        if doc is None:
            return None
        inc = (update or {}).get("$inc") or {}
        for k, v in inc.items():
            doc[k] = int(doc.get(k) or 0) + int(v)
        # Keep list in sync (doc may be the live object when upserted).
        for i, d in enumerate(self._docs):
            if d.get("_id") == doc.get("_id"):
                self._docs[i] = doc
                break
        return deepcopy(doc)

    def update_one(self, flt, update, *, upsert=False, **kwargs):
        doc = self.find_one(flt)
        if doc is None and upsert:
            doc = dict(flt)
            self._docs.append(doc)
        if doc is None:
            return type("R", (), {"matched_count": 0})()
        for op, fields in (update or {}).items():
            if op == "$set":
                for k, v in fields.items():
                    doc[k] = v
        for i, d in enumerate(self._docs):
            if d.get("_id") == doc.get("_id"):
                self._docs[i] = {**d, **doc}
                break
        return type("R", (), {"matched_count": 1})()


class _FakeDB:
    def __init__(self):
        self._cols: dict[str, _FakeCollection] = {
            C.AASI_RUNS: _FakeCollection(C.AASI_RUNS, unique_tenant_idempotency=True),
            C.AASI_DECISIONS: _FakeCollection(C.AASI_DECISIONS),
            C.ID_SEQUENCES: _FakeCollection(C.ID_SEQUENCES),
        }

    def __getitem__(self, name: str) -> _FakeCollection:
        if name not in self._cols:
            self._cols[name] = _FakeCollection(name)
        return self._cols[name]


@pytest.fixture
def store(monkeypatch):
    from attestra.aasi.store import AasiStore

    monkeypatch.setattr(
        "attestra.persistence.mongo.adapters.mongo_audit_record",
        lambda *a, **k: {"id": 0, "ts": None, "prev_hash": "", "hash": ""},
        raising=False,
    )
    return AasiStore(_FakeDB())


# @lat: [[tests#AASI Phase 3 store#Create and get are tenant-scoped]]
def test_create_run_and_get_run(store):
    from attestra.aasi.store import SCHEMA_VERSION

    run = store.create_run(1, 10, "key-a", correlation_id="c1")
    assert run["id"] == run["_id"]
    assert run["tenant_id"] == 1
    assert run["engagement_id"] == 10
    assert run["idempotency_key"] == "key-a"
    assert run["status"] == "CREATED"
    assert run["schema_version"] == SCHEMA_VERSION
    assert "created_at" in run and "updated_at" in run

    got = store.get_run(run["id"], 1)
    assert got is not None
    assert got["idempotency_key"] == "key-a"
    assert store.get_run(run["id"], 2) is None


# @lat: [[tests#AASI Phase 3 store#Idempotency returns existing run]]
def test_create_run_idempotent_same_key(store):
    a = store.create_run(1, 10, "same-key", correlation_id="first")
    b = store.create_run(1, 10, "same-key", correlation_id="second")
    assert a["id"] == b["id"]
    assert b["correlation_id"] == "first"
    # Same key under another tenant is a distinct run.
    c = store.create_run(2, 20, "same-key")
    assert c["id"] != a["id"]
    assert c["tenant_id"] == 2


def test_create_run_duplicate_key_race(store, monkeypatch):
    """Simulate concurrent insert: first find misses, insert raises DuplicateKeyError."""
    first = store.create_run(1, 10, "race-key")
    real_find = store.runs.find_one
    calls = {"n": 0}

    def find_one(flt, *a, **k):
        calls["n"] += 1
        # First lookup in create_run pretends miss; after DuplicateKeyError, return existing.
        if calls["n"] == 1 and flt.get("idempotency_key") == "race-key":
            return None
        return real_find(flt, *a, **k)

    monkeypatch.setattr(store.runs, "find_one", find_one)
    out = store.create_run(1, 10, "race-key")
    assert out["id"] == first["id"]


# @lat: [[tests#AASI Phase 3 store#Decisions are append-only]]
def test_append_decision_append_only_and_list(store):
    from attestra.aasi.store import SCHEMA_VERSION

    run = store.create_run(1, 10, "dec-key")
    d1 = store.append_decision(
        run["id"],
        1,
        "hypothesis",
        {"statement": "model may leak PII", "basis": "observed"},
        role="hypothesis",
        cites=["obs:1"],
    )
    d2 = store.append_decision(
        run["id"],
        1,
        "recommendation",
        {"tool": "garak", "probe": "leakreplay"},
        role="ai_security",
    )
    assert d1["id"] != d2["id"]
    assert d1["schema_version"] == SCHEMA_VERSION
    assert d1["audit_hash"]
    assert d1["engagement_id"] == 10
    assert d1["payload"]["statement"] == "model may leak PII"

    listed = store.list_decisions(run["id"], 1)
    assert [x["id"] for x in listed] == [d1["id"], d2["id"]]
    assert store.list_decisions(run["id"], 2) == []
    hyps = store.list_decisions(run["id"], 1, kind="hypothesis")
    assert len(hyps) == 1 and hyps[0]["kind"] == "hypothesis"

    # No update API: prior decision docs remain unchanged after further appends.
    again = store.list_decisions(run["id"], 1, kind="hypothesis")[0]
    assert again["payload"] == d1["payload"]
    assert again["audit_hash"] == d1["audit_hash"]


# @lat: [[tests#AASI Phase 3 store#CoT keys are stripped]]
def test_sanitize_strips_chain_of_thought(store):
    from attestra.aasi.store import sanitize_payload

    clean = sanitize_payload(
        {
            "statement": "ok",
            "chain_of_thought": "secret reasoning",
            "nested": {"cot": "nope", "score": 1},
        }
    )
    assert clean == {"statement": "ok", "nested": {"score": 1}}

    run = store.create_run(1, 10, "cot-key")
    dec = store.append_decision(
        run["id"],
        1,
        "conclusion",
        {"summary": "done", "raw_reasoning": "do not store", "chain-of-thought": "x"},
    )
    assert "raw_reasoning" not in dec["payload"]
    assert "chain-of-thought" not in dec["payload"]
    assert dec["payload"]["summary"] == "done"


def test_retain_until_soft_retention(store):
    until = datetime.now(UTC) + timedelta(days=90)
    run = store.create_run(1, 10, "ret-key", retain_until=until)
    assert run["retain_until"] == until
    dec = store.append_decision(run["id"], 1, "approval", {"approved": True})
    assert dec["retain_until"] == until


def test_tenant_scope_denied(store):
    from attestra.aasi.store import AasiStore
    from attestra.persistence.mongo.tenant import TenantAccessDenied

    scoped = AasiStore(store.db, tenant_ids=frozenset({1}))
    scoped.create_run(1, 10, "scoped-ok")
    with pytest.raises(TenantAccessDenied):
        scoped.create_run(2, 20, "scoped-bad")
    with pytest.raises(TenantAccessDenied):
        scoped.get_run(1, 2)


def test_append_missing_run_raises(store):
    from attestra.persistence.mongo.tenant import TenantAccessDenied

    with pytest.raises(TenantAccessDenied):
        store.append_decision(9999, 1, "hypothesis", {"statement": "x"})


def test_invalid_kind_and_status(store):
    with pytest.raises(ValueError):
        store.create_run(1, 10, "bad-status", status="NOPE")
    run = store.create_run(1, 10, "ok-status")
    with pytest.raises(ValueError):
        store.append_decision(run["id"], 1, "not_a_kind", {})
    with pytest.raises(ValueError):
        store.create_run(1, 10, "  ")
