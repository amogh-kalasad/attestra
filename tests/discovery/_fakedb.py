"""Tiny in-memory stand-in for the pymongo calls WP4 modules make (no Mongo needed).

Supports: find_one, find(...).sort().limit(), insert_one, replace_one(upsert), update_one
($set), delete_one, count_documents; filters with equality, $in, $nin, $ne, $gte, $lt.
"""

from __future__ import annotations

import copy
from types import SimpleNamespace


def _match_value(v, cond) -> bool:
    if isinstance(cond, dict) and any(str(k).startswith("$") for k in cond):
        for op, arg in cond.items():
            if op == "$in" and v not in arg:
                return False
            if op == "$nin" and v in arg:
                return False
            if op == "$ne" and v == arg:
                return False
            if op == "$gte" and not (v is not None and v >= arg):
                return False
            if op == "$lt" and not (v is not None and v < arg):
                return False
        return True
    return v == cond


def matches(doc: dict, q: dict | None) -> bool:
    return all(_match_value(doc.get(k), c) for k, c in (q or {}).items())


class Cursor:
    def __init__(self, docs):
        self._docs = list(docs)

    def sort(self, key, direction=1):
        self._docs.sort(key=lambda d: (d.get(key) is None, d.get(key)), reverse=direction < 0)
        return self

    def limit(self, n):
        self._docs = self._docs[: int(n)] if n else self._docs
        return self

    def __iter__(self):
        return iter(copy.deepcopy(self._docs))


class Collection:
    def __init__(self):
        self.docs: dict = {}
        self.ops: list[str] = []

    def find_one(self, q=None, projection=None):
        for d in self.docs.values():
            if matches(d, q):
                return copy.deepcopy(d)
        return None

    def find(self, q=None, projection=None):
        return Cursor([d for d in self.docs.values() if matches(d, q)])

    def count_documents(self, q=None, limit=0):
        n = sum(1 for d in self.docs.values() if matches(d, q))
        return min(n, limit) if limit else n

    def insert_one(self, doc):
        self.ops.append("insert")
        if doc["_id"] in self.docs:
            raise ValueError("duplicate key")
        self.docs[doc["_id"]] = copy.deepcopy(doc)
        return SimpleNamespace(inserted_id=doc["_id"])

    def replace_one(self, q, doc, upsert=False):
        self.ops.append("replace")
        for k, d in self.docs.items():
            if matches(d, q):
                new = copy.deepcopy(doc)
                new.setdefault("_id", k)
                self.docs[k] = new
                return SimpleNamespace(matched_count=1)
        if upsert:
            self.docs[doc["_id"]] = copy.deepcopy(doc)
        return SimpleNamespace(matched_count=0)

    def update_one(self, q, update, upsert=False):
        self.ops.append("update")
        for k, d in self.docs.items():
            if matches(d, q):
                d.update(copy.deepcopy(update.get("$set") or {}))
                return SimpleNamespace(matched_count=1)
        return SimpleNamespace(matched_count=0)

    def delete_one(self, q):
        self.ops.append("delete")
        for k, d in list(self.docs.items()):
            if matches(d, q):
                del self.docs[k]
                return SimpleNamespace(deleted_count=1)
        return SimpleNamespace(deleted_count=0)


class FakeDB:
    def __init__(self):
        self.cols: dict[str, Collection] = {}

    def __getitem__(self, name):
        return self.cols.setdefault(name, Collection())
