"""Read models: Mongo documents presented as read-only ORM look-alikes.

During the cutover, read-only service functions (lists, detail views, exports) can
return ``DocView`` objects built from the mirrored Mongo collections instead of
SQLAlchemy rows. ``DocView`` mimics the mapped class:

* column attributes come back with the SQL Python types (naive-UTC datetimes,
  ``date`` for Date columns, JSON text for Text columns that Mongo stores decoded);
* relationship attributes declared on the model (``finding.asset``,
  ``engagement.findings``, ``run.engagement`` ...) are resolved lazily from Mongo,
  so Jinja templates that walk relationships keep working;
* assignment raises - writes must go through the SQL service functions (which the
  dual-write mirror then replays into Mongo).

Switch: ``mongo_reads(area)`` is always true (MongoDB-only runtime); the
``ATTESTRA_MONGO_READS`` flag is no longer consulted.
"""
from __future__ import annotations

import json
from datetime import date, datetime, timezone
from typing import Any

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import RelationshipDirection


def mongo_reads(area: str = "domain") -> bool:
    return True


def _db():
    from attestra.persistence.mongo.adapters import _db as get

    return get()


def _coerce(col_type: Any, value: Any) -> Any:
    if value is None:
        return None
    from sqlalchemy.types import JSON

    if isinstance(col_type, JSON):  # JSON columns: decoded value (bulk imports may hold JSON text)
        if isinstance(value, str):
            try:
                return json.loads(value)
            except ValueError:
                return value
        return value
    try:
        py = col_type.python_type
    except (NotImplementedError, AttributeError):
        py = None
    if py is datetime and isinstance(value, datetime):
        return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value
    if py is date and isinstance(value, datetime):
        return value.date()
    if py in (date, datetime) and isinstance(value, str):  # ISO text (bulk imports / older writers)
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
        if parsed.tzinfo:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed.date() if py is date else parsed
    if py is str and isinstance(value, (dict, list)):
        return json.dumps(value)
    return value


class DocView:
    """Read-only, ORM-shaped view of one Mongo document for ``model``."""

    __slots__ = ("_model", "_doc", "_cache")

    def __init__(self, model: type, doc: dict[str, Any]):
        object.__setattr__(self, "_model", model)
        object.__setattr__(self, "_doc", doc)
        object.__setattr__(self, "_cache", {})

    def __repr__(self) -> str:
        return f"<DocView {self._model.__name__} id={self._doc.get('_id')}>"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, DocView) and other._model is self._model and other.id == self.id

    def __hash__(self) -> int:
        return hash((self._model.__name__, self._doc.get("_id")))

    def __setattr__(self, name: str, value: Any) -> None:
        mapper = sa_inspect(self._model)
        if name == "id" or name in mapper.column_attrs or name in mapper.relationships:
            raise AttributeError(f"{self._model.__name__} read model is read-only (set {name!r} via services)")
        self._cache[name] = value  # transient annotation (e.g. crossmerge.cross_sources)

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__"):
            raise AttributeError(name)
        cache = self._cache
        if name in cache:
            return cache[name]
        mapper = sa_inspect(self._model)
        if name == "id":
            val = self._doc.get("_id")
        elif name in mapper.relationships:
            val = _resolve_relationship(self, mapper.relationships[name])
        elif name in mapper.column_attrs:
            col = mapper.column_attrs[name].columns[0]
            val = _coerce(col.type, self._doc.get(col.name))
        else:
            attr = getattr(self._model, name, None)
            if isinstance(attr, property):  # computed helpers on the model
                val = attr.fget(self)
            elif callable(attr):
                return attr.__get__(self, type(self))
            else:
                raise AttributeError(f"{self._model.__name__} has no attribute {name!r}")
        cache[name] = val
        return val

    def to_dict(self) -> dict[str, Any]:
        mapper = sa_inspect(self._model)
        return {p.key: getattr(self, p.key) for p in mapper.column_attrs}


def _resolve_relationship(view: DocView, rel) -> Any:
    target = rel.mapper.class_
    table = target.__table__.name
    pairs = list(rel.local_remote_pairs)
    if rel.secondary is not None or not pairs:
        return [] if rel.uselist else None
    local, remote = pairs[0]
    db = _db()
    if rel.direction is RelationshipDirection.MANYTOONE:
        fk = view._doc.get(local.name)
        if fk is None:
            return None
        key = "_id" if remote.name == "id" else remote.name
        doc = db[table].find_one({key: fk})
        return DocView(target, doc) if doc else None
    lv = view._doc.get("_id") if local.name == "id" else view._doc.get(local.name)
    docs = [DocView(target, d) for d in db[table].find({remote.name: lv}).sort("_id", 1)]
    if rel.uselist:
        return docs
    return docs[0] if docs else None


def view_all(model: type, query: dict, *, sort: list | None = None, limit: int = 0) -> list[DocView]:
    cur = _db()[model.__table__.name].find(query)
    if sort:
        cur = cur.sort(sort)
    if limit:
        cur = cur.limit(int(limit))
    return [DocView(model, d) for d in cur]


def view_one(model: type, doc_id: int) -> DocView | None:
    doc = _db()[model.__table__.name].find_one({"_id": int(doc_id)})
    return DocView(model, doc) if doc else None
