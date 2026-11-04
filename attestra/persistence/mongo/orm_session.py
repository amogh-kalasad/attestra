"""MongoSession: a SQLAlchemy-Session look-alike that persists straight to MongoDB.

Mongo-only mode: ``db.session()`` yields this instead of a SQL session, so the
existing service code (``s.add`` / ``s.get`` / ``s.scalars(select(...))`` /
``s.flush`` / ``s.delete``) runs unchanged with no SQL database at all.

* New mapped instances (``Finding(...)``) get integer ids from ``id_sequences`` on
  flush, column defaults applied, and are inserted via ``row_to_document``.
* Loaded rows are ``MongoRecord`` objects (writable ``DocView``): column / FK
  assignments are tracked and written back on flush; relationships resolve lazily
  through the session (identity-mapped, so mutations stick).
* ``select()`` statements are compiled to Mongo filters (eq/ne/lt/gt/in/is/like,
  and/or/not, simple FK joins, order_by, limit/offset, count, group_by+count).
* Autoflush before every query; rollback deletes rows inserted and restores rows
  updated in this session (best effort - no multi-document transaction).
"""
from __future__ import annotations

import copy
import re
from datetime import date, datetime, time
from typing import Any

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import RelationshipDirection
from sqlalchemy.orm.attributes import set_committed_value
from sqlalchemy.sql import elements, operators, selectable
from sqlalchemy.sql.functions import FunctionElement

from attestra.persistence.mongo.read_models import DocView, _coerce


class UnsupportedQuery(NotImplementedError):
    pass


class AppendOnlyViolation(PermissionError):
    pass


APPEND_ONLY = frozenset({"audit_events"})


def _append_only(table: str, what: str) -> None:
    if table in APPEND_ONLY:
        raise AppendOnlyViolation(f"{table} is append-only ({what} refused)")


def _db():
    from attestra.persistence.mongo.adapters import _db as get

    return get()


def _table(model) -> str:
    return model.__table__.name


def _to_doc(table: str, row: dict) -> dict:
    from attestra.migration.transform import row_to_document

    return row_to_document(table, row)


# --------------------------------------------------------------------------- records


class MongoRecord(DocView):
    __slots__ = ("_sess", "_snap")

    def __init__(self, model, doc, sess):
        super().__init__(model, doc)
        object.__setattr__(self, "_sess", sess)
        object.__setattr__(self, "_snap", None)

    def __repr__(self) -> str:
        return f"<{self._model.__name__} (mongo) id={self._doc.get('_id')}>"

    def __setattr__(self, name, value):
        mapper = sa_inspect(self._model)
        if name in mapper.relationships:
            rel = mapper.relationships[name]
            self._cache[name] = value
            if rel.direction is RelationshipDirection.MANYTOONE:
                for local, remote in rel.local_remote_pairs:
                    fkval = None if value is None else getattr(value, remote.key if remote.key else remote.name)
                    self._cache[_colkey(mapper, local)] = fkval
            return
        if name == "id":
            raise AttributeError("id is immutable")
        if name in mapper.column_attrs:
            for rname, rel in mapper.relationships.items():  # keep cached M2O in sync
                if rel.direction is RelationshipDirection.MANYTOONE and any(
                    _colkey(mapper, l) == name for l, _ in rel.local_remote_pairs
                ):
                    self._cache.pop(rname, None)
        self._cache[name] = value

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        mapper = sa_inspect(self._model)
        if name in mapper.relationships and name not in self._cache:
            val = self._sess._relationship(self, mapper.relationships[name])
            self._cache[name] = val
            return val
        return DocView.__getattr__(self, name)

    def _row(self) -> dict:
        return self.to_dict()


def _colkey(mapper, column) -> str:
    for p in mapper.column_attrs:
        if p.columns[0] is column or p.columns[0].name == column.name:
            return p.key
    return column.name


# --------------------------------------------------------------------------- results


class _Scalars:
    def __init__(self, items):
        self._items = list(items)

    def __iter__(self):
        return iter(self._items)

    def all(self):
        return list(self._items)

    def first(self):
        return self._items[0] if self._items else None

    def one(self):
        if len(self._items) != 1:
            from sqlalchemy.exc import NoResultFound, MultipleResultsFound

            raise (NoResultFound if not self._items else MultipleResultsFound)("expected one row")
        return self._items[0]

    def one_or_none(self):
        if len(self._items) > 1:
            from sqlalchemy.exc import MultipleResultsFound

            raise MultipleResultsFound("expected at most one row")
        return self._items[0] if self._items else None

    def unique(self):
        seen, out = set(), []
        for i in self._items:
            k = id(i) if not isinstance(i, (int, str, tuple)) else i
            if k not in seen:
                seen.add(k)
                out.append(i)
        return _Scalars(out)

    def __len__(self):
        return len(self._items)

    def yield_per(self, n):
        return self

    def partitions(self, size=None):
        size = size or 100
        for i in range(0, len(self._items), size):
            yield self._items[i:i + size]


class _Result(_Scalars):
    """Rows are tuples."""

    def scalars(self):
        return _Scalars(r[0] for r in self._items)

    def scalar(self):
        return self._items[0][0] if self._items else None

    def scalar_one(self):
        return self.scalars().one()

    def scalar_one_or_none(self):
        return self.scalars().one_or_none()

    def mappings(self):
        return _Scalars(dict(enumerate(r)) for r in self._items)

    @property
    def rowcount(self):
        return len(self._items)


class _UpdateResult:
    def __init__(self, n):
        self.rowcount = n

    def scalar(self):
        return None


# --------------------------------------------------------------------------- compiler


def _val(v):
    if isinstance(v, datetime):
        from attestra.persistence.mongo.serialization import ensure_utc

        return ensure_utc(v)
    if isinstance(v, date):
        return datetime.combine(v, time())
    if isinstance(v, (list, tuple, set, frozenset)):
        return [_val(x) for x in v]
    if isinstance(v, MongoRecord) or hasattr(v, "__table__"):
        return v.id
    return v


def _col_of(expr):
    while isinstance(expr, (elements.Grouping, elements.Label)):
        expr = expr.element
    if isinstance(expr, elements.Cast):
        expr = expr.clause
    if hasattr(expr, "table") and isinstance(expr, elements.ColumnClause):
        return expr
    if hasattr(expr, "expression") and isinstance(getattr(expr, "expression", None), elements.ColumnClause):
        return expr.expression
    return None


def _field(col) -> str:
    return "_id" if col.name == "id" else col.name


def _right(expr):
    while isinstance(expr, elements.Grouping):
        expr = expr.element
    if isinstance(expr, elements.BindParameter):
        v = expr.effective_value
        return _val(v)
    if isinstance(expr, elements.Null):
        return None
    if isinstance(expr, elements.True_):
        return True
    if isinstance(expr, elements.False_):
        return False
    if isinstance(expr, elements.ClauseList):  # in_ lists
        return [_right(c) for c in expr.clauses]
    if isinstance(expr, (elements.Tuple,)):
        return [_right(c) for c in expr.clauses]
    raise UnsupportedQuery(f"unsupported right operand {type(expr).__name__}: {expr}")


def _like_regex(pat: str, ci: bool):
    rx = "^" + "".join(".*" if c == "%" else "." if c == "_" else re.escape(c) for c in pat) + "$"
    return {"$regex": rx, **({"$options": "i"} if ci else {})}


_CMP = {
    operators.eq: None, operators.ne: "$ne", operators.lt: "$lt", operators.le: "$lte",
    operators.gt: "$gt", operators.ge: "$gte",
}


def compile_where(expr, tables: set[str] | None = None) -> dict:
    """SQLAlchemy boolean clause -> Mongo filter. ``tables`` limits to columns of those tables."""
    while isinstance(expr, elements.Grouping):
        expr = expr.element
    if isinstance(expr, elements.BooleanClauseList) or (
        isinstance(expr, elements.ClauseList) and expr.operator in (operators.and_, operators.or_)
    ):
        parts = [compile_where(c, tables) for c in expr.clauses]
        parts = [p for p in parts if p]
        if not parts:
            return {}
        if expr.operator is operators.or_:
            return {"$or": parts}
        return parts[0] if len(parts) == 1 else {"$and": parts}
    if isinstance(expr, elements.True_):
        return {}
    if isinstance(expr, elements.False_):
        return {"_id": {"$exists": False}}
    if isinstance(expr, elements.UnaryExpression):
        if expr.operator is operators.inv:
            inner = compile_where(expr.element, tables)
            return {"$nor": [inner]} if inner else {"_id": {"$exists": False}}
        col = _col_of(expr.element)
        if col is not None and expr.operator in (operators.is_true, None):
            return {_field(col): True}
    if isinstance(expr, elements.ColumnClause):
        return {_field(expr): True}
    if isinstance(expr, elements.BinaryExpression):
        op = expr.operator
        left = _col_of(expr.left)
        if left is None and isinstance(expr.left, FunctionElement):
            fn = expr.left.name.lower()
            inner = list(expr.left.clauses)
            if fn in ("lower", "upper") and inner and _col_of(inner[0]) is not None:
                left = _col_of(inner[0])
                v = _right(expr.right)
                if op is operators.eq and isinstance(v, str):
                    return {_field(left): {"$regex": "^" + re.escape(v) + "$", "$options": "i"}}
                if op in (operators.like_op, operators.ilike_op):
                    return {_field(left): _like_regex(v, True)}
            if fn == "coalesce" and inner and _col_of(inner[0]) is not None:
                left = _col_of(inner[0])
                dflt = _right(inner[1]) if len(inner) > 1 else None
                v = _right(expr.right)
                sub = compile_where(left == v if op is operators.eq else op(left, v), tables) if False else None
                f = _field(left)
                cond = _cmp(f, op, v)
                if _matches_default(op, dflt, v):
                    return {"$or": [cond, {f: None}]}
                return cond
            raise UnsupportedQuery(f"unsupported function in where: {expr.left}")
        if left is None:
            raise UnsupportedQuery(f"unsupported left operand: {expr.left}")
        right_col = _col_of(expr.right) if not isinstance(expr.right, elements.BindParameter) else None
        if right_col is not None and right_col is not left:
            raise UnsupportedQuery(f"column-to-column comparison: {expr}")
        if tables is not None and left.table.name not in tables:
            return {}
        f = _field(left)
        if op in (operators.in_op, operators.not_in_op):
            r = expr.right
            while isinstance(r, elements.Grouping):
                r = r.element
            if isinstance(r, elements.BindParameter) and getattr(r, "expanding", False):
                vals = _val(r.effective_value or [])
            elif isinstance(r, (selectable.Select, selectable.ScalarSelect, selectable.Subquery)):
                vals = _subquery_values(r)
            else:
                vals = _right(r)
            vals = list(vals or [])
            return {f: {"$in" if op is operators.in_op else "$nin": vals}}
        if op is operators.is_:
            return {f: _right(expr.right)}
        if op is operators.is_not:
            return {f: {"$ne": _right(expr.right)}}
        if op in (operators.like_op, operators.ilike_op, operators.not_like_op, operators.not_ilike_op):
            rx = _like_regex(_right(expr.right), op in (operators.ilike_op, operators.not_ilike_op))
            return {f: rx} if op in (operators.like_op, operators.ilike_op) else {f: {"$not": re.compile(rx["$regex"], re.I if "$options" in rx else 0)}}
        if op in (operators.contains_op, operators.startswith_op, operators.endswith_op):
            v = re.escape(str(_right(expr.right)))
            rx = {operators.contains_op: v, operators.startswith_op: "^" + v, operators.endswith_op: v + "$"}[op]
            return {f: {"$regex": rx}}
        if op in _CMP:
            return _cmp(f, op, _right(expr.right))
    raise UnsupportedQuery(f"unsupported where clause {type(expr).__name__}: {expr}")


def _cmp(f, op, v):
    m = _CMP.get(op)
    if m is None:
        return {f: v}
    return {f: {m: v}}


def _matches_default(op, dflt, v):
    try:
        return {operators.eq: dflt == v, operators.ne: dflt != v}.get(op, False)
    except Exception:
        return False


def _subquery_values(sq):
    if isinstance(sq, selectable.ScalarSelect):
        sq = sq.element
    if isinstance(sq, selectable.Subquery):
        sq = sq.element
    res = _active_session()._run_select(sq)
    return [r[0] for r in res]


_CURRENT: list = []


def _active_session():
    if not _CURRENT:
        raise UnsupportedQuery("subquery outside MongoSession")
    return _CURRENT[-1]


# --------------------------------------------------------------------------- session


class MongoSession:
    is_mongo = True

    def __init__(self, tenant_ids=None):
        self.info: dict[str, Any] = {"tenant_ids": tenant_ids}
        self._identity: dict[tuple[str, int], Any] = {}
        self._new: list[Any] = []
        self._deleted: list[Any] = []
        self._inserted: list[tuple[str, int]] = []
        self._originals: dict[tuple[str, int], dict | None] = {}
        self.no_autoflush = _NoAutoflush(self)
        self._autoflush = True
        self.bind = None

    # -- context manager / lifecycle
    def __enter__(self):
        return self

    def __exit__(self, et, ev, tb):
        if et:
            self.rollback()
        self.close()

    def close(self):
        pass

    def expunge_all(self):
        self._identity.clear()

    def expire_all(self):
        for obj in list(self._identity.values()):
            if isinstance(obj, MongoRecord):
                self.refresh(obj)

    def expire(self, obj, *a):
        self.refresh(obj)

    def begin_nested(self):
        return _Nested(self)

    def in_transaction(self):
        return True

    def get_bind(self, *a, **k):
        return None

    # -- unit of work
    def add(self, obj):
        if isinstance(obj, MongoRecord) or any(o is obj for o in self._new) or self._is_persisted(obj):
            return
        self._new.append(obj)

    def _is_persisted(self, obj):
        oid = getattr(obj, "id", None)
        return oid is not None and (_table(type(obj)), oid) in self._identity

    def add_all(self, objs):
        for o in objs:
            self.add(o)

    def delete(self, obj):
        if any(o is obj for o in self._new) and getattr(obj, "id", None) is None:
            self._new = [o for o in self._new if o is not obj]
            return
        self._deleted.append(obj)

    def merge(self, obj, **k):
        self.add(obj)
        return obj

    def refresh(self, obj, *a, **k):
        if isinstance(obj, MongoRecord):
            doc = _db()[_table(obj._model)].find_one({"_id": obj.id})
            if doc:
                object.__setattr__(obj, "_doc", doc)
                obj._cache.clear()
                object.__setattr__(obj, "_snap", None)
                self._snapshot(obj)
        elif hasattr(obj, "refresh") and callable(obj.refresh):
            obj.refresh()

    def _model_of(self, obj):
        return obj._model if isinstance(obj, MongoRecord) else type(obj)

    def _wrap(self, model, doc):
        key = (_table(model), doc["_id"])
        hit = self._identity.get(key)
        if hit is not None:
            return hit
        rec = MongoRecord(model, doc, self)
        self._snapshot(rec)
        self._identity[key] = rec
        return rec

    def _snapshot(self, rec):
        try:
            object.__setattr__(rec, "_snap", _to_doc(_table(rec._model), rec._row()))
        except Exception:
            object.__setattr__(rec, "_snap", None)

    def get(self, model, ident, **k):
        if ident is None:
            return None
        if isinstance(ident, (tuple, list)):
            ident = ident[0]
        if isinstance(ident, dict):
            ident = ident.get("id")
        try:
            ident = int(ident)
        except (TypeError, ValueError):
            return None
        key = (_table(model), ident)
        if key in self._identity:
            return self._identity[key]
        self._autoflush_now()
        doc = _db()[_table(model)].find_one({"_id": ident})
        return self._wrap(model, doc) if doc else None

    def get_one(self, model, ident, **k):
        r = self.get(model, ident)
        if r is None:
            from sqlalchemy.exc import NoResultFound

            raise NoResultFound(f"{model.__name__} {ident}")
        return r

    def _autoflush_now(self):
        if self._autoflush:
            self.flush()

    def flush(self, objects=None):
        db = _db()
        from attestra.persistence.mongo.sequences import next_id

        # cascade: new children appended to a loaded record's collection (eng.assets.append(a))
        for rec in list(self._identity.values()):
            is_rec = isinstance(rec, MongoRecord)
            store = rec._cache if is_rec else rec.__dict__
            rmapper = sa_inspect(rec._model if is_rec else type(rec))
            for rname, rel in rmapper.relationships.items():
                if rel.direction is not RelationshipDirection.ONETOMANY or rname not in store:
                    continue
                val = store[rname]
                for child in (val if isinstance(val, list) else [val] if val is not None else []):
                    if isinstance(child, MongoRecord) or not hasattr(child, "__table__"):
                        continue
                    if any(c is child for c in self._new) or self._is_persisted(child):
                        continue
                    cm = sa_inspect(type(child))
                    for local, remote in rel.local_remote_pairs:
                        if getattr(child, _colkey(cm, remote), None) is None:
                            setattr(child, _colkey(cm, remote), getattr(rec, _colkey(rmapper, local)))
                    self._new.append(child)
        # cascade: pick up new instances reachable from new instances' relationships
        i = 0
        while i < len(self._new):
            obj = self._new[i]
            mapper = sa_inspect(type(obj))
            for rel in mapper.relationships:
                v = obj.__dict__.get(rel.key)
                for child in (v if isinstance(v, list) else [v] if v is not None else []):
                    if hasattr(child, "__table__") and not isinstance(child, MongoRecord) and not any(c is child for c in self._new) and not self._is_persisted(child):
                        self._new.append(child)
            i += 1
        # parents first (MANYTOONE targets) - simple repeated pass
        pending = list(self._new)
        self._new = []
        guard = 0
        while pending and guard < 50:
            guard += 1
            rest = []
            for obj in pending:
                if not self._m2o_ready(obj, pending):
                    rest.append(obj)
                    continue
                self._insert(db, obj, next_id)
            if len(rest) == len(pending):
                for obj in rest:
                    self._insert(db, obj, next_id)
                rest = []
            pending = rest
        # dirty records + mutated new objects
        for key, obj in list(self._identity.items()):
            self._write_back(db, key, obj)
        for obj in self._deleted:
            model = self._model_of(obj)
            key = (_table(model), obj.id)
            _append_only(key[0], "delete")
            if key not in self._originals:
                self._originals[key] = db[key[0]].find_one({"_id": obj.id})
            db[key[0]].delete_one({"_id": obj.id})
            self._identity.pop(key, None)
        self._deleted = []

    def _m2o_ready(self, obj, pending):
        mapper = sa_inspect(type(obj))
        for rel in mapper.relationships:
            if rel.direction is RelationshipDirection.MANYTOONE:
                v = obj.__dict__.get(rel.key)
                if v is not None and any(p is v for p in pending) and v is not obj:
                    return False
        return True

    def _insert(self, db, obj, next_id):
        model = type(obj)
        mapper = sa_inspect(model)
        table = _table(model)
        # FKs from MANYTOONE relationship objects
        for rel in mapper.relationships:
            if rel.direction is RelationshipDirection.MANYTOONE:
                v = obj.__dict__.get(rel.key)
                if v is not None:
                    for local, remote in rel.local_remote_pairs:
                        setattr(obj, _colkey(mapper, local), getattr(v, _colkey(rel.mapper, remote)))
        # parent ONETOMANY collections holding this new child
        for col_attr in mapper.column_attrs:
            col = col_attr.columns[0]
            if getattr(obj, col_attr.key, None) is None and col.default is not None and not col.primary_key:
                d = col.default
                try:
                    val = d.arg(None) if d.is_callable else d.arg
                except TypeError:
                    val = d.arg()
                if not getattr(d, "is_sequence", False) and not getattr(d, "is_clause_element", False):
                    setattr(obj, col_attr.key, val)
        if getattr(obj, "id", None) is None and "id" in mapper.column_attrs:
            obj.id = next_id(db, table)
        row = {p.key if p.key == p.columns[0].name else p.columns[0].name: getattr(obj, p.key) for p in mapper.column_attrs}
        doc = _to_doc(table, row)
        db[table].replace_one({"_id": doc["_id"]}, doc, upsert=True)
        key = (table, doc["_id"])
        self._inserted.append(key)
        self._originals.setdefault(key, None)
        self._identity[key] = obj
        obj.__dict__["_mongo_snap"] = doc
        # child collections on the new instance: wire their FKs
        for rel in mapper.relationships:
            if rel.direction is RelationshipDirection.ONETOMANY:
                v = obj.__dict__.get(rel.key)
                for child in v or []:
                    for local, remote in rel.local_remote_pairs:
                        cm = sa_inspect(type(child)) if not isinstance(child, MongoRecord) else None
                        if cm is not None:
                            setattr(child, _colkey(cm, remote), getattr(obj, _colkey(mapper, local)))
        # keep parents' loaded collections current (eng.authorizations after s.add(Authorization(...)))
        for rel in mapper.relationships:
            if rel.direction is not RelationshipDirection.MANYTOONE:
                continue
            back = rel.back_populates or (rel.backref if isinstance(rel.backref, str) else None)
            if not back:
                for prel in rel.mapper.relationships:
                    if prel.direction is RelationshipDirection.ONETOMANY and prel.mapper.class_ is model and prel.secondary is None:
                        back = prel.key
                        break
            if not back:
                continue
            local, remote = rel.local_remote_pairs[0]
            fk = getattr(obj, _colkey(mapper, local), None)
            if fk is None or remote.name != "id":
                continue
            parent = self._identity.get((_table(rel.mapper.class_), fk))
            if parent is None:
                continue
            store = parent._cache if isinstance(parent, MongoRecord) else parent.__dict__
            if back in store and isinstance(store[back], list):
                if not any(c is obj for c in store[back]):
                    store[back].append(obj) if isinstance(parent, MongoRecord) else set_committed_value(parent, back, list(store[back]) + [obj])
            elif not isinstance(parent, MongoRecord):
                set_committed_value(parent, back, self._relationship_for_instance(parent, back))
        # fresh instance: preload its collections so later reads/appends see Mongo state
        for rel in mapper.relationships:
            if rel.direction is RelationshipDirection.ONETOMANY and rel.key not in obj.__dict__ and rel.secondary is None:
                set_committed_value(obj, rel.key, [] if rel.uselist else None)
        # M2O relationships resolvable after flush
        for rel in mapper.relationships:
            if rel.direction is RelationshipDirection.MANYTOONE and rel.key not in obj.__dict__:
                try:
                    fk = getattr(obj, _colkey(mapper, rel.local_remote_pairs[0][0]))
                    if fk is not None:
                        set_committed_value(obj, rel.key, self.get(rel.mapper.class_, fk) if _colkey(rel.mapper, rel.local_remote_pairs[0][1]) == "id" else None)
                except Exception:
                    pass

    def _write_back(self, db, key, obj):
        table = key[0]
        if isinstance(obj, MongoRecord):
            row = obj._row()
            snap = obj._snap
        else:
            mapper = sa_inspect(type(obj))
            row = {p.columns[0].name: getattr(obj, p.key) for p in mapper.column_attrs}
            snap = obj.__dict__.get("_mongo_snap")
        try:
            doc = _to_doc(table, row)
        except Exception:
            return
        if snap is not None and doc == snap:
            return
        _append_only(table, "update")
        model = self._model_of(obj)
        mapper = sa_inspect(model)
        for p in mapper.column_attrs:  # onupdate (updated_at ...)
            col = p.columns[0]
            if col.onupdate is not None and getattr(col.onupdate, "is_callable", False):
                if snap is None or doc.get(col.name) == snap.get(col.name):
                    try:
                        v = col.onupdate.arg(None)
                        if isinstance(obj, MongoRecord):
                            obj._cache[p.key] = v
                        else:
                            setattr(obj, p.key, v)
                        doc[col.name] = _to_doc(table, {"id": 0, col.name: v})[col.name]
                    except Exception:
                        pass
        if key not in self._originals:
            self._originals[key] = copy.deepcopy(snap) if snap is not None else db[table].find_one({"_id": key[1]})
        if isinstance(obj, MongoRecord):
            extra = {k: v for k, v in obj._doc.items() if k not in doc}
            doc.update(extra)
            db[table].replace_one({"_id": key[1]}, doc, upsert=True)
            object.__setattr__(obj, "_snap", {k: v for k, v in doc.items() if k not in extra})
        else:
            db[table].replace_one({"_id": key[1]}, doc, upsert=True)
            obj.__dict__["_mongo_snap"] = doc

    def commit(self):
        self.flush()
        self._inserted = []
        self._originals = {}

    def rollback(self):
        db = _db()
        self._new = []
        self._deleted = []
        for (table, oid), orig in self._originals.items():
            if orig is None:
                db[table].delete_one({"_id": oid})
            else:
                db[table].replace_one({"_id": oid}, orig, upsert=True)
        self._originals = {}
        self._inserted = []
        self._identity.clear()

    # -- relationships
    def _relationship_for_instance(self, obj, key):
        rel = sa_inspect(type(obj)).relationships[key]
        target = rel.mapper.class_
        local, remote = rel.local_remote_pairs[0]
        lv = getattr(obj, _colkey(sa_inspect(type(obj)), local))
        field = "_id" if remote.name == "id" else remote.name
        items = [self._wrap(target, d) for d in _db()[_table(target)].find({field: lv}).sort("_id", 1)]
        return items if rel.uselist else (items[0] if items else None)

    def _relationship(self, rec, rel):
        target = rel.mapper.class_
        pairs = list(rel.local_remote_pairs)
        if rel.secondary is not None or not pairs:
            return [] if rel.uselist else None
        local, remote = pairs[0]
        lkey = _colkey(sa_inspect(rec._model), local)
        lv = getattr(rec, lkey)
        if lv is None:
            return [] if rel.uselist else None
        if rel.direction is RelationshipDirection.MANYTOONE and remote.name == "id":
            return self.get(target, lv)
        self._autoflush_now()
        field = "_id" if remote.name == "id" else remote.name
        cur = _db()[_table(target)].find({field: lv}).sort("_id", 1)
        items = [self._wrap(target, d) for d in cur]
        if rel.order_by:
            items = _py_sort(items, rel.order_by)
        if rel.uselist:
            return items
        return items[0] if items else None

    # -- queries
    def scalars(self, stmt, params=None, **k):
        return self.execute(stmt).scalars()

    def scalar(self, stmt, params=None, **k):
        return self.execute(stmt).scalar()

    def execute(self, stmt, params=None, **k):
        from sqlalchemy.sql.dml import Delete, Update

        if isinstance(stmt, Update):
            return self._run_update(stmt)
        if isinstance(stmt, Delete):
            return self._run_delete(stmt)
        if not isinstance(stmt, selectable.Select):
            raise UnsupportedQuery(f"raw SQL is not available in Mongo mode: {str(stmt)[:120]}")
        return _Result(self._run_select(stmt))

    def _base_and_filter(self, stmt, model):
        filt = {}
        if stmt.whereclause is not None:
            filt = self._where_with_joins(stmt, model)
        return filt

    def _where_with_joins(self, stmt, model):
        base_table = _table(model)
        joins = _joined_models(stmt)
        clauses = _and_parts(stmt.whereclause)
        base_parts, by_join = [], {}
        for c in clauses:
            tabs = {col.table.name for col in _columns_in(c)}
            if not tabs or tabs == {base_table}:
                base_parts.append(compile_where(c))
            elif len(tabs) == 1 and next(iter(tabs)) in joins:
                by_join.setdefault(next(iter(tabs)), []).append(c)
            else:
                raise UnsupportedQuery(f"cross-table where needs a Mongo branch: {c}")
        for jt, cs in by_join.items():
            jmodel, base_fk, jkey = joins[jt]
            jf = {"$and": [compile_where(c) for c in cs]}
            jfield = "_id" if jkey == "id" else jkey
            vals = [d.get(jfield) for d in _db()[jt].find(jf, {jfield: 1})]
            base_parts.append({("_id" if base_fk == "id" else base_fk): {"$in": vals}})
        base_parts = [p for p in base_parts if p]
        if not base_parts:
            return {}
        return base_parts[0] if len(base_parts) == 1 else {"$and": base_parts}

    def _run_select(self, stmt):
        _CURRENT.append(self)
        try:
            self._autoflush_now()
            return self._select(stmt)
        finally:
            _CURRENT.pop()

    def _select(self, stmt):
        descs = stmt.column_descriptions
        ents = [d.get("entity") for d in descs]
        model = next((e for e in ents if e is not None), None)
        if model is None:
            froms = stmt.get_final_froms()
            for fr in froms:
                m = _model_for_table(getattr(fr, "name", None))
                if m is not None:
                    model = m
                    break
        if model is None:
            raise UnsupportedQuery(f"cannot determine collection for {stmt}")
        coll = _db()[_table(model)]
        filt = self._base_and_filter(stmt, model)
        cols = list(stmt.selected_columns)
        group = list(stmt._group_by_clauses)
        aggs = [c for c in cols if _is_agg(c)]
        if aggs and not group:
            docs = list(coll.find(filt))
            return [tuple(_agg(c, docs) for c in cols)]
        if group:
            docs = list(coll.find(filt))
            buckets: dict = {}
            gcols = [_col_of(g) for g in group]
            for d in docs:
                bk = tuple(_docval(d, gc) for gc in gcols)
                buckets.setdefault(bk, []).append(d)
            rows = []
            for bk, ds in buckets.items():
                row = []
                for c in cols:
                    if _is_agg(c):
                        row.append(_agg(c, ds))
                    else:
                        cc = _col_of(c)
                        row.append(_coerce(cc.type, _docval(ds[0], cc)))
                rows.append(tuple(row))
            return _order_rows(rows, stmt, cols)
        cur = coll.find(filt)
        sort = _sort_spec(stmt)
        py_sort = sort is None
        if sort:
            cur = cur.sort(sort)
        off = _intval(stmt._offset_clause)
        lim = _intval(stmt._limit_clause)
        if not py_sort or not stmt._order_by_clauses:
            if off:
                cur = cur.skip(off)
            if lim:
                cur = cur.limit(lim)
        recs = [self._wrap(model, d) for d in cur]
        if py_sort and stmt._order_by_clauses:
            recs = _py_sort(recs, stmt._order_by_clauses)
            recs = recs[off or 0:(off or 0) + lim if lim else None]
        if stmt._distinct and len(cols) == 1 and not (len(descs) == 1 and descs[0].get("expr") is model):
            pass
        out = []
        whole = all(d.get("expr") is d.get("entity") and d.get("entity") is not None for d in descs)
        for r in recs:
            if whole:
                out.append(tuple(r for _ in descs))
            else:
                row = []
                for d, c in zip(descs, cols):
                    if d.get("expr") is d.get("entity") and d.get("entity") is model:
                        row.append(r)
                    else:
                        cc = _col_of(c)
                        if cc is None or cc.table.name != _table(model):
                            raise UnsupportedQuery(f"unsupported selected column {c}")
                        row.append(getattr(r, _colkey(sa_inspect(model), cc)))
                out.append(tuple(row))
        if stmt._distinct:
            seen, uniq = set(), []
            for row in out:
                k = tuple(id(x) if isinstance(x, MongoRecord) else (x if isinstance(x, (int, str, float, type(None))) else repr(x)) for x in row)
                if k not in seen:
                    seen.add(k)
                    uniq.append(row)
            out = uniq
        return out

    def _run_update(self, stmt):
        _append_only(stmt.table.name, "update")
        model = _model_for_table(stmt.table.name)
        self._autoflush_now()
        filt = compile_where(stmt.whereclause) if stmt.whereclause is not None else {}
        values = {}
        for k, v in stmt._values.items():
            name = getattr(k, "name", k)
            values[name] = _right(v)
        doc = _to_doc(_table(model), {"id": 0, **values})
        doc.pop("_id", None)
        res = _db()[_table(model)].update_many(filt, {"$set": doc})
        for key in [k for k in self._identity if k[0] == _table(model)]:
            obj = self._identity[key]
            if isinstance(obj, MongoRecord):
                self.refresh(obj)
        return _UpdateResult(res.modified_count if res.matched_count else 0)

    def _run_delete(self, stmt):
        _append_only(stmt.table.name, "delete")
        model = _model_for_table(stmt.table.name)
        self._autoflush_now()
        filt = compile_where(stmt.whereclause) if stmt.whereclause is not None else {}
        res = _db()[_table(model)].delete_many(filt)
        for key in [k for k in self._identity if k[0] == _table(model)]:
            self._identity.pop(key, None)
        return _UpdateResult(res.deleted_count)

    def query(self, *a, **k):
        raise UnsupportedQuery("Session.query is not supported in Mongo mode; use select()")

    def connection(self, *a, **k):
        raise UnsupportedQuery("no SQL connection in Mongo mode")


class _NoAutoflush:
    def __init__(self, s):
        self.s = s

    def __enter__(self):
        self.prev = self.s._autoflush
        self.s._autoflush = False
        return self.s

    def __exit__(self, *a):
        self.s._autoflush = self.prev


class _Nested:
    def __init__(self, s):
        self.s = s

    def __enter__(self):
        return self

    def __exit__(self, et, *a):
        return False

    def commit(self):
        self.s.flush()

    def rollback(self):
        pass


# --------------------------------------------------------------------------- helpers


def _model_for_table(name):
    if not name:
        return None
    from attestra.models import Base

    for m in Base.registry.mappers:
        if getattr(m.class_, "__tablename__", None) == name:
            return m.class_
    return None


def _joined_models(stmt):
    out = {}
    for j in getattr(stmt, "_setup_joins", ()) or ():
        target, onclause = j[0], j[1]
        tmodel = getattr(target, "class_", target)
        if not hasattr(tmodel, "__table__"):
            tmodel = _model_for_table(getattr(target, "name", None))
            if tmodel is None:
                continue
        tt = _table(tmodel)
        if onclause is None:
            raise UnsupportedQuery("join without explicit on clause")
        oc = onclause
        while isinstance(oc, elements.Grouping):
            oc = oc.element
        if not isinstance(oc, elements.BinaryExpression) or oc.operator is not operators.eq:
            raise UnsupportedQuery(f"complex join: {onclause}")
        l, r = _col_of(oc.left), _col_of(oc.right)
        if l.table.name == tt:
            l, r = r, l
        out[tt] = (tmodel, l.name, r.name)
    return out


def _and_parts(expr):
    while isinstance(expr, elements.Grouping):
        expr = expr.element
    if hasattr(expr, 'clauses') and getattr(expr, 'operator', None) is operators.and_:
        out = []
        for c in expr.clauses:
            out.extend(_and_parts(c))
        return out
    return [expr]


def _columns_in(expr):
    from sqlalchemy.sql import visitors

    return [c for c in visitors.iterate(expr) if isinstance(c, elements.ColumnClause) and getattr(c, "table", None) is not None]


def _is_agg(c):
    while isinstance(c, elements.Label):
        c = c.element
    return isinstance(c, FunctionElement) and c.name.lower() in ("count", "max", "min", "sum", "avg")


def _docval(doc, col):
    return doc.get("_id") if col.name == "id" else doc.get(col.name)


def _agg(c, docs):
    while isinstance(c, elements.Label):
        c = c.element
    name = c.name.lower()
    args = list(c.clauses)
    col = _col_of(args[0]) if args else None
    if col is not None and (getattr(col, "table", None) is None or col.name == "*"):
        col = None  # count(*) / count()
    if name == "count":
        if c._has_args if hasattr(c, "_has_args") else False:
            pass
        if col is None:
            return len(docs)
        vals = [_docval(d, col) for d in docs if _docval(d, col) is not None]
        if any("DISTINCT" in str(a).upper() for a in args):
            return len(set(map(repr, vals)))
        return len(vals)
    vals = [_docval(d, col) for d in docs if col is not None and _docval(d, col) is not None]
    if not vals:
        return None
    if name == "max":
        return _coerce(col.type, max(vals))
    if name == "min":
        return _coerce(col.type, min(vals))
    if name == "sum":
        return sum(vals)
    return sum(vals) / len(vals)


def _intval(clause):
    if clause is None:
        return 0
    try:
        return int(clause.effective_value if hasattr(clause, "effective_value") else clause.value)
    except Exception:
        return 0


def _sort_spec(stmt):
    spec = []
    for ob in stmt._order_by_clauses:
        direction = 1
        e = ob
        while isinstance(e, elements.UnaryExpression):
            if e.modifier is operators.desc_op:
                direction = -1
            elif e.modifier is operators.asc_op:
                direction = 1
            e = e.element
        col = _col_of(e)
        if col is None:
            return None
        spec.append((_field(col), direction))
    return spec or []


def _py_sort(items, order_by):
    keys = []
    for ob in order_by:
        rev, e = False, ob
        while isinstance(e, elements.UnaryExpression):
            if e.modifier is operators.desc_op:
                rev = True
            e = e.element
        col = _col_of(e)
        if col is None:
            continue
        keys.append((col.key or col.name, rev))
    for name, rev in reversed(keys):
        items = sorted(items, key=lambda r, n=name: (getattr(r, n, None) is None, getattr(r, n, None) if getattr(r, n, None) is not None else 0), reverse=rev)
    return items


def _order_rows(rows, stmt, cols):
    return rows
