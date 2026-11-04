"""One-shot SQL removal for the Mongo-only Attestra (dry run by default).

    python scripts/mongo_only_removal.py            # print the plan, change nothing
    python scripts/mongo_only_removal.py --apply    # apply (files are MOVED, never deleted)
    python scripts/mongo_only_removal.py --apply --include-shared   # also files owned by other workers

Every moved file goes to .migration_backups/sql_removal/<relative path>; every edited
file is first copied to <file>.bak_mongofull (if no backup exists yet). No git writes.
"""
from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / ".migration_backups" / "sql_removal"

# -- files moved out (mine / unshared)
MOVE = [
    "migrations",                                   # Alembic versions
    "alembic.ini",
    "attestra/persistence/mongo/dualwrite.py",      # SQL->Mongo mirror (obsolete)
    "tests/test_postgres_rls.py",                   # Postgres RLS
]
# -- files owned by other workers: moved only with --include-shared, after they sign off
MOVE_SHARED = [
    "attestra/persistence/mongo/dualwrite_identity.py",   # identity worker (cli.py:51 installs it)
    "tests/persistence/test_mongo_module_mirror.py",      # backfill-from-SQL tests
    "tests/persistence/test_mongo_identity_webhooks.py",  # contains SQL mirror backfill test
]

NEW_DB_PY = '''"""Session handling - MongoDB only.

``session()`` yields a :class:`MongoSession` (SQLAlchemy-Session look-alike that
persists straight to MongoDB). The declarative ``Base`` stays as the schema that
MongoSession maps; there is no SQL engine.
"""
from __future__ import annotations

from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


_engine = None          # kept for callers that probe it (api.py observability)
_SessionLocal = None

_UNSET = object()
current_tenant_ids: ContextVar[frozenset[int] | None] = ContextVar("attestra_tenant_ids", default=None)


def normalize_url(url: str) -> str:  # legacy helper (mongo-migrate import of old SQL dumps)
    for prefix in ("postgres://", "postgresql://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix):]
    return url


def is_postgres(url: str) -> bool:
    return normalize_url(url).startswith("postgresql")


@contextmanager
def tenant_scope(tenant_ids: Iterable[int] | None) -> Iterator[None]:
    token = current_tenant_ids.set(None if tenant_ids is None else frozenset(int(t) for t in tenant_ids))
    try:
        yield
    finally:
        current_tenant_ids.reset(token)


def init(url: str | None = None, *, use_migrations: bool = False) -> None:
    """Initialise MongoDB (client + schema migrations). ``url``/``use_migrations`` are ignored."""
    from attestra.persistence.mongo.adapters import _db

    _db()


def upgrade(url: str | None = None) -> None:
    init()


@contextmanager
def session(tenant_ids: Iterable[int] | None | object = _UNSET):
    from attestra.persistence.mongo.orm_session import MongoSession

    if tenant_ids is _UNSET:
        ids = current_tenant_ids.get()
    else:
        ids = None if tenant_ids is None else frozenset(int(t) for t in tenant_ids)
    s = MongoSession(ids)
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
'''

NEW_PERSISTENCE_INIT = '''"""Persistence backend for Attestra: MongoDB only."""

from __future__ import annotations


def persistence_backend() -> str:
    return "mongo"


def using_mongo() -> bool:
    return True
'''

# -- (file, regex, replacement) text edits
EDITS: list[tuple[str, str, str]] = [
    # ops/backup.py: drop the SQLite branches
    ("attestra/ops/backup.py", r"^import sqlite3\n", ""),
    ("attestra/ops/backup.py",
     r"(    if using_mongo\(\):\n        from attestra\.ops\.mongo_backup import backup_mongo\n\n        return backup_mongo\(dest\)\n)[\s\S]*?(?=\n\ndef verify_manifest)",
     r"\1"),
    ("attestra/ops/backup.py",
     r"\n    ok, errors = verify_manifest\(backup_dir\)\n    if not ok:\n        raise BackupError\(\"restore refused: \" \+ \"; \"\.join\(errors\)\)\n[\s\S]*\Z",
     "\n    ok, errors = verify_manifest(backup_dir)\n    raise BackupError(\"restore refused: \" + (\"; \".join(errors) if errors else \"not a MongoDB logical backup\"))\n"),
    # .env.example: no SQL settings
    (".env.example", r"(?m)^ATTESTRA_PERSISTENCE=.*\n", ""),
    (".env.example", r"(?m)^#?\s*ATTESTRA_DATABASE_URL=.*\n", ""),
    (".env.example", r"(?m)^#?\s*ATTESTRA_MONGO_READS=.*\n", ""),
]
REWRITE = {
    "attestra/db.py": NEW_DB_PY,
    "attestra/persistence/__init__.py": NEW_PERSISTENCE_INIT,
}

# -- follow-ups the script reports but does not touch (owner, file, what)
FOLLOW_UPS = [
    ("identity worker", "attestra/cli.py:51", "drop _install_identity_mirror(db._SessionLocal)"),
    ("web worker", "attestra/api.py:53", "drop SQL engine instrumentation branch (harmless: _engine is None)"),
    ("web worker", "attestra/web/data_access.py", "drop sql branches / ATTESTRA_MONGO_READS checks"),
    ("reports worker", "attestra/persistence/mongo/report_reads.py", "drop SQL fallback"),
    ("reports worker", "tests/persistence/test_mongo_reports.py", "mirrored fixture uses s.query on SQL"),
    ("tests worker", "tests/conftest.py", "drop SQLite init + --persistence option (Mongo only)"),
    ("everyone", "sql_only-marked tests", "delete (SQL triggers/RLS/sql_chain)"),
    ("everyone", "`if using_mongo(): ... else:` branches", "keep the Mongo side only (mechanical cleanup)"),
    ("everyone", "ATTESTRA_SQL_SESSION / mongo_reads()", "remove flags; read_models.mongo_reads -> always True"),
]


def _backup(p: Path, apply: bool) -> None:
    b = p.with_name(p.name + ".bak_mongofull")
    if apply and p.exists() and not b.exists():
        shutil.copy2(p, b)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--include-shared", action="store_true")
    a = ap.parse_args()
    tag = "APPLY" if a.apply else "DRY"
    moves = MOVE + (MOVE_SHARED if a.include_shared else [])
    for rel in moves:
        src = ROOT / rel
        if not src.exists():
            print(f"[{tag}] skip (missing) {rel}")
            continue
        print(f"[{tag}] move {rel} -> .migration_backups/sql_removal/{rel}")
        if a.apply:
            dst = ARCHIVE / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src), str(dst))
    if not a.include_shared:
        for rel in MOVE_SHARED:
            print(f"[{tag}] (shared, needs --include-shared) {rel}")
    for rel, content in REWRITE.items():
        p = ROOT / rel
        print(f"[{tag}] rewrite {rel} (Mongo-only)")
        if a.apply:
            _backup(p, True)
            p.write_text(content, encoding="utf-8")
    for rel, rx, rep in EDITS:
        p = ROOT / rel
        if not p.exists():
            print(f"[{tag}] skip edit (missing) {rel}")
            continue
        text = p.read_text(encoding="utf-8")
        new, n = re.subn(rx, rep, text, count=1, flags=re.M)
        print(f"[{tag}] edit {rel}: {'match' if n else 'NO MATCH'} /{rx[:50]}.../")
        if a.apply and n:
            _backup(p, True)
            p.write_text(new, encoding="utf-8")
    print("\nFollow-ups for other owners (not changed by this script):")
    for owner, where, what in FOLLOW_UPS:
        print(f"  - [{owner}] {where}: {what}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
