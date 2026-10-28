"""Database engine and session handling."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from attestra import config


class Base(DeclarativeBase):
    pass


_engine = None
_SessionLocal: sessionmaker | None = None

# Tenant ids the current request may see (None = unrestricted). Read by session()
# and pushed to Postgres as ``app.tenant_id`` for row-level security (Phase 6.1).
_UNSET = object()
current_tenant_ids: ContextVar[frozenset[int] | None] = ContextVar("attestra_tenant_ids", default=None)


def normalize_url(url: str) -> str:
    """Use the psycopg 3 driver for bare ``postgres://`` / ``postgresql://`` URLs."""
    for prefix in ("postgres://", "postgresql://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix):]
    return url


def is_postgres(url: str) -> bool:
    return normalize_url(url).startswith("postgresql")


@contextmanager
def tenant_scope(tenant_ids: Iterable[int] | None) -> Iterator[None]:
    """Restrict sessions opened inside this block to ``tenant_ids`` (RLS on Postgres)."""
    token = current_tenant_ids.set(None if tenant_ids is None else frozenset(int(t) for t in tenant_ids))
    try:
        yield
    finally:
        current_tenant_ids.reset(token)


def upgrade(url: str | None = None) -> None:
    """Apply Alembic migrations to head (production / `attestra init` / serve startup)."""
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", normalize_url(url or config.DATABASE_URL).replace("%", "%%"))
    command.upgrade(cfg, "head")


def init(url: str | None = None, *, use_migrations: bool = False) -> None:
    """Create the engine and tables.

    Tests and quick local use call ``create_all`` (fast). Production start-up should
    pass ``use_migrations=True`` or call :func:`upgrade` so schema comes from Alembic.
    """
    global _engine, _SessionLocal
    if url is None and _engine is not None:
        return
    config.ensure_dirs()
    url = normalize_url(url or config.DATABASE_URL)
    if url.startswith("sqlite"):
        # timeout: wait up to 30 s for a write lock instead of failing at once when the
        # worker runs several scans in parallel (and the web server writes too).
        kwargs = {"connect_args": {"check_same_thread": False, "timeout": 30}}
    else:
        kwargs = {"pool_pre_ping": True}
    _engine = create_engine(url, **kwargs)
    _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False)
    from attestra import models  # noqa: F401  (register tables)

    if use_migrations:
        upgrade(url)
    else:
        Base.metadata.create_all(_engine)
        _add_missing_columns(_engine)
        _install_audit_triggers(_engine)


def _add_missing_columns(engine) -> None:
    """Deprecated ad-hoc migration for additive columns. Prefer Alembic (``upgrade``)."""
    insp = inspect(engine)
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if not insp.has_table(table.name):
                continue
            existing = {c["name"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name in existing:
                    continue
                ddl = f"ALTER TABLE {table.name} ADD COLUMN {col.name} {col.type.compile(engine.dialect)}"
                default = col.default.arg if col.default is not None and not callable(col.default.arg) else None
                if isinstance(default, bool):
                    ddl += f" DEFAULT {int(default)}"
                elif isinstance(default, (int, float)):
                    ddl += f" DEFAULT {default}"
                elif isinstance(default, str):
                    ddl += " DEFAULT '" + default.replace("'", "''") + "'"
                conn.execute(text(ddl))


def _install_audit_triggers(engine) -> None:
    """Enforce append-only audit_events for create_all (tests / quick local)."""
    if engine.dialect.name != "sqlite":
        return
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                CREATE TRIGGER IF NOT EXISTS audit_events_no_update
                BEFORE UPDATE ON audit_events
                BEGIN
                    SELECT RAISE(ABORT, 'audit_events is append-only');
                END;
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
                BEFORE DELETE ON audit_events
                BEGIN
                    SELECT RAISE(ABORT, 'audit_events is append-only');
                END;
                """
            )
        )


def _apply_tenant_setting(s: Session, transaction, connection) -> None:
    """Set ``app.tenant_id`` for this transaction (SET LOCAL semantics, pool-safe)."""
    if connection.dialect.name != "postgresql":
        return
    from attestra.rls import SETTING, setting_value

    ids = s.info.get("tenant_ids")
    connection.execute(
        text("SELECT set_config(:k, :v, true)"), {"k": SETTING, "v": setting_value(ids)}
    )


@contextmanager
def session(tenant_ids: Iterable[int] | None | object = _UNSET) -> Iterator[Session]:
    """Unit-of-work session.

    ``tenant_ids`` (or the surrounding :func:`tenant_scope`) limits which tenants'
    rows Postgres RLS exposes. ``None`` means unrestricted. Re-applied on every
    transaction because ``set_config(..., true)`` is transaction-local.
    """
    if _SessionLocal is None:
        init()
    if tenant_ids is _UNSET:
        ids = current_tenant_ids.get()
    else:
        ids = None if tenant_ids is None else frozenset(int(t) for t in tenant_ids)
    s = _SessionLocal()
    s.info["tenant_ids"] = ids
    event.listen(s, "after_begin", _apply_tenant_setting)
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()
