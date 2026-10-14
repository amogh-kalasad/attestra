"""Database engine and session handling."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from attestra import config


class Base(DeclarativeBase):
    pass


_engine = None
_SessionLocal: sessionmaker | None = None


def upgrade(url: str | None = None) -> None:
    """Apply Alembic migrations to head (production / `attestra init` / serve startup)."""
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", url or config.DATABASE_URL)
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
    url = url or config.DATABASE_URL
    kwargs = {"connect_args": {"check_same_thread": False}} if url.startswith("sqlite") else {}
    _engine = create_engine(url, **kwargs)
    _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False)
    from attestra import models  # noqa: F401  (register tables)

    if use_migrations:
        upgrade(url)
    else:
        Base.metadata.create_all(_engine)
        _add_missing_columns(_engine)


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


@contextmanager
def session() -> Iterator[Session]:
    if _SessionLocal is None:
        init()
    s = _SessionLocal()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()
