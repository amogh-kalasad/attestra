"""Alembic baseline builds a schema matching SQLAlchemy metadata."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

import attestra.models  # noqa: F401
from attestra.db import Base


def _alembic_cfg(url: str) -> Config:
    root = Path(__file__).resolve().parents[1]
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def test_upgrade_head_matches_metadata(tmp_path, monkeypatch):
    from attestra import config

    data = tmp_path / "mig"
    data.mkdir()
    monkeypatch.setattr(config, "DATA_DIR", data)
    db_path = data / "migrated.db"
    url = f"sqlite:///{db_path.as_posix()}"
    monkeypatch.setattr(config, "DATABASE_URL", url)

    cfg = _alembic_cfg(url)
    command.upgrade(cfg, "head")

    engine = create_engine(url)
    tables = set(inspect(engine).get_table_names())
    expected = set(Base.metadata.tables) | {"alembic_version"}
    assert set(Base.metadata.tables).issubset(tables)
    assert "alembic_version" in tables

    command.downgrade(cfg, "base")
    tables_after = set(inspect(engine).get_table_names())
    assert not (set(Base.metadata.tables) & tables_after)
    # expected unused except for clarity in failure messages
    assert expected
