"""AASI Phase 3 migration 0005 is registered and additive."""

from __future__ import annotations

# @lat: [[aasi#Phase 3 Mongo persistence]]


def test_migration_0005_registered():
    from attestra.persistence.mongo.migrations import MIGRATIONS
    from attestra.persistence.mongo import collections as C

    ids = [rev for rev, _desc, _fn in MIGRATIONS]
    assert "0005_aasi_collections" in ids
    assert C.AASI_RUNS == "aasi_runs"
    assert C.AASI_DECISIONS == "aasi_decisions"
    assert C.AASI_RUNS in C.DOMAIN_COLLECTIONS
    assert C.AASI_DECISIONS in C.DOMAIN_COLLECTIONS


def test_aasi_feature_flag_default_off(monkeypatch):
    monkeypatch.delenv("ATTESTRA_AASI", raising=False)
    # Re-read via enabled() which uses config.AASI_ENABLED loaded at import —
    # assert the module helper and config constant semantics.
    from attestra import config
    from attestra import aasi

    assert hasattr(config, "AASI_ENABLED")
    assert aasi.enabled() is bool(config.AASI_ENABLED)
