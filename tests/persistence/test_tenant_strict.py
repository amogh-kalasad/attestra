"""K-01: tenant scope fails closed under ATTESTRA_TENANT_STRICT; SYSTEM_SCOPE is explicit.

No MongoDB needed: repositories run against an in-memory fake collection.
"""
# @lat: [[attack-surface-and-platform#Tenant strict mode]]

from __future__ import annotations

import copy
import pickle

import pytest

from attestra.persistence.mongo import tenant as T
from attestra.persistence.mongo.repositories.base import BaseRepository
from tests.discovery._fakedb import FakeDB


class WidgetRepo(BaseRepository):
    collection_name = "widgets"


@pytest.fixture
def strict(monkeypatch):
    monkeypatch.setattr(T, "strict_enabled", lambda: True)


@pytest.fixture
def lax(monkeypatch):
    monkeypatch.setattr(T, "strict_enabled", lambda: False)


@pytest.fixture
def db():
    d = FakeDB()
    d["widgets"].insert_one({"_id": 1, "tenant_id": 10, "name": "a"})
    d["widgets"].insert_one({"_id": 2, "tenant_id": 20, "name": "b"})
    d["engagements"].insert_one({"_id": 100, "tenant_id": 10})
    d["engagements"].insert_one({"_id": 200, "tenant_id": 20})
    return d


def test_strict_flag_off_by_default(monkeypatch):
    from attestra import config

    monkeypatch.delenv("ATTESTRA_TENANT_STRICT", raising=False)
    monkeypatch.setattr(config, "TENANT_STRICT", None, raising=False)
    assert T.strict_enabled() is False
    monkeypatch.setenv("ATTESTRA_TENANT_STRICT", "1")
    assert T.strict_enabled() is True
    # Once INT wires config.TENANT_STRICT it wins over the env var.
    monkeypatch.setattr(config, "TENANT_STRICT", False, raising=False)
    assert T.strict_enabled() is False


def test_legacy_none_is_unrestricted_when_not_strict(lax):
    assert T.effective_scope(None) is None
    assert T.tenant_filter("tenant_id", None) == {}
    T.require_tenant_access(99, None)  # no raise


def test_strict_none_denies(strict, caplog):
    with caplog.at_level("WARNING", logger="attestra.tenant"):
        assert T.effective_scope(None, where="unit") == frozenset()
    assert "tenant scope missing in unit" in caplog.text
    assert T.tenant_filter("tenant_id", None) == {"tenant_id": {"$in": []}}
    with pytest.raises(T.TenantAccessDenied):
        T.require_tenant_access(10, None)


def test_system_scope_is_explicit_unrestricted(strict):
    assert T.effective_scope(T.SYSTEM_SCOPE) is None
    assert T.tenant_filter("tenant_id", T.SYSTEM_SCOPE) == {}
    T.require_tenant_access(10, T.SYSTEM_SCOPE)
    assert T.normalize_tenant_ids(T.SYSTEM_SCOPE) is T.SYSTEM_SCOPE


def test_system_scope_fails_closed_if_treated_as_plain_set():
    # Code that does not know the sentinel sees an empty tenant set → no access.
    assert len(T.SYSTEM_SCOPE) == 0
    assert 10 not in T.SYSTEM_SCOPE
    assert copy.copy(T.SYSTEM_SCOPE) is T.SYSTEM_SCOPE
    assert pickle.loads(pickle.dumps(T.SYSTEM_SCOPE)) is T.SYSTEM_SCOPE


def test_explicit_tenant_set_unchanged_by_strict(strict):
    assert T.tenant_filter("tenant_id", frozenset({20, 10})) == {"tenant_id": {"$in": [10, 20]}}
    T.require_tenant_access(10, frozenset({10}))
    with pytest.raises(T.TenantAccessDenied):
        T.require_tenant_access(20, frozenset({10}))


def test_engagement_ids_strict(db, strict):
    assert T.engagement_ids_for_tenants(db, None) == []
    assert T.engagement_ids_for_tenants(db, T.SYSTEM_SCOPE) is None
    assert T.engagement_ids_for_tenants(db, frozenset({10})) == [100]
    assert T.via_engagement_filter(db, None) == {"engagement_id": {"$in": []}}


def test_repository_unscoped_read_raises_under_strict(db, strict):
    repo = WidgetRepo(db, tenant_ids=None)
    assert repo.tenant_ids == frozenset()
    assert repo.requested_tenant_ids is None
    with pytest.raises(T.TenantAccessDenied):
        repo.get_raw(1)


def test_repository_unscoped_write_raises_under_strict(db, strict):
    repo = WidgetRepo(db, tenant_ids=None)
    with pytest.raises(T.TenantAccessDenied):
        repo.insert_with_id({"tenant_id": 10, "name": "new"}, doc_id=3)
    assert repo.replace(1, {"tenant_id": 10, "name": "x"}) is None
    assert repo.delete(1) is False
    assert db["widgets"].find_one({"_id": 1})["name"] == "a"


def test_repository_system_scope_passes_under_strict(db, strict):
    repo = WidgetRepo(db, tenant_ids=T.SYSTEM_SCOPE)
    assert repo.tenant_ids is None
    assert repo.get_raw(2)["name"] == "b"
    repo.insert_with_id({"tenant_id": 20, "name": "c"}, doc_id=3)
    assert db["widgets"].find_one({"_id": 3})


def test_repository_cross_tenant_denied_in_both_modes(db, monkeypatch):
    for mode in (True, False):
        monkeypatch.setattr(T, "strict_enabled", lambda m=mode: m)
        repo = WidgetRepo(db, tenant_ids=frozenset({10}))
        assert repo.get_raw(1)["name"] == "a"
        with pytest.raises(T.TenantAccessDenied):
            repo.get_raw(2)
        with pytest.raises(T.TenantAccessDenied):
            repo.insert_with_id({"tenant_id": 20, "name": "evil"}, doc_id=50 + int(mode))


def test_repository_legacy_none_still_unrestricted_when_flag_off(db, lax):
    repo = WidgetRepo(db, tenant_ids=None)
    assert repo.tenant_ids is None
    assert repo.get_raw(2)["name"] == "b"
