"""Tenant isolation for Mongo repositories (replacement for PostgreSQL RLS).

Uses the shared ``mongo_test_db`` fixture (throwaway ``attestra_test_*`` DB on the
local replica set, dropped afterwards). Never touches the live ``attestra`` DB.
"""
from __future__ import annotations

import pytest

pytest.importorskip("pymongo")

pytestmark = pytest.mark.mongo


@pytest.fixture
def two_tenants(mongo_test_db):
    from attestra.persistence.mongo.repositories.core import (
        ApiKeyRepository,
        EngagementRepository,
        FindingRepository,
        TenantRepository,
        UserRepository,
    )

    db = mongo_test_db
    a = TenantRepository(db).create("tenant-a")
    b = TenantRepository(db).create("tenant-b")
    ea = EngagementRepository(db).create(a["id"], "eng-a", "web")
    eb = EngagementRepository(db).create(b["id"], "eng-b", "web")
    ua = UserRepository(db).create("user-a", tenant_id=a["id"])
    ub = UserRepository(db).create("user-b", tenant_id=b["id"])
    admin = UserRepository(db).create("admin", role="admin")
    kb = ApiKeyRepository(db).create(ub["id"], "hash-b", "pfx-b")
    fb = FindingRepository(db).create(eb["id"], "fp-b", "finding-b")
    return {"db": db, "a": a["id"], "b": b["id"], "ea": ea["id"], "eb": eb["id"],
            "ua": ua["id"], "ub": ub["id"], "admin": admin["id"], "kb": kb["id"], "fb": fb["id"]}


def _hidden(fn):
    """Cross-tenant access must look like "not found": None/False or TenantAccessDenied."""
    from attestra.persistence.mongo.tenant import TenantAccessDenied

    try:
        out = fn()
    except TenantAccessDenied:
        return True
    return out is None or out is False


def test_test_db_is_throwaway(mongo_test_db):
    assert mongo_test_db.name.startswith("attestra_test_")
    assert mongo_test_db.name != "attestra"


def test_base_get_replace_delete_cross_tenant(two_tenants):
    from attestra.persistence.mongo.repositories.core import EngagementRepository, FindingRepository

    t = two_tenants
    db = t["db"]
    eng_a = EngagementRepository(db, tenant_ids={t["a"]})
    assert _hidden(lambda: eng_a.get_raw(t["eb"]))
    assert _hidden(lambda: eng_a.replace(t["eb"], {"tenant_id": t["b"], "name": "pwn"}))
    assert _hidden(lambda: eng_a.delete(t["eb"]))
    assert db["engagements"].find_one({"_id": t["eb"]})["name"] == "eng-b"
    # Own tenant still works.
    assert eng_a.get_raw(t["ea"])["name"] == "eng-a"
    # Child docs resolve tenant via engagement_id.
    fin_a = FindingRepository(db, tenant_ids={t["a"]})
    assert _hidden(lambda: fin_a.get_raw(t["fb"]))
    assert _hidden(lambda: fin_a.delete(t["fb"]))
    assert db["findings"].count_documents({"_id": t["fb"]}) == 1


def test_replace_cannot_move_doc_into_foreign_tenant(two_tenants):
    from attestra.persistence.mongo.repositories.core import EngagementRepository
    from attestra.persistence.mongo.tenant import TenantAccessDenied

    t = two_tenants
    eng_a = EngagementRepository(t["db"], tenant_ids={t["a"]})
    with pytest.raises(TenantAccessDenied):
        eng_a.replace(t["ea"], {"tenant_id": t["b"], "name": "moved"})
    assert t["db"]["engagements"].find_one({"_id": t["ea"]})["tenant_id"] == t["a"]


def test_insert_with_id_rejects_foreign_tenant(two_tenants):
    from attestra.persistence.mongo.repositories.core import EngagementRepository, FindingRepository
    from attestra.persistence.mongo.tenant import TenantAccessDenied

    t = two_tenants
    with pytest.raises(TenantAccessDenied):
        EngagementRepository(t["db"], tenant_ids={t["a"]}).insert_with_id({"tenant_id": t["b"], "name": "x"})
    with pytest.raises(TenantAccessDenied):
        FindingRepository(t["db"], tenant_ids={t["a"]}).insert_with_id({"engagement_id": t["eb"], "title": "x"})


def test_apikey_revoke_and_create_scoped(two_tenants):
    from attestra.persistence.mongo.repositories.core import ApiKeyRepository
    from attestra.persistence.mongo.tenant import TenantAccessDenied

    t = two_tenants
    db = t["db"]
    assert _hidden(lambda: ApiKeyRepository(db, tenant_ids={t["a"]}).revoke(t["kb"]))
    assert db["api_keys"].find_one({"_id": t["kb"]})["revoked_at"] is None
    with pytest.raises(TenantAccessDenied):
        ApiKeyRepository(db, tenant_ids={t["a"]}).create(t["ub"], "hash-x", "pfx-x")
    with pytest.raises(TenantAccessDenied):  # no keys for global/admin users from a scoped caller
        ApiKeyRepository(db, tenant_ids={t["a"]}).create(t["admin"], "hash-y", "pfx-y")
    assert ApiKeyRepository(db, tenant_ids={t["a"]}).create(t["ua"], "hash-z", "pfx-z")["user_id"] == t["ua"]
    assert ApiKeyRepository(db, tenant_ids={t["b"]}).revoke(t["kb"])["revoked_at"] is not None


def test_tenant_and_user_creation_scoped(two_tenants):
    from attestra.persistence.mongo.repositories.core import TenantRepository, UserRepository
    from attestra.persistence.mongo.tenant import TenantAccessDenied

    t = two_tenants
    db = t["db"]
    with pytest.raises(TenantAccessDenied):
        TenantRepository(db, tenant_ids={t["a"]}).create("rogue")
    with pytest.raises(TenantAccessDenied):
        UserRepository(db, tenant_ids={t["a"]}).create("rogue-global")
    with pytest.raises(TenantAccessDenied):
        UserRepository(db, tenant_ids={t["a"]}).create("rogue-b", tenant_id=t["b"])
    assert UserRepository(db, tenant_ids={t["a"]}).create("ok-a", tenant_id=t["a"])["tenant_id"] == t["a"]


def test_list_queries_are_scoped(two_tenants):
    from attestra.persistence.mongo.repositories.core import (
        EngagementRepository,
        FindingRepository,
        TenantRepository,
    )

    t = two_tenants
    db = t["db"]
    assert [e["id"] for e in EngagementRepository(db, tenant_ids={t["a"]}).list()] == [t["ea"]]
    assert [x["id"] for x in TenantRepository(db, tenant_ids={t["a"]}).list()] == [t["a"]]
    assert FindingRepository(db, tenant_ids={t["a"]}).list_scoped() == []
    assert EngagementRepository(db, tenant_ids=frozenset()).list() == []
    assert _hidden(lambda: FindingRepository(db, tenant_ids={t["a"]}).list_for_engagement(t["eb"]))


def test_report_get_cross_tenant(two_tenants):
    from attestra.persistence.mongo.repositories.reports import ReportRepository

    t = two_tenants
    db = t["db"]
    rb = ReportRepository(db).create(t["eb"], "technical", path="mongo://r.pdf", sha256="0" * 64)
    assert _hidden(lambda: ReportRepository(db, tenant_ids={t["a"]}).get(rb["id"]))
    with pytest.raises(LookupError):
        ReportRepository(db, tenant_ids={t["a"]}).transition(rb["id"], "submitted", actor="a")
    assert db["reports"].find_one({"_id": rb["id"]})["status"] == "draft"
