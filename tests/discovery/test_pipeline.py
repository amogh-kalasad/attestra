"""A-01: passive discovery pipeline and tenant-scoped candidate store (fixtures only)."""
# @lat: [[attack-surface-and-platform#Passive discovery]]

from __future__ import annotations

import random
from types import SimpleNamespace

import pytest

from attestra.discovery import DiscoveryDisabled, discovery_enabled, pipeline
from attestra.discovery import candidates as dc
from attestra.discovery.candidates import Observation
from attestra.discovery.normalize import candidate_key, host_denied, normalize_hostname
from attestra.persistence.mongo import tenant as T
from tests.discovery._fakedb import FakeDB

SCOPE = ["example.com", "www.example.com"]


def obs(name, source, seen="2026-11-10", **detail):
    return Observation(name=name, source=source, seen_at=seen, detail=detail)


@pytest.fixture
def enabled(monkeypatch):
    from attestra import config

    monkeypatch.setattr(config, "DISCOVERY_ENABLED", True, raising=False)


def test_flag_off_by_default(monkeypatch):
    from attestra import config

    monkeypatch.setattr(config, "DISCOVERY_ENABLED", None, raising=False)
    monkeypatch.delenv("ATTESTRA_DISCOVERY_ENABLED", raising=False)
    assert discovery_enabled() is False
    with pytest.raises(DiscoveryDisabled):
        pipeline.run_passive_discovery(apex="example.com", allowed_hosts=SCOPE, sources={})


@pytest.mark.parametrize(
    "raw,want",
    [
        ("WWW.Example.COM.", "www.example.com"),
        ("*.dev.example.com", "dev.example.com"),
        ("https://shop.example.com:8443/path", "shop.example.com"),
        ("bücher.example.com", "xn--bcher-kva.example.com"),
        ("10.0.0.1", None),
        ("a b.example.com", None),
        ("foo.*.example.com", None),
        ("-bad.example.com", None),
        ("_dmarc.example.com", None),
        ("localhost", None),
        ("", None),
    ],
)
def test_normalize_hostname(raw, want):
    assert normalize_hostname(raw) == want


def test_deny_rules():
    assert host_denied("admin.example.com", ["admin.example.com"])
    assert host_denied("x.corp.example.com", ["*.corp.example.com"])
    assert not host_denied("corp.example.com", ["*.corp.example.com"])


def test_dedup_is_deterministic_regardless_of_order():
    rows = [
        obs("www.example.com", "ct", "2026-11-01", issuer="R3"),
        obs("WWW.example.com.", "subfinder", "2026-11-05", via="crtsh"),
        obs("api.example.com", "subfinder", "2026-11-02"),
        obs("api.example.com", "dnsx", "2026-11-03", a=["192.0.2.10"], status="NOERROR"),
        obs("www.example.com", "ct", "2026-10-30", issuer="E1"),
    ]
    results = []
    for seed in range(5):
        shuffled = rows[:]
        random.Random(seed).shuffle(shuffled)
        res = pipeline.merge_observations(shuffled, apex="example.com", allowed_hosts=SCOPE)
        results.append([c.as_dict() for c in res.candidates])
    assert all(r == results[0] for r in results)
    names = [c["name"] for c in results[0]]
    assert names == ["api.example.com", "www.example.com"]


def test_provenance_and_confidence():
    res = pipeline.merge_observations(
        [
            obs("www.example.com", "ct", "2026-11-01", issuer="R3"),
            obs("www.example.com", "subfinder", "2026-11-05"),
            obs("solo.example.com", "httpx", "2026-11-06", status_code=200),
            obs("api.example.com", "dnsx", "2026-11-03", a=["192.0.2.10"]),
        ],
        apex="example.com",
        allowed_hosts=SCOPE,
    )
    by = {c.name: c for c in res.candidates}
    www = by["www.example.com"]
    assert www.sources == ("ct", "subfinder")
    assert www.first_seen == "2026-11-01" and www.last_seen == "2026-11-05"
    assert {p["source"] for p in www.provenance} == {"ct", "subfinder"}
    assert www.confidence > by["solo.example.com"].confidence
    assert by["api.example.com"].resolution == "resolved"
    assert by["api.example.com"].addresses == ("192.0.2.10",)
    assert all(c.status == "pending" and c.in_scope for c in res.candidates)


def test_confidence_scoring_rules():
    assert dc.score_confidence(["ct", "subfinder"], "resolved") > dc.score_confidence(["ct", "subfinder"])
    assert dc.score_confidence(["ct"], "nxdomain") < dc.score_confidence(["ct"])
    assert dc.score_confidence(["ct", "subfinder", "dnsx"], "wildcard") <= 0.3


def test_out_of_scope_excluded_and_counted():
    res = pipeline.merge_observations(
        [
            obs("www.example.com", "ct"),
            obs("evil.com", "ct"),
            obs("example.com.evil.net", "subfinder"),
            obs("admin.example.com", "ct"),
            obs("not a host", "ct"),
        ],
        apex="example.com",
        allowed_hosts=SCOPE,
        deny_hosts=["admin.example.com"],
    )
    assert [c.name for c in res.candidates] == ["www.example.com"]
    assert res.excluded_out_of_scope == 3
    assert res.excluded_invalid == 1


def test_apex_must_be_in_signed_scope():
    with pytest.raises(ValueError):
        pipeline.merge_observations([obs("a.other.com", "ct")], apex="other.com", allowed_hosts=SCOPE)


def test_run_records_source_errors_and_never_adds_assets(enabled, monkeypatch):
    import attestra.services as services

    def boom(*a, **k):  # any asset creation during discovery is a bug
        raise AssertionError("discovery must never add assets")

    monkeypatch.setattr(services, "add_asset", boom)

    def broken(apex):
        raise RuntimeError("aggregator down")

    res = pipeline.run_passive_discovery(
        apex="example.com",
        allowed_hosts=SCOPE,
        sources={"ct": lambda apex: [obs("www.example.com", "ct")], "subfinder": broken},
    )
    assert [c.name for c in res.candidates] == ["www.example.com"]
    assert "subfinder" in res.errors
    assert all(not dc.is_scannable(c.as_dict()) for c in res.candidates)


def test_observations_from_ct():
    sug = [SimpleNamespace(name="www.example.com", first_seen="2026-01-01", issuer="R3"), {"name": "api.example.com"}]
    out = pipeline.observations_from_ct(sug)
    assert [o.name for o in out] == ["www.example.com", "api.example.com"]
    assert out[0].detail["issuer"] == "R3"


# ---------------------------------------------------------------- store


def _cands(*names):
    return pipeline.merge_observations([obs(n, "ct") for n in names], apex="example.com", allowed_hosts=SCOPE).candidates


def test_upsert_idempotent_and_keys_stable():
    db = FakeDB()
    assert dc.upsert_candidates(db, tenant_id=1, engagement_id=7, candidates=_cands("a.example.com"), actor="t") == {
        "created": 1,
        "updated": 0,
    }
    again = dc.upsert_candidates(db, tenant_id=1, engagement_id=7, candidates=_cands("a.example.com"), actor="t")
    assert again == {"created": 0, "updated": 1}
    assert len(db[dc.COLLECTION].docs) == 1
    assert candidate_key(1, 7, "A.example.com.") == candidate_key(1, 7, "a.example.com")


def test_upsert_merges_provenance_and_keeps_review_state():
    db = FakeDB()
    dc.upsert_candidates(db, tenant_id=1, engagement_id=7, candidates=_cands("a.example.com"), actor="t")
    cid = candidate_key(1, 7, "a.example.com")
    dc.set_review(db, cid, tenant_ids=frozenset({1}), engagement_id=7, status="rejected", actor="lead")
    more = pipeline.merge_observations(
        [obs("a.example.com", "subfinder", "2026-11-12")], apex="example.com", allowed_hosts=SCOPE
    ).candidates
    dc.upsert_candidates(db, tenant_id=1, engagement_id=7, candidates=more, actor="t")
    doc = db[dc.COLLECTION].find_one({"_id": cid})
    assert doc["status"] == "rejected"
    assert doc["sources"] == ["ct", "subfinder"]
    assert len(doc["provenance"]) == 2


def test_store_tenant_isolation_and_strict(monkeypatch):
    db = FakeDB()
    dc.upsert_candidates(db, tenant_id=1, engagement_id=7, candidates=_cands("a.example.com"), actor="t")
    dc.upsert_candidates(db, tenant_id=2, engagement_id=8, candidates=_cands("b.example.com"), actor="t")
    assert [c["name"] for c in dc.list_candidates(db, tenant_ids=frozenset({1}), engagement_id=7)] == ["a.example.com"]
    assert dc.list_candidates(db, tenant_ids=frozenset({1}), engagement_id=8) == []
    with pytest.raises(T.TenantAccessDenied):
        dc.get_candidate(db, candidate_key(2, 8, "b.example.com"), tenant_ids=frozenset({1}))
    with pytest.raises(T.TenantAccessDenied):
        dc.upsert_candidates(db, tenant_id=2, engagement_id=8, candidates=_cands("c.example.com"), actor="t", tenant_ids=frozenset({1}))
    monkeypatch.setattr(T, "strict_enabled", lambda: True)
    assert dc.list_candidates(db, tenant_ids=None, engagement_id=7) == []
    assert len(dc.list_candidates(db, tenant_ids=T.SYSTEM_SCOPE, engagement_id=7)) == 1


def test_review_transitions():
    db = FakeDB()
    dc.upsert_candidates(db, tenant_id=1, engagement_id=7, candidates=_cands("a.example.com", "b.example.com"), actor="t")
    a, b = candidate_key(1, 7, "a.example.com"), candidate_key(1, 7, "b.example.com")
    with pytest.raises(dc.CandidateError):
        dc.set_review(db, a, tenant_ids=frozenset({1}), engagement_id=7, status="approved", actor="lead")  # no asset id
    out = dc.set_review(db, a, tenant_ids=frozenset({1}), engagement_id=7, status="approved", actor="lead", asset_id=42)
    assert out["status"] == "approved" and out["asset_id"] == 42 and out["review"]["by"] == "lead"
    assert out["scannable"] is False  # the Asset is the scan target, never the candidate
    with pytest.raises(dc.CandidateError):
        dc.set_review(db, a, tenant_ids=frozenset({1}), engagement_id=7, status="rejected", actor="lead")
    with pytest.raises(LookupError):
        dc.set_review(db, b, tenant_ids=frozenset({1}), engagement_id=999, status="rejected", actor="lead")
    with pytest.raises(dc.CandidateError):
        dc.set_review(db, b, tenant_ids=frozenset({1}), engagement_id=7, status="pending", actor="lead")


def test_out_of_scope_candidate_never_stored():
    db = FakeDB()
    c = _cands("a.example.com")[0]
    c.in_scope = False
    assert dc.upsert_candidates(db, tenant_id=1, engagement_id=7, candidates=[c], actor="t") == {"created": 0, "updated": 0}


def test_ct_suggestions_record_candidates_with_fake_db():
    from attestra.runner.authorization import AuthorizedScope
    from attestra.runner.ct_suggestions import CtSuggestion, record_ct_candidates

    scope = AuthorizedScope(
        name="t", allowed_hosts=frozenset({"example.com"}), allowed_urls=(), allowed_paths=(), allowed_images=(),
        deny_hosts=("secret.example.com",),
    )
    db = FakeDB()
    out = record_ct_candidates(
        db, tenant_id=3, engagement_id=9, apex="example.com", actor="lead",
        suggestions=[CtSuggestion("www.example.com", "2026-01-01", "R3"), CtSuggestion("secret.example.com", "", "")],
        scope=scope,
    )
    assert out["created"] == 1 and out["excluded_out_of_scope"] == 1
    doc = db[dc.COLLECTION].find_one({"name": "www.example.com"})
    assert doc["tenant_id"] == 3 and doc["status"] == "pending" and doc["sources"] == ["ct"]
