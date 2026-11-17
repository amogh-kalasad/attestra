"""C-05 GraphQL detection / bounded introspection / two-identity field check (mock only)."""

from __future__ import annotations

import pytest

from attestra.automated_vapt.testing import graphql_tests as gq
from tests.automated_vapt.fixtures.probes.helpers import BASE, ctx, probe_client, seen, waf_client


@pytest.fixture(autouse=True)
def _flags(monkeypatch):
    monkeypatch.setenv("ATTESTRA_GRAPHQL_PROBE", "1")
    monkeypatch.setenv("ATTESTRA_PROBE_DELAY_MS", "0")


def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv("ATTESTRA_GRAPHQL_PROBE", raising=False)
    c = probe_client()
    assert gq.run(c, BASE, ctx=ctx())["skip_reason"] == "disabled_by_flag"
    assert seen(c) == []


def test_introspection_enabled_reported_low_and_no_mutation_sent():
    c = probe_client()
    out = gq.run(c, BASE, ctx=ctx(auth=True))
    assert out["finding_candidate"] is True
    assert out["observations"]["introspection"]["enabled"] is True
    assert out["observations"]["introspection"]["has_mutations"] is True
    sent = seen(c)
    assert all("mutation" not in s["query"].lower().replace("mutationtype", "") for s in sent)
    assert {s["method"] for s in sent} == {"GET"}
    assert len(sent) <= gq.META.request_budget


def test_introspection_disabled_is_not_a_vulnerability():
    out = gq.run(probe_client(graphql_introspection=False), BASE, ctx=ctx(auth=True, second=True))
    assert out["finding_candidate"] is False
    assert out["observations"]["field_authz"]["status"] == "NOT_TESTED"


def test_missing_second_identity_is_not_tested_never_pass():
    out = gq.run(probe_client(), BASE, ctx=ctx(auth=True))
    assert out["observations"]["field_authz"] == {"status": "NOT_TESTED", "reason": "no_second_role"}


def test_two_identity_field_comparison():
    broken = gq.run(probe_client(field_authz_broken=True), BASE, ctx=ctx(auth=True, second=True))
    assert broken["observations"]["field_authz"]["suspected"] == ["adminUsers"]
    ok = gq.run(probe_client(field_authz_broken=False), BASE, ctx=ctx(auth=True, second=True))
    assert ok["observations"]["field_authz"]["suspected"] == []


def test_mutation_guard_and_depth_limit():
    with pytest.raises(gq.UnsafeGraphQLQuery):
        gq.assert_read_only("mutation { deleteUser }")
    with pytest.raises(gq.UnsafeGraphQLQuery):
        gq.assert_read_only("subscription { x }")
    with pytest.raises(gq.UnsafeGraphQLQuery):
        gq.assert_read_only("{" * 9 + "}" * 9)
    assert gq.query_depth(gq.INTROSPECTION_QUERY) <= gq.MAX_DEPTH
    gq.assert_read_only(gq.INTROSPECTION_QUERY)


def test_response_cap_512kb():
    out = gq.run(probe_client(), BASE, ctx=ctx(), candidates=["http://testserver/huge-graphql"])
    intro = out["observations"]["introspection"]
    assert intro["truncated"] is True and intro["enabled"] is False


def test_waf_blocked():
    out = gq.run(waf_client(), BASE, ctx=ctx())
    assert out["status_hint"] == "BLOCKED"
