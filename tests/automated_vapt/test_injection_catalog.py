"""B-05 injection catalogue: completeness, safety tiers and distinct outcomes."""

from __future__ import annotations

from fastapi.testclient import TestClient

from attestra.automated_vapt.testing import injection_catalog as cat
from attestra.automated_vapt.testing import injection_tests
from tests.automated_vapt.fixtures.probes.helpers import BASE, probe_client, waf_client


def test_catalog_is_valid_and_non_destructive():
    assert cat.validate_catalog() == []
    for c in cat.CHECKS:
        assert c.tier in cat.TIERS and c.payload_class and c.location in cat.LOCATIONS


def test_validator_rejects_destructive_and_time_based_payloads():
    bad = cat.InjectionCheck("X1", "INJ", "sql", "query", "T1", "WSTG-INPV-05", "bad", ("1; DROP TABLE users",))
    slow = cat.InjectionCheck("X2", "INJ", "sql", "query", "T1", "WSTG-INPV-05", "bad", ("1' AND SLEEP(5)--",))
    meta = cat.InjectionCheck("X3", "INJ", "ssrf", "query", "T1", "WSTG-INPV-19", "bad", ("http://169.254.169.254/",))
    probs = cat.validate_catalog([bad, slow, meta, bad])
    assert any("forbidden" in p for p in probs) and any("duplicate" in p for p in probs)
    assert sum("forbidden" in p for p in probs) >= 3


def test_every_inj_payload_sent_is_declared():
    declared = {p for c in cat.checks(test_id="INJ") for p in c.payloads}
    for bp in injection_tests._BOOLEAN_PAYLOADS[:2]:
        assert bp in declared


def test_outcomes_distinct():
    assert cat.classify_outcome("waf_block", reflected_unencoded=True, error_signature=False, marker_present_encoded=False) == "blocked"
    assert cat.classify_outcome("challenge", reflected_unencoded=False, error_signature=False, marker_present_encoded=False) == "blocked"
    assert cat.classify_outcome("network_failed", reflected_unencoded=False, error_signature=False, marker_present_encoded=False) == "inconclusive"
    assert cat.classify_outcome("app_ok", reflected_unencoded=False, error_signature=False, marker_present_encoded=True) == "filtered"
    assert cat.classify_outcome("app_ok", reflected_unencoded=True, error_signature=False, marker_present_encoded=False) == "reflected"
    assert cat.classify_outcome("app_ok", reflected_unencoded=False, error_signature=False, marker_present_encoded=False) == "not_reflected"


def test_inj_rows_carry_class_location_tier_and_samples():
    c = probe_client(vulnerable=True)
    out = injection_tests.run(c, BASE, probes=[("/search", "q")], boolean_canaries=False)
    row = out["observations"]["probes"][0]
    assert row["payload_class"] == "reflection_canary" and row["location"] == "query" and row["tier"] == "T1"
    assert row["outcome"] == "reflected"
    assert out["finding_candidate"] is True
    assert out["validity_samples"]
    assert out["observations"]["catalog_version"] == cat.CATALOG_VERSION


def test_inj_filtered_on_encoding_app():
    out = injection_tests.run(probe_client(vulnerable=False), BASE, probes=[("/echo-encoded", "q")], boolean_canaries=False)
    assert out["observations"]["probes"][0]["outcome"] == "filtered"
    assert out["finding_candidate"] is False


def test_inj_blocked_by_waf_is_not_a_pass():
    c: TestClient = waf_client()
    out = injection_tests.run(c, BASE, probes=[("/search", "q"), ("/", "q")])
    assert out["status_hint"] == "BLOCKED"
    assert {r["outcome"] for r in out["observations"]["probes"]} == {"blocked"}
    assert all("boolean_payload" not in r for r in out["observations"]["probes"])


def test_inj_module_dict_is_json_serialisable_like_the_orchestrator_persists_it():
    """The orchestrator json.dumps every module key except evidence_pairs."""
    import json

    out = injection_tests.run(waf_client(), BASE, probes=[("/search", "q")])
    persisted = {k: v for k, v in out.items() if k != "evidence_pairs"}
    text = json.dumps(persisted, sort_keys=True)
    assert "validity_samples" in text
    s0 = out["validity_samples"][0]
    assert s0.cls in ("challenge", "waf_block") and isinstance(s0.reasons, tuple)
