"""Phase 0: lock import-time noise / contradiction classification (attestra/finding_validation/classify.py).

Pure function tests with string fixtures; no network, no Mongo.
"""

from __future__ import annotations

from types import SimpleNamespace

from attestra.finding_validation.classify import (
    apply_classification_to_finding,
    classify_observation,
    elite_status_to_validation,
    should_create_elite_finding,
)
from attestra.finding_validation.statuses import (
    CONFIRMED,
    FALSE_POSITIVE,
    INFORMATIONAL,
    NEEDS_MANUAL_VALIDATION,
    NOT_REPRODUCIBLE,
    POTENTIAL,
    UNVALIDATED,
)
from attestra.importers.zap import _force_informational_severity

_HSTS_EVIDENCE = (
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n"
)
_CHALLENGE_URL = "https://app.example.com/cdn-cgi/challenge-platform/h/b/scripts/jsd/abc/main.js"


# --- ZAP notices -----------------------------------------------------------------


# @lat: [[tests#test_finding_validation_classify.py#ZAP notices are informational]]
def test_zap_10109_rule_id_is_informational():
    res = classify_observation(title="Some ZAP alert", rule_ids=["10109"], severity="medium")
    assert res["validation_status"] == INFORMATIONAL
    assert res["severity"] == "info"
    assert any("scanner notice" in r.lower() for r in res["reasons"])


def test_zap_10112_and_modern_web_app_title_are_informational():
    assert classify_observation(title="x", rule_ids=["10112"])["validation_status"] == INFORMATIONAL
    res = classify_observation(title="Modern Web Application", severity="medium")
    assert res["validation_status"] == INFORMATIONAL
    res = classify_observation(title="Session Management Response Identified")
    assert res["validation_status"] == INFORMATIONAL


# --- CDN / challenge / static noise ----------------------------------------------


# @lat: [[tests#test_finding_validation_classify.py#Cloudflare challenge and cookie noise]]
def test_cf_clearance_cookie_samesite_is_informational():
    res = classify_observation(
        title="Cookie without SameSite Attribute",
        param="cf_clearance",
        location="https://app.example.com/",
        severity="low",
    )
    assert res["validation_status"] == INFORMATIONAL
    assert any("cf_clearance" in r for r in res["reasons"])


def test_cache_finding_on_challenge_platform_is_informational():
    res = classify_observation(
        title="Storable and Cacheable Content",
        rule_ids=["10049"],
        location=_CHALLENGE_URL,
        severity="info",
    )
    assert res["validation_status"] == INFORMATIONAL
    assert any("CDN/challenge" in r for r in res["reasons"])


def test_cache_finding_on_next_static_is_informational():
    res = classify_observation(
        title="Re-examine Cache-control Directives",
        rule_ids=["10015"],
        location="https://app.example.com/_next/static/chunks/main-abc123.js",
    )
    assert res["validation_status"] == INFORMATIONAL
    assert any("static asset" in r for r in res["reasons"])


def test_cache_finding_on_application_page_stays_unvalidated():
    res = classify_observation(
        title="Re-examine Cache-control Directives",
        rule_ids=["10015"],
        location="https://app.example.com/account/settings",
    )
    assert res["validation_status"] == UNVALIDATED


def test_cors_on_challenge_url_is_informational():
    res = classify_observation(
        title="Cross-Domain Misconfiguration",
        location=_CHALLENGE_URL,
        evidence_texts=["Access-Control-Allow-Origin: *"],
    )
    assert res["validation_status"] == INFORMATIONAL


# --- Deprecated headers -----------------------------------------------------------


# @lat: [[tests#test_finding_validation_classify.py#Expect-CT and X-XSS-Protection are informational]]
def test_expect_ct_is_informational_with_misconfig_mapping():
    res = classify_observation(title="Expect-CT header not set", severity="medium", cwe=16)
    assert res["validation_status"] == INFORMATIONAL
    assert res["severity"] == "info"
    assert res["cwe"] == 693
    assert res["owasp_top10"].startswith("A05")
    assert res["clear_injection_mapping"] is True


def test_x_xss_protection_is_informational_not_xss():
    res = classify_observation(title="X-XSS-Protection header missing", rule_ids=["10016"])
    assert res["validation_status"] == INFORMATIONAL
    assert res["cwe"] == 693
    assert res["wstg_ref"] == "WSTG-CONF-12"


# --- Header-missing contradictions ------------------------------------------------


# @lat: [[tests#test_finding_validation_classify.py#HSTS contradiction and severity cap]]
def test_hsts_missing_contradicted_by_evidence_is_not_reproducible():
    res = classify_observation(
        title="Strict-Transport-Security Header Not Set",
        location="https://app.example.com/",
        evidence_texts=[_HSTS_EVIDENCE],
        severity="low",
    )
    assert res["validation_status"] == NOT_REPRODUCIBLE
    assert any("max-age" in r for r in res["reasons"])


def test_hsts_missing_without_poc_stays_unvalidated_capped_low():
    res = classify_observation(
        title="HSTS header missing on HTTPS",
        description="HTTPS response has no usable Strict-Transport-Security header.",
        location="https://app.example.com/",
        severity="medium",
    )
    assert res["validation_status"] == UNVALIDATED
    assert res["severity"] == "low"


def test_hsts_missing_with_https_redirect_evidence_is_informational():
    res = classify_observation(
        title="HSTS header missing",
        location="https://app.example.com/",
        evidence_texts=["HTTP/1.1 301 Moved Permanently\r\nLocation: https://app.example.com/\r\n"],
    )
    assert res["validation_status"] == INFORMATIONAL
    assert res["severity"] == "low"


def test_hsts_missing_with_ssl_strip_poc_is_not_capped():
    res = classify_observation(
        title="HSTS header missing",
        description="Confirmed sslstrip downgrade on captive portal.",
        location="https://app.example.com/",
        severity="medium",
    )
    assert res["validation_status"] == UNVALIDATED
    assert res["severity"] is None  # untouched


def test_hsts_claim_on_challenge_url_is_informational():
    res = classify_observation(title="HSTS header missing", location=_CHALLENGE_URL)
    assert res["validation_status"] == INFORMATIONAL


def test_permissions_policy_contradiction_is_not_reproducible():
    res = classify_observation(
        title="Permissions Policy Header Not Set",
        evidence_texts=["Permissions-Policy: camera=(), microphone=()"],
    )
    assert res["validation_status"] == NOT_REPRODUCIBLE


def test_clickjacking_contradiction_is_not_reproducible():
    res = classify_observation(
        title="Missing Anti-clickjacking Header",
        evidence_texts=["X-Frame-Options: SAMEORIGIN"],
    )
    assert res["validation_status"] == NOT_REPRODUCIBLE
    res = classify_observation(
        title="Missing Anti-clickjacking Header",
        evidence_texts=["Content-Security-Policy: frame-ancestors 'self'"],
    )
    assert res["validation_status"] == NOT_REPRODUCIBLE


# --- DNS / TLS honesty ------------------------------------------------------------


# @lat: [[tests#test_finding_validation_classify.py#DNS and cipher honesty]]
def test_spf_without_mx_and_dane_are_informational():
    assert classify_observation(title="DNS: no SPF record on host without MX")["validation_status"] == INFORMATIONAL
    assert classify_observation(title="DNS: no DANE (TLSA) record")["validation_status"] == INFORMATIONAL


def test_weak_cipher_without_suite_names_needs_manual_validation():
    res = classify_observation(title="Weak cipher suites supported", evidence_texts=["TLS 1.0 enabled"])
    assert res["validation_status"] == NEEDS_MANUAL_VALIDATION
    res = classify_observation(
        title="Weak cipher suites supported",
        evidence_texts=["TLS_RSA_WITH_3DES_EDE_CBC_SHA offered"],
    )
    assert res["validation_status"] == UNVALIDATED


def test_default_is_unvalidated():
    res = classify_observation(title="SQL Injection", location="https://app.example.com/search?q=1")
    assert res["validation_status"] == UNVALIDATED
    assert res["severity"] is None


# --- Apply + Elite mapping --------------------------------------------------------


# @lat: [[tests#test_finding_validation_classify.py#Applying a classification remaps injection fields]]
def test_apply_classification_remaps_injection_mapping():
    f = SimpleNamespace(
        validation_status=UNVALIDATED,
        validation_reasons=[],
        severity="medium",
        cwe=79,
        owasp_top10="A03:2021-Injection",
        asvs_ref="V5.3.3",
        wstg_ref="WSTG-INPV-01",
    )
    apply_classification_to_finding(f, classify_observation(title="X-XSS-Protection header missing"))
    assert f.validation_status == INFORMATIONAL
    assert f.severity == "info"
    assert f.cwe == 693
    assert f.owasp_top10.startswith("A05")
    assert f.asvs_ref == "V14.4.3"
    assert f.wstg_ref == "WSTG-CONF-12"
    assert f.validation_reasons


def test_apply_classification_leaves_untouched_fields():
    f = SimpleNamespace(validation_status=UNVALIDATED, validation_reasons=[], severity="high", cwe=89)
    apply_classification_to_finding(f, classify_observation(title="SQL Injection"))
    assert f.severity == "high" and f.cwe == 89
    assert f.validation_status == UNVALIDATED


def test_elite_status_mapping_and_create_gate():
    assert elite_status_to_validation("CONFIRMED") == CONFIRMED
    assert elite_status_to_validation("potential") == POTENTIAL
    assert elite_status_to_validation("NEEDS_MANUAL_REVIEW") == NEEDS_MANUAL_VALIDATION
    assert elite_status_to_validation("INCONCLUSIVE") == NEEDS_MANUAL_VALIDATION
    assert elite_status_to_validation("NOT_VULNERABLE") == FALSE_POSITIVE
    assert elite_status_to_validation("") == UNVALIDATED
    assert should_create_elite_finding({"status": "CONFIRMED"}, {"is_likely_fp": False})
    assert not should_create_elite_finding({"status": "CONFIRMED"}, {"is_likely_fp": True})
    assert not should_create_elite_finding({"status": "NOT_VULNERABLE"}, {})


# --- ZAP import-time severity cap -------------------------------------------------


# @lat: [[tests#test_finding_validation_classify.py#ZAP importer caps notice severity]]
def test_zap_importer_forces_info_for_notices_and_static_cache():
    kw = {"title": "Modern Web Application", "description": "", "location": "https://a.example.com/"}
    assert _force_informational_severity(pluginid="10109", severity="medium", **kw) == "info"
    assert _force_informational_severity(pluginid="10112-1", severity="low", **kw) == "info"
    cache = {"title": "Storable and Cacheable Content", "description": ""}
    assert (
        _force_informational_severity(
            pluginid="10049-1", severity="low", location="https://a.example.com/_next/static/x.js", **cache
        )
        == "info"
    )
    assert (
        _force_informational_severity(pluginid="10049", severity="low", location=_CHALLENGE_URL, **cache)
        == "info"
    )
    # Cache alert on an application page keeps the scanner severity.
    assert (
        _force_informational_severity(
            pluginid="10049", severity="low", location="https://a.example.com/account", **cache
        )
        == "low"
    )
    assert _force_informational_severity(pluginid="40012", severity="high", **kw) == "high"
