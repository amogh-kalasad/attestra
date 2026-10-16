"""Unit tests for [[attestra/runner/scanners/webcheck_dns.py#dns_checks]].

Fake resolver interface (inject via ``resolver=``):

* **dict**: maps ``(name, rdtype)`` → ``list[str]`` where ``rdtype`` is
  ``"CAA"``, ``"AAAA"``, ``"MX"``, ``"TXT"``, or ``"TLSA"``. Missing key or
  ``[]`` means no records. Names are matched case-insensitively after
  stripping a trailing dot.
* **object** with ``resolve(name, rdtype) -> list[str]`` (exceptions → no records).
* **callable** ``(name, rdtype) -> list[str]``.

Never asserts against live DNS.
"""

from __future__ import annotations

import importlib.util

from attestra.runner.scanners.webcheck_dns import VERIFY_PREFIX, dns_checks


def _ids(findings: list[dict]) -> set[str]:
    return {f["id"] for f in findings}


def test_caa_on_parent_suppresses_dns_caa():
    """CAA on a parent means the host is covered; no dns-caa finding."""
    table = {
        ("example.com", "CAA"): ["0 issue letsencrypt.org"],
        ("www.example.com", "AAAA"): ["2001:db8::1"],
        ("www.example.com", "MX"): ["10 mail.example.com"],
        ("www.example.com", "TXT"): ["v=spf1 -all"],
        ("_443._tcp.www.example.com", "TLSA"): ["3 1 1 aabb"],
    }
    findings = dns_checks("www.example.com", resolver=table)
    assert "dns-caa" not in _ids(findings)
    assert findings == []


def test_caa_on_host_suppresses_dns_caa():
    table = {
        ("a.b.example.com", "CAA"): ["0 issueletsencrypt.org;"],
        ("a.b.example.com", "AAAA"): ["2001:db8::2"],
        ("a.b.example.com", "MX"): ["10 mail.example.com"],
        ("a.b.example.com", "TXT"): ["v=spf1 -all"],
        ("_443._tcp.a.b.example.com", "TLSA"): ["3 1 1 ccdd"],
    }
    assert "dns-caa" not in _ids(dns_checks("a.b.example.com", resolver=table))


def test_empty_resolver_emits_all_applicable_findings():
    """Nothing anywhere → CAA, AAAA, SPF (no MX), and TLSA findings."""
    findings = dns_checks("shop.example.com", resolver={})
    assert _ids(findings) == {"dns-caa", "dns-aaaa", "dns-spf", "dns-tlsa"}
    by = {f["id"]: f for f in findings}
    assert by["dns-caa"]["severity"] == "low"
    assert by["dns-caa"]["cwe"] == 16
    assert by["dns-aaaa"]["severity"] == "info"
    assert by["dns-spf"]["severity"] == "info"
    assert by["dns-tlsa"]["severity"] == "info"
    for f in findings:
        assert f["location"] == "shop.example.com"
        assert "id" in f and "title" in f and "description" in f


def test_spf_finding_when_no_mx_and_no_spf_txt():
    table = {
        ("mailess.example.com", "AAAA"): ["2001:db8::3"],
        ("mailess.example.com", "CAA"): ["0 issue ;"],
        ("_443._tcp.mailess.example.com", "TLSA"): ["3 1 1 ee"],
        # TXT present but not SPF (and not leaked in description)
        ("mailess.example.com", "TXT"): [f"{VERIFY_PREFIX}secret-token-value"],
    }
    findings = dns_checks("mailess.example.com", resolver=table)
    assert "dns-spf" in _ids(findings)
    # ownership verify TXT payload must never appear in findings
    blob = " ".join(str(v) for f in findings for v in f.values())
    assert "secret-token-value" not in blob
    assert f"{VERIFY_PREFIX}secret-token-value" not in blob


def test_spf_suppressed_when_mx_present():
    table = {
        ("mx.example.com", "MX"): ["10 mail.example.com"],
        ("mx.example.com", "CAA"): ["0 issue ;"],
        ("mx.example.com", "AAAA"): ["2001:db8::4"],
        ("_443._tcp.mx.example.com", "TLSA"): ["3 1 1 ff"],
    }
    assert "dns-spf" not in _ids(dns_checks("mx.example.com", resolver=table))


def test_spf_suppressed_when_spf_txt_present():
    table = {
        ("spf.example.com", "TXT"): ["v=spf1 include:_spf.example.com -all"],
        ("spf.example.com", "CAA"): ["0 issue ;"],
        ("spf.example.com", "AAAA"): ["2001:db8::5"],
        ("_443._tcp.spf.example.com", "TLSA"): ["3 1 1 00"],
    }
    assert "dns-spf" not in _ids(dns_checks("spf.example.com", resolver=table))


def test_aaaa_and_tlsa_independent():
    table = {
        ("dual.example.com", "CAA"): ["0 issue ;"],
        ("dual.example.com", "MX"): ["10 mail.example.com"],
        ("dual.example.com", "TXT"): ["v=spf1 -all"],
        # no AAAA, no TLSA
    }
    ids = _ids(dns_checks("dual.example.com", resolver=table))
    assert ids == {"dns-aaaa", "dns-tlsa"}


def test_callable_resolver():
    def resolve(name: str, rdtype: str) -> list[str]:
        if name == "call.example.com" and rdtype == "CAA":
            return ["0 issue ;"]
        if name == "call.example.com" and rdtype == "AAAA":
            return ["2001:db8::6"]
        if name == "call.example.com" and rdtype == "MX":
            return ["10 mail.example.com"]
        if name == "_443._tcp.call.example.com" and rdtype == "TLSA":
            return ["3 1 1 aa"]
        return []

    assert dns_checks("call.example.com", resolver=resolve) == []


def test_object_resolver():
    class Fake:
        def resolve(self, name: str, rdtype: str) -> list[str]:
            return []

    assert _ids(dns_checks("obj.example.com", resolver=Fake())) == {
        "dns-caa",
        "dns-aaaa",
        "dns-spf",
        "dns-tlsa",
    }


def test_skipped_note_when_dnspython_missing_and_no_resolver():
    """Without an injected resolver, missing dnspython yields a skipped note (no crash)."""
    if importlib.util.find_spec("dns") is not None:
        # Environment has dnspython; skip-path is still covered by forcing ImportError via unit of _default_resolve.
        from attestra.runner.scanners import webcheck_dns as mod

        original = mod._default_resolve
        mod._default_resolve = lambda: None  # type: ignore[assignment]
        try:
            findings = dns_checks("skip.example.com", resolver=None)
        finally:
            mod._default_resolve = original
    else:
        findings = dns_checks("skip.example.com", resolver=None)

    assert len(findings) == 1
    note = findings[0]
    assert note["id"] == "dns-skipped"
    assert note.get("skipped") is True
    assert "dnspython" in note["description"].lower()
    assert note["location"] == "skip.example.com"
