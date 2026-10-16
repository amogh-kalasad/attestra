"""Detection gaps R17/R18: testssl weak signature hashes and OCSP stapling."""

from __future__ import annotations

from pathlib import Path

from attestra import importers
from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.testssl import TlsTestsslAdapter, _flags

FIX = Path(__file__).parent / "fixtures" / "testssl"
PIN = PinnedTarget(host="shop.example.com", ip="93.184.216.34", port=443, scheme="https")


def test_r17_sha224_signature_kept_at_info():
    out = importers.parse("testssl", (FIX / "gaps_r17_r18.json").read_bytes())
    r17 = [f for f in out if f.title == "TLS: weak signature or hash algorithm offered (SHA224/SHA1/MD5)"]
    assert len(r17) == 1
    f = r17[0]
    assert f.severity == "low"
    assert f.cwe == 327
    assert f.variant == "cert_signatureAlgorithm"
    assert f.rule_id == "cert_signatureAlgorithm"
    assert "SHA224" in f.description


def test_r18_absent_when_ocsp_url_empty():
    out = importers.parse("testssl", (FIX / "gaps_r17_r18.json").read_bytes())
    assert not any(f.title == "TLS: OCSP stapling not offered" for f in out)
    # INFO service row still skipped; only R17 keeper from this fixture.
    assert all(f.title.startswith("TLS: weak signature") for f in out)


def test_r18_present_when_ocsp_url_set():
    out = importers.parse("testssl", (FIX / "gaps_r18_ocsp.json").read_bytes())
    r18 = [f for f in out if f.title == "TLS: OCSP stapling not offered"]
    assert len(r18) == 1
    f = r18[0]
    assert f.severity == "info"
    assert f.cwe == 299
    assert f.variant == "OCSP_stapling"
    assert f.rule_id == "OCSP_stapling"


def test_baseline_flags_exclude_vulnerable():
    flags = _flags(PIN, "/tmp/out.json", profile="baseline")
    assert "-U" not in flags
    assert "--vulnerable" not in flags
    assert "--vulnerabilities" not in flags
    for opt in ("-p", "-S", "-P", "-f", "-H"):
        assert opt in flags
    argv = TlsTestsslAdapter().build_argv(PIN, out_file=Path("/tmp/out.json"), profile="baseline")
    assert "-U" not in argv
    assert "--vulnerable" not in argv
