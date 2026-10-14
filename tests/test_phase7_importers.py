"""Phase 7.3 importers: Prowler, kube-bench, testssl.sh, Gitleaks, Checkov, naabu."""
from __future__ import annotations

from pathlib import Path

import pytest

from attestra import importers

FIX = Path(__file__).parent / "fixtures"


def _load(tool: str, name: str):
    return importers.parse(tool, (FIX / tool / name).read_bytes())


def test_registry_has_phase7_tools():
    for tool in ("prowler", "kube_bench", "testssl", "gitleaks", "checkov", "naabu"):
        assert tool in importers.PARSERS


def test_prowler_ocsf_only_failures():
    out = _load("prowler", "prowler.ocsf.json")
    assert len(out) == 1
    f = out[0]
    assert f.tool == "prowler" and f.severity == "high"
    assert f.location == "arn:aws:s3:::shop-logs"
    assert f.rule_id == "s3_bucket_public_access"
    assert "Block Public Access" in f.recommendation


def test_prowler_legacy_json():
    out = _load("prowler", "prowler_v3.json")
    assert [f.rule_id for f in out] == ["iam_password_policy_minimum_length_14"]
    assert out[0].severity == "medium"


def test_kube_bench_fail_and_warn():
    out = _load("kube_bench", "kube_bench.json")
    by = {f.param: f for f in out}
    assert set(by) == {"4.2.1", "4.2.9"}
    assert by["4.2.1"].severity == "medium"
    assert by["4.2.9"].severity == "low"
    assert by["4.2.1"].location == "k8s:node"


def test_testssl_skips_ok_and_info():
    out = _load("testssl", "testssl.json")
    by = {f.rule_id: f for f in out}
    assert set(by) == {"TLS1", "BEAST"}
    assert by["BEAST"].cves == ["CVE-2011-3389"]
    assert by["BEAST"].location == "shop.example.com:443"
    assert by["TLS1"].cwe == 327


def test_testssl_pretty_format():
    raw = b'{"scanResult":[{"targetHost":"shop.example.com","ip":"93.184.216.34","port":"443",' \
          b'"protocols":[{"id":"TLS1_1","severity":"LOW","finding":"offered"}]}]}'
    out = importers.parse("testssl", raw)
    assert len(out) == 1 and out[0].location == "shop.example.com:443"


def test_gitleaks_never_keeps_secret():
    out = _load("gitleaks", "gitleaks.json")
    assert len(out) == 1
    f = out[0]
    assert f.cwe == 798 and f.severity == "high"
    assert f.location == "services/payments/config.py:12"
    blob = repr(f)
    assert "AKIAIOSFODNN7EXAMPLE" not in blob


def test_checkov_failed_checks():
    out = _load("checkov", "checkov.json")
    assert [f.rule_id for f in out] == ["CKV_AWS_20", "CKV_AWS_18"]
    assert out[0].severity == "high" and out[1].severity == "medium"
    assert out[0].location == "infra/s3.tf:3"


def test_naabu_jsonl_open_ports():
    out = _load("naabu", "naabu.jsonl")
    assert sorted(f.location for f in out) == ["shop.example.com:22", "shop.example.com:443"]
    assert all(f.severity == "info" for f in out)


@pytest.mark.parametrize("tool", ["prowler", "kube_bench", "testssl", "gitleaks", "checkov", "naabu"])
def test_empty_input(tool):
    assert importers.parse(tool, b"") == []


def test_import_gitleaks_into_engagement(engagement):
    from attestra import db, services

    with db.session() as s:
        run = services.import_results(
            s, engagement, tool="gitleaks", filename="gitleaks.json",
            data=(FIX / "gitleaks" / "gitleaks.json").read_bytes(), actor="tester",
        )
        assert run.new_findings == 1
        assert run.unmatched_findings == 0  # matched the services/payments repo asset
