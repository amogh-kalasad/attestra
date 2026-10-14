"""Phase 7.3 adapters: argv only. Nothing is executed."""
from __future__ import annotations

import re

import pytest

from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners import get_adapter, http_service
from attestra.runner.scanners.registry import list_adapters

_METACHAR = re.compile(r"[;|&`$]|\$\(|\n|\r")
PIN = PinnedTarget(host="shop.example.com", ip="93.184.216.34", port=443, scheme="https")


def _clean(argv):
    assert [a for a in argv if _METACHAR.search(a)] == []
    return argv


def test_registry_lists_new_adapters():
    names = set(list_adapters())
    assert {"prowler", "kube_bench", "testssl", "gitleaks", "checkov", "naabu"} <= names
    for n in ("prowler", "kube_bench", "testssl", "gitleaks", "checkov", "naabu"):
        assert get_adapter(n).import_tool == n


def test_prowler_argv(tmp_path):
    argv = _clean(get_adapter("prowler").build_argv("aws", out_file=tmp_path / "prowler-out.json"))
    assert argv[:2] == ["prowler", "aws"] and "json-ocsf" in argv
    with pytest.raises(ValueError):
        get_adapter("prowler").build_argv("aws; rm", out_file=tmp_path / "x.json")
    with pytest.raises(ValueError):
        get_adapter("prowler").build_argv(PIN, out_file=tmp_path / "x.json")


def test_prowler_resolve_output(tmp_path):
    out = tmp_path / "prowler-out.json"
    real = tmp_path / "prowler-out.ocsf.json"
    real.write_text("[]")
    assert get_adapter("prowler").resolve_output(out) == real


def test_kube_bench_argv(tmp_path):
    argv = _clean(get_adapter("kube_bench").build_argv("node,policies", out_file=tmp_path / "o.json"))
    assert "--json" in argv and "node,policies" in argv
    with pytest.raises(ValueError):
        get_adapter("kube_bench").build_argv("everything", out_file=tmp_path / "o.json")


def test_testssl_uses_pinned_ip(tmp_path):
    argv = _clean(get_adapter("testssl").build_argv(PIN, out_file=tmp_path / "o.json"))
    assert argv[argv.index("--ip") + 1] == "93.184.216.34"
    assert argv[-1] == "shop.example.com:443"
    with pytest.raises(ValueError):
        get_adapter("testssl").build_argv("shop.example.com", out_file=tmp_path / "o.json")


def test_gitleaks_redacts(tmp_path):
    argv = _clean(get_adapter("gitleaks").build_argv("services/payments", out_file=tmp_path / "o.json"))
    assert "--redact" in argv


def test_checkov_argv(tmp_path):
    argv = _clean(get_adapter("checkov").build_argv("infra", out_file=tmp_path / "o.json"))
    assert argv[:3] == ["checkov", "--directory", "infra"]


def test_naabu_scans_pinned_ip_only(tmp_path):
    argv = _clean(get_adapter("naabu").build_argv(PIN, out_file=tmp_path / "o.jsonl"))
    assert argv[argv.index("-host") + 1] == "93.184.216.34"
    assert "shop.example.com" not in argv
    with pytest.raises(ValueError):
        get_adapter("naabu").build_argv(PIN, out_file=tmp_path / "o.jsonl", profile="aggressive")


def test_gpl_services_off_by_default():
    assert http_service.enabled_services({}) == []
    with pytest.raises(http_service.ServiceDisabled):
        http_service.service_config("openvas", {})
    with pytest.raises(http_service.ServiceDisabled):
        http_service.service_config("mobsf", {"ATTESTRA_MOBSF_ENABLED": "1"})  # no URL


def test_gpl_service_enabled_explicitly():
    env = {"ATTESTRA_OPENVAS_ENABLED": "true", "ATTESTRA_OPENVAS_URL": "https://gvm.internal.example/"}
    cfg = http_service.service_config("openvas", env)
    assert cfg.base_url == "https://gvm.internal.example" and "AGPL" in cfg.licence
    assert http_service.enabled_services(env) == ["openvas"]
