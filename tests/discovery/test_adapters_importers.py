"""A-02/A-03/A-04: subfinder, dnsx and httpx-probe adapters + importers (fixtures only)."""
# @lat: [[attack-surface-and-platform#Discovery adapters]]

from __future__ import annotations

from pathlib import Path

import pytest

from attestra.importers import dnsx, httpx_probe, subfinder
from attestra.importers.subfinder import DiscoveryParseError
from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.dnsx import DnsxAdapter
from attestra.runner.scanners.httpx_probe import HttpxProbeAdapter
from attestra.runner.scanners.subfinder import SubfinderAdapter

FX = Path(__file__).parent / "fixtures"


def raw(name: str) -> bytes:
    return (FX / name).read_bytes()


def test_subfinder_parse_valid_and_duplicates():
    obs = subfinder.parse_observations(raw("subfinder.jsonl"))
    keys = [(o.name, o.detail["via"]) for o in obs]
    assert ("www.example.com", "crtsh") in keys and ("api.example.com", "alienvault") in keys
    assert keys.count(("www.example.com", "crtsh")) == 1  # exact duplicate dropped
    assert all(o.source == "subfinder" for o in obs)
    assert subfinder.parse(raw("subfinder.jsonl")) == []  # never findings


def test_subfinder_partial_last_line_tolerated():
    assert [o.name for o in subfinder.parse_observations(raw("subfinder_partial.jsonl"))] == ["a.example.com", "b.example.com"]


@pytest.mark.parametrize("mod", [subfinder, dnsx, httpx_probe])
def test_malformed_rejected(mod):
    with pytest.raises(DiscoveryParseError):
        mod.parse(raw("malformed.jsonl"))
    with pytest.raises(DiscoveryParseError):
        mod.parse(b"{not json")


@pytest.mark.parametrize("mod", [subfinder, dnsx, httpx_probe])
def test_empty_output_is_valid(mod):
    assert mod.parse(b"") == [] and mod.parse_observations(b"  \n") == []


def test_row_without_host_rejected():
    with pytest.raises(DiscoveryParseError):
        subfinder.parse(b'{"input":"example.com"}\n')
    with pytest.raises(DiscoveryParseError):
        dnsx.parse(b'{"a":["192.0.2.1"]}\n')
    with pytest.raises(DiscoveryParseError):
        httpx_probe.parse(b'{"status_code":200}\n')


def test_dnsx_merges_rows_and_keeps_status():
    obs = {o.name: o for o in dnsx.parse_observations(raw("dnsx.jsonl"))}
    www = obs["www.example.com"].detail
    assert www["a"] == ["93.184.216.34"] and www["aaaa"] == ["2606:2800:220:1::248"]
    assert www["cname"] == ["example.edgekey.net"] and www["status"] == "NOERROR"
    assert obs["old.example.com"].detail["status"] == "NXDOMAIN"
    assert obs["flaky.example.com"].detail["status"] == "SERVFAIL"
    assert dnsx.parse(raw("dnsx.jsonl")) == []


def test_httpx_prefers_https_and_keeps_metadata():
    obs = {o.name: o for o in httpx_probe.parse_observations(raw("httpx.jsonl"))}
    www = obs["www.example.com"].detail
    assert www["scheme"] == "https" and www["status_code"] == 200
    assert www["tech"] == ["HSTS", "Nginx"] and www["cdn"] == "cloudflare"
    assert obs["api.example.com"].detail["status_code"] == 401
    assert httpx_probe.parse(raw("httpx.jsonl")) == []


def test_importer_output_feeds_pipeline_as_candidates_only():
    from attestra.discovery import pipeline

    allobs = (
        subfinder.parse_observations(raw("subfinder.jsonl"))
        + dnsx.parse_observations(raw("dnsx.jsonl"))
        + httpx_probe.parse_observations(raw("httpx.jsonl"))
    )
    res = pipeline.merge_observations(allobs, apex="example.com", allowed_hosts=["example.com"])
    by = {c.name: c for c in res.candidates}
    assert by["www.example.com"].sources == ("dnsx", "httpx", "subfinder")
    assert by["www.example.com"].resolution == "resolved"
    assert by["old.example.com"].resolution == "nxdomain"
    assert by["www.example.com"].http["status_code"] == 200
    assert all(c.status == "pending" for c in res.candidates)


# ---------------------------------------------------------------- adapters (argv only, nothing runs)


def test_subfinder_argv_passive_bounded_no_keys(tmp_path):
    a = SubfinderAdapter()
    out = tmp_path / a.out_name
    argv = a.build_argv("Example.com", out_file=out)
    assert argv[:3] == ["subfinder", "-d", "example.com"]
    assert "-all" not in argv and "-active" not in argv and "-nW" not in argv
    pc = Path(argv[argv.index("-pc") + 1])
    assert pc.parent == tmp_path and "never uses provider API keys" in pc.read_text(encoding="utf-8")
    assert argv[argv.index("-max-time") + 1] == "10" and argv[argv.index("-rl") + 1] == "10"
    d = a.docker_args("example.com", out_file=out)
    assert "/out/subfinder-out.jsonl" in d and "/out/subfinder-provider-config.yaml" in d
    with pytest.raises(ValueError):
        a.build_argv(PinnedTarget(host="example.com", ip="192.0.2.1", port=443, scheme="https"), out_file=out)


def test_dnsx_argv_uses_bounded_host_file(tmp_path):
    a = DnsxAdapter()
    out = tmp_path / a.out_name
    argv = a.build_argv("www.example.com, API.example.com\nwww.example.com", out_file=out)
    lst = Path(argv[argv.index("-l") + 1])
    assert lst.read_text(encoding="utf-8").split() == ["www.example.com", "api.example.com"]
    assert argv[argv.index("-rl") + 1] == "50" and "-json" in argv
    assert a.docker_args("www.example.com", out_file=out)[1] == "/out/dnsx-hosts.txt"


def test_httpx_never_uses_python_httpx_binary(tmp_path, monkeypatch):
    import attestra.runner.scanners.httpx_probe as hp

    monkeypatch.setenv("ATTESTRA_HTTPX_BIN", "httpx")
    monkeypatch.setattr(hp, "which", lambda name: "/usr/bin/httpx")
    assert HttpxProbeAdapter().available() is False
    monkeypatch.delenv("ATTESTRA_HTTPX_BIN")
    assert HttpxProbeAdapter().available() is True  # httpx-toolkit found
    argv = HttpxProbeAdapter().build_argv("www.example.com", out_file=tmp_path / "httpx-out.jsonl")
    assert argv[0] == "httpx-toolkit"
    for flag in ("-rl", "-timeout", "-retries"):
        assert flag in argv
    assert "-follow-redirects" not in argv and "-fr" not in argv


@pytest.mark.parametrize("adapter", [SubfinderAdapter(), DnsxAdapter(), HttpxProbeAdapter()], ids=lambda a: a.name)
def test_validate_report_uses_own_importer(adapter):
    assert adapter.validate_report(raw(f"{'httpx' if adapter.name == 'httpx_probe' else adapter.name}.jsonl")) is None
    assert adapter.validate_report(b"garbage{") is not None
