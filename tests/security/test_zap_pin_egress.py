"""Tests for ZAP adapter: --add-host pin in argv and quarantine on out-of-scope sites."""
from __future__ import annotations

import json

import pytest

from attestra.runner.authorization import AuthorizedScope
from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.zap import ZapAdapter


def _scope(host: str = "shop.example.com") -> AuthorizedScope:
    return AuthorizedScope(
        name="test",
        allowed_hosts=frozenset([host]),
        allowed_urls=(f"https://{host}",),
        allowed_paths=(),
        allowed_images=(),
        allow_private=False,
    )


def _pin(host: str = "shop.example.com", ip: str = "93.184.216.34") -> PinnedTarget:
    return PinnedTarget(host=host, ip=ip, port=443, scheme="https")


# ---------------------------------------------------------------- --add-host in argv


def test_build_argv_contains_add_host(tmp_path):
    adapter = ZapAdapter()
    pin = _pin()
    argv = adapter.build_argv(pin, out_file=tmp_path / "report.json")
    assert "--add-host" in argv
    idx = argv.index("--add-host")
    assert argv[idx + 1] == f"{pin.host}:{pin.ip}"


def test_build_argv_target_uses_host_header(tmp_path):
    adapter = ZapAdapter()
    pin = _pin()
    argv = adapter.build_argv(pin, out_file=tmp_path / "report.json")
    assert "-t" in argv
    t_idx = argv.index("-t")
    assert "shop.example.com" in argv[t_idx + 1]


def test_build_argv_requires_pinned_target(tmp_path):
    adapter = ZapAdapter()
    with pytest.raises((ValueError, Exception)):
        adapter.build_argv("https://shop.example.com/", out_file=tmp_path / "report.json")


# ---------------------------------------------------------------- quarantine_if_out_of_scope


def test_quarantine_returns_none_for_in_scope():
    adapter = ZapAdapter()
    scope = _scope()
    report = json.dumps({
        "site": [
            {
                "@name": "https://shop.example.com",
                "alerts": [],
            }
        ]
    }).encode()
    assert adapter.quarantine_if_out_of_scope(report, scope) is None


def test_quarantine_returns_reason_for_extra_site():
    adapter = ZapAdapter()
    scope = _scope()
    report = json.dumps({
        "site": [
            {"@name": "https://shop.example.com", "alerts": []},
            {"@name": "https://evil.example.com", "alerts": []},
        ]
    }).encode()
    reason = adapter.quarantine_if_out_of_scope(report, scope)
    assert reason is not None
    assert len(reason) > 0


def test_quarantine_invalid_json():
    adapter = ZapAdapter()
    scope = _scope()
    reason = adapter.quarantine_if_out_of_scope(b"not json", scope)
    assert reason == "invalid ZAP JSON"


def test_quarantine_out_of_scope_instance_uri():
    adapter = ZapAdapter()
    scope = _scope()
    report = json.dumps({
        "site": [
            {
                "@name": "https://shop.example.com",
                "alerts": [
                    {
                        "instances": [
                            {"uri": "https://evil.example.com/xss"},
                        ]
                    }
                ],
            }
        ]
    }).encode()
    reason = adapter.quarantine_if_out_of_scope(report, scope)
    assert reason is not None
