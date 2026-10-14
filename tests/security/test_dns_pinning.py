"""Tests for DNS pinning — resolver mock, pin_url success and SSRF refusal."""
from __future__ import annotations

import pytest

from attestra.runner.authorization import AuthorizationError, AuthorizedScope
from attestra.runner.dns_pin import PinnedTarget, pin_url


def _scope_for(host: str, *, allow_private: bool = False, private_ok: frozenset = frozenset()) -> AuthorizedScope:
    return AuthorizedScope(
        name="test",
        allowed_hosts=frozenset([host]),
        allowed_urls=(f"https://{host}",),
        allowed_paths=(),
        allowed_images=(),
        allow_private=allow_private,
        private_ok_hosts=private_ok,
    )


# ---------------------------------------------------------------- happy path — mock resolver returns public IP


def test_pin_url_returns_pinned_target():
    scope = _scope_for("shop.example.com")

    def mock_resolver(host: str):
        return ["93.184.216.34"]  # example.com public IP

    result = pin_url("https://shop.example.com/api", scope, resolver=mock_resolver)
    assert isinstance(result, PinnedTarget)
    assert result.host == "shop.example.com"
    assert result.ip == "93.184.216.34"
    assert result.port == 443
    assert result.scheme == "https"


def test_pin_url_connect_url():
    scope = _scope_for("shop.example.com")

    def mock_resolver(_):
        return ["93.184.216.34"]

    pt = pin_url("https://shop.example.com", scope, resolver=mock_resolver)
    assert pt.connect_url == "https://93.184.216.34:443"


# ---------------------------------------------------------------- SSRF — resolver returns metadata IP → raises


def test_pin_url_metadata_ip_raises():
    scope = _scope_for("victim.example.com")

    def evil_resolver(_):
        return ["169.254.169.254"]

    with pytest.raises(AuthorizationError, match="blocked IP"):
        pin_url("https://victim.example.com", scope, resolver=evil_resolver)


def test_pin_url_cgnat_ip_raises():
    scope = _scope_for("victim.example.com")

    def cgnat_resolver(_):
        return ["100.64.0.1"]

    with pytest.raises(AuthorizationError, match="blocked IP"):
        pin_url("https://victim.example.com", scope, resolver=cgnat_resolver)


# ---------------------------------------------------------------- port and host_header


def test_pin_url_non_default_port():
    scope = AuthorizedScope(
        name="test",
        allowed_hosts=frozenset(["shop.example.com"]),
        allowed_urls=("https://shop.example.com:8443",),
        allowed_paths=(),
        allowed_images=(),
        allow_private=False,
    )

    def mock_resolver(_):
        return ["93.184.216.34"]

    pt = pin_url("https://shop.example.com:8443/", scope, resolver=mock_resolver)
    assert pt.port == 8443
    assert pt.host_header == "shop.example.com:8443"
