import pytest

from attestra.runner.authorization import AuthorizationError, AuthorizedScope
from attestra.runner.dns_pin import drop_nat64_duplicates, pin_url


def _scope():
    return AuthorizedScope.__new__(AuthorizedScope)


def test_drops_nat64_when_matching_ipv4_present():
    assert drop_nat64_duplicates(["64:ff9b::1479:8dac", "20.121.141.172"]) == ["20.121.141.172"]


def test_keeps_nat64_without_matching_ipv4():
    assert drop_nat64_duplicates(["64:ff9b::1479:8dac", "8.8.8.8"]) == ["64:ff9b::1479:8dac", "8.8.8.8"]


def test_pin_url_uses_ipv4_behind_dns64(monkeypatch):
    scope = _scope()
    object.__setattr__(scope, "allow_private", False) if hasattr(type(scope), "__dataclass_fields__") else None
    try:
        scope.allow_private = False
        scope.private_ok_hosts = set()
    except Exception:
        object.__setattr__(scope, "allow_private", False)
        object.__setattr__(scope, "private_ok_hosts", set())
    pin = pin_url("https://demo.example.com/", scope, resolver=lambda h: ["64:ff9b::1479:8dac", "20.121.141.172"])
    assert pin.ip == "20.121.141.172"


def test_lone_nat64_still_refused():
    scope = _scope()
    try:
        scope.allow_private = False
        scope.private_ok_hosts = set()
    except Exception:
        object.__setattr__(scope, "allow_private", False)
        object.__setattr__(scope, "private_ok_hosts", set())
    with pytest.raises(AuthorizationError):
        pin_url("https://demo.example.com/", scope, resolver=lambda h: ["64:ff9b::1479:8dac"])


def test_private_ipv4_still_refused():
    scope = _scope()
    try:
        scope.allow_private = False
        scope.private_ok_hosts = set()
    except Exception:
        object.__setattr__(scope, "allow_private", False)
        object.__setattr__(scope, "private_ok_hosts", set())
    with pytest.raises(AuthorizationError):
        pin_url("https://demo.example.com/", scope, resolver=lambda h: ["64:ff9b::a00:1", "10.0.0.1"])
