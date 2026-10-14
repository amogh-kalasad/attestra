"""Tests for SSRF IP policy — blocked CIDRs and allow_private semantics."""
from __future__ import annotations

import ipaddress

import pytest

from attestra.runner.authorization import (
    AuthorizationError,
    is_blocked_ip,
    validate_resolved_ips,
)

# ---------------------------------------------------------------- is_blocked_ip


@pytest.mark.parametrize("addr", [
    "100.64.1.1",          # CGNAT / carrier-grade NAT
    "0.0.0.1",             # unspecified block (0.0.0.0/8)
    "169.254.169.254",     # link-local metadata (AWS / GCP)
    "fd00:ec2::254",       # AWS EC2 IMDSv2 IPv6
])
def test_blocked_ip(addr):
    ip = ipaddress.ip_address(addr)
    assert is_blocked_ip(ip) is True


def test_ipv4_mapped_loopback_refused_by_validate():
    """::ffff:127.0.0.1 unwraps to loopback and is treated as a blocked SSRF pivot."""
    with pytest.raises(AuthorizationError, match="blocked IP"):
        validate_resolved_ips(["::ffff:127.0.0.1"], allow_private=False)


def test_public_ip_not_blocked():
    ip = ipaddress.ip_address("8.8.8.8")
    assert is_blocked_ip(ip) is False


# ---------------------------------------------------------------- validate_resolved_ips — blocked always refused


@pytest.mark.parametrize("addr", [
    "169.254.169.254",
    "100.64.1.1",
    "fd00:ec2::254",
])
def test_validate_blocked_always_raises(addr):
    with pytest.raises(AuthorizationError, match="blocked IP"):
        validate_resolved_ips([addr], allow_private=False)


def test_validate_blocked_with_allow_private_still_raises():
    """Blocked CIDRs are never allowed, even with allow_private=True."""
    with pytest.raises(AuthorizationError, match="blocked IP"):
        validate_resolved_ips(["169.254.169.254"], allow_private=True)


# ---------------------------------------------------------------- validate_resolved_ips — private refused without allow_private


def test_private_ip_refused_when_allow_private_false():
    with pytest.raises(AuthorizationError, match="non-global IP"):
        validate_resolved_ips(["192.168.1.1"], allow_private=False)


def test_public_ip_allowed():
    result = validate_resolved_ips(["8.8.8.8"], allow_private=False)
    assert len(result) == 1
    assert str(result[0]) == "8.8.8.8"


def test_empty_list_raises():
    with pytest.raises(AuthorizationError, match="no resolved IPs"):
        validate_resolved_ips([])
