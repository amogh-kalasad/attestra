"""Tests for engagement-scoped target authorization."""
from __future__ import annotations

from datetime import date, timedelta

import pytest

from attestra.runner.authorization import (
    AuthorizationError,
    AuthorizedScope,
    _image_allowed,
    assert_safe_cli_arg,
    scope_for_engagement,
    validate_image_target,
    validate_url_target,
)

# ---------------------------------------------------------------- helpers


def _make_scope(**overrides) -> AuthorizedScope:
    defaults = dict(
        name="test",
        allowed_hosts=frozenset(["shop.example.com"]),
        allowed_urls=("https://shop.example.com",),
        allowed_paths=("services/payments",),
        allowed_images=("registry.example.com/shop/api",),
        allow_private=False,
        deny_hosts=(),
        deny_urls=(),
        deny_paths=(),
        deny_images=(),
        deny_cidrs=(),
        private_ok_hosts=frozenset(),
    )
    defaults.update(overrides)
    return AuthorizedScope(**defaults)


# ---------------------------------------------------------------- off-list host


def test_url_host_not_in_scope_raises():
    scope = _make_scope()
    with pytest.raises(AuthorizationError, match="not in scope"):
        validate_url_target(scope, "https://evil.example.com/login")


# ---------------------------------------------------------------- wrong scheme


def test_non_http_scheme_raises():
    scope = _make_scope()
    with pytest.raises(AuthorizationError, match="unsupported URL scheme"):
        validate_url_target(scope, "ftp://shop.example.com/")


# ---------------------------------------------------------------- path outside prefix


def test_path_outside_allowed_prefix_raises():
    scope = _make_scope()
    with pytest.raises(AuthorizationError, match="outside allowed prefixes"):
        from attestra.runner.authorization import validate_path_target
        validate_path_target(scope, "other/service")


def test_path_inside_prefix_ok():
    scope = _make_scope()
    from attestra.runner.authorization import validate_path_target
    # should not raise
    validate_path_target(scope, "services/payments/src")


# ---------------------------------------------------------------- unsafe CLI chars


@pytest.mark.parametrize("bad", [
    "arg;rm -rf /",
    "arg|cat /etc/passwd",
    "arg&id",
    "arg`whoami`",
    "arg$(id)",
    "arg\necho hi",
    "arg\recho hi",
])
def test_assert_safe_cli_arg_blocks_metacharacters(bad):
    with pytest.raises(AuthorizationError, match="unsafe characters"):
        assert_safe_cli_arg(bad)


def test_assert_safe_cli_arg_allows_normal():
    result = assert_safe_cli_arg("--severity=HIGH")
    assert result == "--severity=HIGH"


# ---------------------------------------------------------------- expired auth via scope_for_engagement


def test_scope_for_engagement_expired_auth_raises(engagement):
    from attestra import db
    from attestra.runner.authorization import scope_for_engagement

    # Use a future date far beyond window — authorization expires 30 days from fixture
    future = date.today() + timedelta(days=60)
    with db.session() as s:
        with pytest.raises(AuthorizationError, match="no valid authorization"):
            scope_for_engagement(s, engagement, on=future)


def test_scope_for_engagement_valid(engagement):
    from attestra import db

    with db.session() as s:
        scope = scope_for_engagement(s, engagement)
    assert "shop.example.com" in scope.allowed_hosts


# ---------------------------------------------------------------- exact image match (_image_allowed)


def test_image_allowed_exact_match():
    assert _image_allowed("nginx:1.25", "nginx:1.25") is True


def test_image_allowed_no_match():
    assert _image_allowed("nginx-evil:1.25", "nginx:1.25") is False


def test_image_allowed_wildcard():
    assert _image_allowed("nginx:1.25", "nginx*") is True


def test_image_evil_not_matched_by_non_wildcard():
    """nginx:1.25 scope must not authorize nginx-evil."""
    scope = _make_scope(allowed_images=("nginx:1.25",))
    with pytest.raises(AuthorizationError, match="not in scope"):
        validate_image_target(scope, "nginx-evil:1.25")


def test_image_exact_allowed():
    scope = _make_scope(allowed_images=("nginx:1.25",))
    # Should not raise
    validate_image_target(scope, "nginx:1.25")
