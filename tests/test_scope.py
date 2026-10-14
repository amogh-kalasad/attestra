"""Tests for authorization validity, asset URL validation, scope matching, and
environment-gated import controls."""
from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------- Authorization model


def test_authorization_is_valid_within_window(fresh_db):
    """is_valid() returns True when today is between signed_on and expires_on."""
    from attestra import db, services

    today = date.today()
    with db.session() as s:
        e = services.create_engagement(
            s, tenant="T1", name="E1", type="va", frameworks=[],
            window_start=None, window_end=None, actor="tester",
        )
        a = services.add_authorization(
            s, e.id,
            filename="auth.txt",
            data=b"signed doc",
            signer="CISO",
            signed_on=today - timedelta(days=3),
            expires_on=today + timedelta(days=10),
            rules_of_engagement="no DoS",
            environments=["production"],
            actor="tester",
        )
        assert a.is_valid() is True
        assert a.is_valid(today - timedelta(days=5)) is False  # before window
        assert a.is_valid(today + timedelta(days=20)) is False  # after window


def test_authorization_covers_environment(fresh_db):
    """covers() returns True only for environments listed in the authorization."""
    from attestra import db, services

    today = date.today()
    with db.session() as s:
        e = services.create_engagement(
            s, tenant="T2", name="E2", type="va", frameworks=[],
            window_start=None, window_end=None, actor="tester",
        )
        a = services.add_authorization(
            s, e.id,
            filename="auth.txt",
            data=b"signed doc",
            signer="CISO",
            signed_on=today - timedelta(days=1),
            expires_on=today + timedelta(days=10),
            rules_of_engagement="ok",
            environments=["production", "staging"],
            actor="tester",
        )
        assert a.covers("production") is True
        assert a.covers("staging") is True
        assert a.covers("uat") is False
        assert a.covers("dev") is False


def test_expired_authorization_not_valid(fresh_db):
    """An authorization whose expires_on is in the past is not valid."""
    from attestra import db, services

    today = date.today()
    with db.session() as s:
        e = services.create_engagement(
            s, tenant="T3", name="E3", type="va", frameworks=[],
            window_start=None, window_end=None, actor="tester",
        )
        a = services.add_authorization(
            s, e.id,
            filename="auth.txt",
            data=b"old doc",
            signer="Former CISO",
            signed_on=today - timedelta(days=60),
            expires_on=today - timedelta(days=1),
            rules_of_engagement="expired",
            environments=["production"],
            actor="tester",
        )
        assert a.is_valid() is False


# ---------------------------------------------------------------- Asset URL validation


def test_web_app_asset_requires_full_url(fresh_db):
    """web_app assets must be a full URL with scheme and host."""
    from attestra import db, services
    from attestra.services import ServiceError

    with db.session() as s:
        e = services.create_engagement(
            s, tenant="T4", name="E4", type="va", frameworks=[],
            window_start=None, window_end=None, actor="tester",
        )
        with pytest.raises(ServiceError, match="full URLs"):
            services.add_asset(s, e.id, kind="web_app", identifier="shop.example.com", actor="tester")


def test_web_app_asset_accepts_https_url(fresh_db):
    """A full https:// URL is accepted for web_app."""
    from attestra import db, services

    with db.session() as s:
        e = services.create_engagement(
            s, tenant="T5", name="E5", type="va", frameworks=[],
            window_start=None, window_end=None, actor="tester",
        )
        a = services.add_asset(
            s, e.id, kind="web_app", identifier="https://shop.example.com", actor="tester"
        )
        assert a.identifier == "https://shop.example.com"


def test_invalid_kind_raises(fresh_db):
    from attestra import db, services
    from attestra.services import ServiceError

    with db.session() as s:
        e = services.create_engagement(
            s, tenant="T6", name="E6", type="va", frameworks=[],
            window_start=None, window_end=None, actor="tester",
        )
        with pytest.raises(ServiceError, match="kind"):
            services.add_asset(s, e.id, kind="unknown_kind", identifier="x", actor="tester")


# ---------------------------------------------------------------- match_asset label boundaries


def test_match_asset_exact():
    """A location that contains the asset key matches it."""
    from attestra.services import match_asset

    assets = [_make_asset("https://shop.example.com")]
    f = match_asset(assets, "https://shop.example.com/cart")
    assert f is not None
    assert f.identifier == "https://shop.example.com"


def test_match_asset_label_boundary_staging_does_not_match_production():
    """staging.shop.example.com must NOT match the production shop.example.com target."""
    from attestra.services import match_asset

    assets = [_make_asset("https://shop.example.com")]
    # staging.shop.example.com has 'shop.example.com' as a suffix but with a
    # word-boundary guard it should NOT match the production asset.
    result = match_asset(assets, "https://staging.shop.example.com/cart")
    assert result is None, "staging subdomain should not match production target"


def test_match_asset_prefers_longest_key():
    """When two assets could match, the one with the longer key wins."""
    from attestra.services import match_asset

    # Longer repo path key wins over a shorter parent prefix.
    repo_parent = _make_asset("services")
    repo_child = _make_asset("services/payments")
    result = match_asset([repo_parent, repo_child], "services/payments/views.py:42")
    assert result is not None
    assert result.identifier == "services/payments"


def test_match_asset_no_match_returns_none():
    from attestra.services import match_asset

    assets = [_make_asset("https://shop.example.com")]
    assert match_asset(assets, "https://other.com/page") is None


# ---------------------------------------------------------------- Environment-gated import


def test_env_gated_import_fails_when_asset_env_not_authorized(fresh_db):
    """Import is refused when a matched finding lands on an asset in an environment
    not covered by any valid authorization."""
    from attestra import db, services
    from attestra.services import ServiceError

    today = date.today()
    with db.session() as s:
        e = services.create_engagement(
            s, tenant="T7", name="E7", type="va", frameworks=[],
            window_start=None, window_end=None, actor="tester",
        )
        # Auth covers only staging — NOT production
        services.add_authorization(
            s, e.id,
            filename="auth.txt",
            data=b"staging only auth",
            signer="CISO",
            signed_on=today - timedelta(days=1),
            expires_on=today + timedelta(days=30),
            rules_of_engagement="staging only",
            environments=["staging"],
            actor="tester",
        )
        # Asset is in production — outside the authorized environment
        services.add_asset(
            s, e.id,
            kind="web_app",
            identifier="https://shop.example.com",
            environment="production",
            actor="tester",
        )
        # ZAP fixture targets shop.example.com → matches production asset → refused
        with pytest.raises(ServiceError, match="environments the client has not authorized"):
            services.import_results(
                s, e.id,
                tool="zap",
                filename="zap.json",
                data=(FIXTURES / "zap.json").read_bytes(),
                actor="tester",
            )


# ---------------------------------------------------------------- Duplicate asset


def test_duplicate_asset_refusal(fresh_db):
    """Adding the same target identifier twice to one engagement is rejected."""
    from attestra import db, services
    from attestra.services import ServiceError

    with db.session() as s:
        e = services.create_engagement(
            s, tenant="T8", name="E8", type="va", frameworks=[],
            window_start=None, window_end=None, actor="tester",
        )
        services.add_asset(
            s, e.id, kind="web_app", identifier="https://shop.example.com", actor="tester"
        )
        with pytest.raises(ServiceError, match="already in scope"):
            services.add_asset(
                s, e.id, kind="web_app", identifier="https://shop.example.com", actor="tester"
            )


# ---------------------------------------------------------------- helpers


def _make_asset(identifier: str):
    """Build a minimal Asset-like object for match_asset testing (no DB)."""
    from unittest.mock import MagicMock

    a = MagicMock()
    a.identifier = identifier
    return a
