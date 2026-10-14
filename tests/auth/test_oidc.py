"""OIDC claim validation (mocked; no network)."""
# @lat: [[tests#Phase 2 auth tests#tests/auth/test_oidc.py]]

from __future__ import annotations

import time

import pytest


def test_validate_id_token_rejects_bad_nonce(monkeypatch):
    from attestra.auth.oidc import OIDCError, validate_id_token_claims

    monkeypatch.setattr("attestra.config.OIDC_ISSUER", "https://idp.example/realms/attestra")
    monkeypatch.setattr("attestra.config.OIDC_CLIENT_ID", "attestra")
    claims = {
        "iss": "https://idp.example/realms/attestra",
        "aud": "attestra",
        "nonce": "good",
        "exp": time.time() + 60,
    }
    with pytest.raises(OIDCError, match="nonce"):
        validate_id_token_claims(claims, expected_nonce="bad")


def test_validate_id_token_rejects_wrong_audience(monkeypatch):
    from attestra.auth.oidc import OIDCError, validate_id_token_claims

    monkeypatch.setattr("attestra.config.OIDC_ISSUER", "https://idp.example/realms/attestra")
    monkeypatch.setattr("attestra.config.OIDC_CLIENT_ID", "attestra")
    claims = {
        "iss": "https://idp.example/realms/attestra",
        "aud": "other-client",
        "nonce": "n1",
        "exp": time.time() + 60,
    }
    with pytest.raises(OIDCError, match="audience"):
        validate_id_token_claims(claims, expected_nonce="n1")


def test_validate_id_token_rejects_expired(monkeypatch):
    from attestra.auth.oidc import OIDCError, validate_id_token_claims

    monkeypatch.setattr("attestra.config.OIDC_ISSUER", "https://idp.example/realms/attestra")
    monkeypatch.setattr("attestra.config.OIDC_CLIENT_ID", "attestra")
    claims = {
        "iss": "https://idp.example/realms/attestra",
        "aud": "attestra",
        "nonce": "n1",
        "exp": time.time() - 10,
    }
    with pytest.raises(OIDCError, match="expired"):
        validate_id_token_claims(claims, expected_nonce="n1")


def test_map_oidc_role():
    from attestra.auth.oidc import map_oidc_role

    assert map_oidc_role({"realm_access": {"roles": ["lead"]}}) == "lead"
    assert map_oidc_role({"groups": ["/attestra-tester"]}) == "tester"
    assert map_oidc_role({}) == "client_viewer"
