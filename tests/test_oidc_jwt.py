"""Step 6.4: OIDC bearer JWT validation with a mocked JWKS (no network, no Keycloak)."""

from __future__ import annotations

import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ISS = "https://idp.example/realms/attestra"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _int_b64(n: int, size: int | None = None) -> str:
    size = size or (n.bit_length() + 7) // 8
    return _b64(n.to_bytes(size, "big"))


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def _jwk_rsa(key, kid="k1"):
    pub = key.public_key().public_numbers()
    return {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": _int_b64(pub.n), "e": _int_b64(pub.e)}


def _jwk_ec(key, kid="e1"):
    pub = key.public_key().public_numbers()
    return {"kty": "EC", "kid": kid, "crv": "P-256", "x": _int_b64(pub.x, 32), "y": _int_b64(pub.y, 32)}


def _sign(key, claims, *, alg="RS256", kid="k1"):
    header = _b64(json.dumps({"alg": alg, "typ": "JWT", "kid": kid}).encode())
    payload = _b64(json.dumps(claims).encode())
    msg = f"{header}.{payload}".encode()
    if alg == "RS256":
        sig = key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
    elif alg == "ES256":
        r, s = decode_dss_signature(key.sign(msg, ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    else:
        sig = b""
    return f"{header}.{payload}.{_b64(sig)}"


def _claims(**over):
    now = time.time()
    base = {"iss": ISS, "aud": ["account"], "azp": "attestra", "exp": now + 300, "iat": now,
            "sub": "u-1", "preferred_username": "Kc.Lead", "realm_access": {"roles": ["attestra-lead"]}}
    base.update(over)
    return base


@pytest.fixture
def oidc_on(monkeypatch):
    import attestra.config as cfg

    monkeypatch.setattr(cfg, "OIDC_ENABLED", True)
    monkeypatch.setattr(cfg, "OIDC_ISSUER", ISS)
    monkeypatch.setattr(cfg, "OIDC_CLIENT_ID", "attestra")
    monkeypatch.setattr(cfg, "OIDC_AUDIENCE", "")
    monkeypatch.setattr(cfg, "OIDC_ALGORITHMS", "RS256,ES256")
    monkeypatch.setattr(cfg, "OIDC_AUTO_PROVISION", True)


@pytest.fixture
def jwks(rsa_key, ec_key):
    from attestra.auth.jwt_verify import JWKSCache

    calls = []

    def fetch(url):
        calls.append(url)
        return {"keys": [_jwk_rsa(rsa_key), _jwk_ec(ec_key)]}

    cache = JWKSCache(ISS + "/protocol/openid-connect/certs", fetch=fetch)
    cache.calls = calls
    return cache


def test_valid_rs256_and_es256(oidc_on, jwks, rsa_key, ec_key):
    from attestra.auth.oidc import validate_access_token

    assert validate_access_token(_sign(rsa_key, _claims()), jwks=jwks)["sub"] == "u-1"
    assert validate_access_token(_sign(ec_key, _claims(), alg="ES256", kid="e1"), jwks=jwks)["sub"] == "u-1"
    assert len(jwks.calls) == 1  # cached


@pytest.mark.parametrize(
    "over,match",
    [
        ({"iss": "https://evil.example/realms/attestra"}, "issuer"),
        ({"aud": "other", "azp": "other"}, "audience"),
        ({"exp": time.time() - 3600}, "expired"),
        ({"nbf": time.time() + 3600}, "not yet valid"),
    ],
)
def test_claim_rejections(oidc_on, jwks, rsa_key, over, match):
    from attestra.auth.oidc import OIDCError, validate_access_token

    with pytest.raises(OIDCError, match=match):
        validate_access_token(_sign(rsa_key, _claims(**over)), jwks=jwks)


def test_bad_signature_wrong_key_and_alg_none(oidc_on, jwks, rsa_key):
    from attestra.auth.oidc import OIDCError, validate_access_token

    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(OIDCError, match="signature"):
        validate_access_token(_sign(other, _claims()), jwks=jwks)
    tok = _sign(rsa_key, _claims())
    h, p, s = tok.split(".")
    tampered = _b64(json.dumps(_claims(realm_access={"roles": ["admin"]})).encode())
    with pytest.raises(OIDCError, match="signature"):
        validate_access_token(f"{h}.{tampered}.{s}", jwks=jwks)
    with pytest.raises(OIDCError, match="algorithm"):
        validate_access_token(_sign(rsa_key, _claims(), alg="none"), jwks=jwks)
    with pytest.raises(OIDCError, match="algorithm"):
        validate_access_token(_sign(rsa_key, _claims(), alg="HS256"), jwks=jwks)


def test_unknown_kid_refetches_once_then_fails(oidc_on, jwks, rsa_key):
    from attestra.auth.oidc import OIDCError, validate_access_token

    validate_access_token(_sign(rsa_key, _claims()), jwks=jwks)
    with pytest.raises(OIDCError, match="not found"):
        validate_access_token(_sign(rsa_key, _claims(), kid="rotated"), jwks=jwks)
    assert len(jwks.calls) == 1  # refresh is rate-limited (min_refresh_s)


def test_disabled_by_default_returns_none(fresh_db, jwks, rsa_key, monkeypatch):
    from attestra import db
    from attestra.auth.oidc import authenticate_bearer_jwt

    monkeypatch.setattr("attestra.config.OIDC_ENABLED", False)
    with db.session() as s:
        assert authenticate_bearer_jwt(s, _sign(rsa_key, _claims()), jwks=jwks) is None


def test_principal_provisioning_role_and_tenant(oidc_on, fresh_db, jwks, rsa_key):
    from attestra import db
    from attestra.auth.oidc import authenticate_bearer_jwt
    from attestra.models import Tenant, User

    with db.session() as s:
        t = Tenant(name="Acme")
        s.add(t)
        s.flush()
        tid = t.id
        p = authenticate_bearer_jwt(s, _sign(rsa_key, _claims()), jwks=jwks)
        assert p and p.username == "kc.lead" and p.role == "lead" and p.tenant_id is None
        user = s.get(User, p.user_id)
        assert user.password_hash == "oidc"
        client_tok = _sign(rsa_key, _claims(preferred_username="cv", realm_access={"roles": []},
                                            attestra_tenant_id=str(tid)))
        cv = authenticate_bearer_jwt(s, client_tok, jwks=jwks)
        assert cv and cv.role == "client_viewer" and cv.tenant_id == tid
        # client role without tenant claim is refused; unknown tenant is refused
        assert authenticate_bearer_jwt(s, _sign(rsa_key, _claims(preferred_username="x", realm_access={})), jwks=jwks) is None
        assert authenticate_bearer_jwt(s, _sign(rsa_key, _claims(attestra_tenant_id=9999)), jwks=jwks) is None


def test_no_auto_provision(oidc_on, fresh_db, jwks, rsa_key, monkeypatch):
    from attestra import db
    from attestra.auth.oidc import authenticate_bearer_jwt

    monkeypatch.setattr("attestra.config.OIDC_AUTO_PROVISION", False)
    with db.session() as s:
        assert authenticate_bearer_jwt(s, _sign(rsa_key, _claims()), jwks=jwks) is None


def test_local_password_login_impossible_for_oidc_user(oidc_on, fresh_db, jwks, rsa_key):
    from attestra import db
    from attestra.auth.keys import authenticate_password
    from attestra.auth.oidc import authenticate_bearer_jwt

    with db.session() as s:
        assert authenticate_bearer_jwt(s, _sign(rsa_key, _claims()), jwks=jwks)
        assert authenticate_password(s, "kc.lead", "oidc") is None


def test_api_accepts_jwt_when_enabled(oidc_on, fresh_db, jwks, rsa_key, monkeypatch):
    from fastapi.testclient import TestClient

    import attestra.auth.oidc as oidc
    from attestra.api import app

    monkeypatch.setattr(oidc, "_jwks", lambda: jwks)
    tok = _sign(rsa_key, _claims())
    with TestClient(app) as c:
        assert c.get("/api/engagements", headers={"Authorization": f"Bearer {tok}"}).status_code == 200
        bad = _sign(rsa_key, _claims(iss="https://evil.example"))
        assert c.get("/api/engagements", headers={"Authorization": f"Bearer {bad}"}).status_code == 401
        monkeypatch.setattr("attestra.config.OIDC_ENABLED", False)
        assert c.get("/api/engagements", headers={"Authorization": f"Bearer {tok}"}).status_code == 401
