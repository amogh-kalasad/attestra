"""Minimal JWS (JWT) verification against a JWKS, using ``cryptography`` only.

Supports RS256/RS384/RS512 and ES256/ES384. Used for OIDC bearer tokens issued
by Keycloak (Step 6.4). ``alg: none`` and HMAC algorithms are always rejected.
"""

from __future__ import annotations

import base64
import json
import threading
import time
import urllib.request
from collections.abc import Callable
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

JwksFetcher = Callable[[str], dict[str, Any]]

_RSA = {"RS256": hashes.SHA256, "RS384": hashes.SHA384, "RS512": hashes.SHA512}
_EC = {"ES256": (hashes.SHA256, ec.SECP256R1, 32), "ES384": (hashes.SHA384, ec.SECP384R1, 48)}
_CURVES = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1}


class JWTError(Exception):
    pass


def b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _b64_int(data: str) -> int:
    return int.from_bytes(b64url_decode(data), "big")


def http_get_json(url: str, *, timeout: float = 5.0) -> dict[str, Any]:
    if not url.lower().startswith(("https://", "http://")):
        raise JWTError("JWKS URL must be http(s)")
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - scheme checked above
        return json.loads(resp.read(1_000_000).decode("utf-8"))


def public_key_from_jwk(jwk: dict[str, Any]):
    kty = jwk.get("kty")
    if kty == "RSA":
        return rsa.RSAPublicNumbers(_b64_int(jwk["e"]), _b64_int(jwk["n"])).public_key()
    if kty == "EC":
        curve = _CURVES.get(jwk.get("crv", ""))
        if curve is None:
            raise JWTError("unsupported EC curve")
        return ec.EllipticCurvePublicNumbers(_b64_int(jwk["x"]), _b64_int(jwk["y"]), curve()).public_key()
    raise JWTError(f"unsupported key type {kty!r}")


class JWKSCache:
    """Caches a JWKS document; refetches on unknown ``kid`` (key rotation), rate-limited."""

    def __init__(self, url: str, *, fetch: JwksFetcher | None = None, ttl_s: float = 300.0, min_refresh_s: float = 30.0):
        self.url = url
        self.fetch = fetch or http_get_json
        self.ttl_s = ttl_s
        self.min_refresh_s = min_refresh_s
        self._keys: dict[str, dict[str, Any]] = {}
        self._fetched_at = 0.0
        self._lock = threading.Lock()

    def _refresh(self) -> None:
        doc = self.fetch(self.url)
        keys = {}
        for k in doc.get("keys") or []:
            if k.get("use", "sig") == "sig":
                keys[k.get("kid", "")] = k
        self._keys = keys
        self._fetched_at = time.monotonic()

    def get(self, kid: str) -> dict[str, Any]:
        with self._lock:
            age = time.monotonic() - self._fetched_at
            if not self._keys or age > self.ttl_s or (kid not in self._keys and age > self.min_refresh_s):
                self._refresh()
            if kid in self._keys:
                return self._keys[kid]
            if not kid and len(self._keys) == 1:
                return next(iter(self._keys.values()))
        raise JWTError("signing key not found in JWKS")


def verify_jws(token: str, jwks: JWKSCache, *, allowed_algs: tuple[str, ...] = ("RS256", "ES256")) -> dict[str, Any]:
    """Verify the signature and return the decoded claims. Claims are NOT validated here."""
    try:
        h64, p64, s64 = token.split(".")
        header = json.loads(b64url_decode(h64))
        claims = json.loads(b64url_decode(p64))
        sig = b64url_decode(s64)
    except Exception as exc:
        raise JWTError("malformed token") from exc
    alg = header.get("alg")
    if alg not in allowed_algs or (alg not in _RSA and alg not in _EC):
        raise JWTError(f"algorithm not allowed: {alg!r}")
    jwk = jwks.get(header.get("kid", ""))
    if jwk.get("alg") and jwk["alg"] != alg:
        raise JWTError("algorithm does not match key")
    key = public_key_from_jwk(jwk)
    signing_input = f"{h64}.{p64}".encode("ascii")
    try:
        if alg in _RSA:
            if not isinstance(key, rsa.RSAPublicKey):
                raise JWTError("key type mismatch")
            key.verify(sig, signing_input, padding.PKCS1v15(), _RSA[alg]())
        else:
            hash_cls, _curve, size = _EC[alg]
            if not isinstance(key, ec.EllipticCurvePublicKey) or len(sig) != 2 * size:
                raise JWTError("key type mismatch")
            der = encode_dss_signature(int.from_bytes(sig[:size], "big"), int.from_bytes(sig[size:], "big"))
            key.verify(der, signing_input, ec.ECDSA(hash_cls()))
    except InvalidSignature as exc:
        raise JWTError("bad signature") from exc
    if not isinstance(claims, dict):
        raise JWTError("claims must be an object")
    return claims
