"""Report signing.

v0.1 signs with HMAC-SHA256 using a per-install secret key. This proves the
report has not changed since this Attestra instance signed it. It is not a
public-key signature: for customer-verifiable signatures, swap in Sigstore
cosign or an X.509 document signature (see docs/ARCHITECTURE.md).
"""
# @lat: [[reports#Signing]]

from __future__ import annotations

import hashlib
import hmac
import secrets

from attestra import config

ALGORITHM = "hmac-sha256"


def _key() -> bytes:
    config.ensure_dirs()
    path = config.DATA_DIR / "keys" / "signing.key"
    if not path.exists():
        path.write_text(secrets.token_hex(32))
        path.chmod(0o400)
    return bytes.fromhex(path.read_text().strip())


def key_id() -> str:
    return hashlib.sha256(_key()).hexdigest()[:16]


def sign(sha256_hex: str) -> str:
    mac = hmac.new(_key(), sha256_hex.encode(), hashlib.sha256).hexdigest()
    return f"{ALGORITHM}:{key_id()}:{mac}"


def verify(sha256_hex: str, signature: str) -> bool:
    try:
        alg, kid, mac = signature.split(":")
    except ValueError:
        return False
    if alg != ALGORITHM or kid != key_id():
        return False
    expected = hmac.new(_key(), sha256_hex.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, mac)
