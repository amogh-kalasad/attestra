"""Report signing: Ed25519 (customer-verifiable) with HMAC-SHA256 fallback.

Ed25519 public key is written to ``data/keys/signing.pub`` so customers can
verify outside Attestra. Legacy ``hmac-sha256:...`` signatures still verify.
"""
# @lat: [[reports#Signing]]

from __future__ import annotations

import hashlib
import hmac
import secrets
from base64 import b64decode, b64encode
from pathlib import Path

from attestra import config

ALGORITHM_HMAC = "hmac-sha256"
ALGORITHM_ED25519 = "ed25519"


def _hmac_key() -> bytes:
    config.ensure_dirs()
    path = config.DATA_DIR / "keys" / "signing.key"
    if not path.exists():
        path.write_text(secrets.token_hex(32), encoding="utf-8")
        path.chmod(0o400)
    return bytes.fromhex(path.read_text(encoding="utf-8").strip())


def hmac_key_id() -> str:
    return hashlib.sha256(_hmac_key()).hexdigest()[:16]


def _ed25519_paths() -> tuple[Path, Path]:
    config.ensure_dirs()
    keys = config.DATA_DIR / "keys"
    return keys / "signing_ed25519.pem", keys / "signing.pub"


def _ensure_ed25519():
    """Return cryptography Ed25519 private key, generating if needed. None if unavailable."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        return None
    priv_path, pub_path = _ed25519_paths()
    if priv_path.exists():
        data = priv_path.read_bytes()
        return serialization.load_pem_private_key(data, password=None)
    key = Ed25519PrivateKey.generate()
    priv_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    priv_path.chmod(0o400)
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_path.write_text(b64encode(pub).decode("ascii"), encoding="utf-8")
    pub_path.chmod(0o444)
    return key


def public_key_b64() -> str | None:
    _, pub_path = _ed25519_paths()
    if pub_path.exists():
        return pub_path.read_text(encoding="utf-8").strip()
    key = _ensure_ed25519()
    if key is None:
        return None
    return pub_path.read_text(encoding="utf-8").strip() if pub_path.exists() else None


def sign(sha256_hex: str) -> str:
    """Sign digest; prefer Ed25519, fall back to HMAC."""
    key = _ensure_ed25519()
    if key is not None:
        sig = key.sign(sha256_hex.encode("utf-8"))
        return f"{ALGORITHM_ED25519}:{b64encode(sig).decode('ascii')}"
    mac = hmac.new(_hmac_key(), sha256_hex.encode(), hashlib.sha256).hexdigest()
    return f"{ALGORITHM_HMAC}:{hmac_key_id()}:{mac}"


def algorithm_of(signature: str) -> str:
    if not signature:
        return ""
    return signature.split(":", 1)[0]


def verify(sha256_hex: str, signature: str) -> bool:
    try:
        parts = signature.split(":")
        alg = parts[0]
    except (ValueError, IndexError):
        return False
    if alg == ALGORITHM_HMAC:
        if len(parts) != 3:
            return False
        _, kid, mac = parts
        if kid != hmac_key_id():
            return False
        expected = hmac.new(_hmac_key(), sha256_hex.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, mac)
    if alg == ALGORITHM_ED25519:
        if len(parts) != 2:
            return False
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except ImportError:
            return False
        pub_b64 = public_key_b64()
        if not pub_b64:
            return False
        try:
            pub = Ed25519PublicKey.from_public_bytes(b64decode(pub_b64))
            pub.verify(b64decode(parts[1]), sha256_hex.encode("utf-8"))
            return True
        except Exception:
            return False
    return False


# Back-compat aliases used by older docs/tests
ALGORITHM = ALGORITHM_HMAC


def key_id() -> str:
    return hmac_key_id()
