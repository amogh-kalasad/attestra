"""Reversible at-rest encryption for secrets that must be recovered (webhook HMAC keys).

Uses the same Fernet key as the credential store (``ATTESTRA_CREDENTIAL_FERNET_KEY``;
``ATTESTRA_CREDENTIAL_ALLOW_EPHEMERAL=1`` only for tests/dev - an ephemeral key makes
stored secrets unreadable after a restart). Plaintext secrets are never written to Mongo:
if no key is configured, writers fail closed (``SecretCodecError``) or, for bulk
migration/mirroring, drop the secret and flag the document (``secret_unavailable``).
"""

from __future__ import annotations

import hashlib
from typing import Any

PREFIX = "fernet:v1:"


class SecretCodecError(RuntimeError):
    """Encryption key missing/invalid, or a ciphertext could not be decrypted."""


def _fernet():
    from cryptography.fernet import Fernet

    from attestra.credentials.store import SecretsError, resolve_fernet_key

    try:
        return Fernet(resolve_fernet_key())
    except SecretsError as exc:
        raise SecretCodecError(f"secret encryption unavailable: {exc}") from None


def is_encrypted(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def encrypt_secret(plain: str) -> str:
    if not isinstance(plain, str) or not plain:
        raise SecretCodecError("empty secret")
    if is_encrypted(plain):
        return plain
    token = _fernet().encrypt(plain.encode("utf-8")).decode("ascii")
    return PREFIX + token


def decrypt_secret(stored: str) -> str:
    from cryptography.fernet import InvalidToken

    if not is_encrypted(stored):
        raise SecretCodecError("value is not an encrypted secret")
    try:
        return _fernet().decrypt(stored[len(PREFIX):].encode("ascii")).decode("utf-8")
    except InvalidToken:
        raise SecretCodecError("secret cannot be decrypted with the configured key") from None


def fingerprint(plain: str) -> str:
    """Short non-reversible id for a secret (lets ops confirm rotation without exposing it)."""
    return hashlib.sha256(plain.encode("utf-8")).hexdigest()[:12]


def protect_webhook_endpoint(doc: dict[str, Any]) -> dict[str, Any]:
    """Replace a plaintext ``secret`` field with ``secret_enc`` (in place, returns doc).

    Used by ``mongo-migrate import`` and the dual-write mirrors. Never raises for a missing
    key: the plaintext is dropped and ``secret_unavailable=True`` is set so the endpoint can be
    rotated after the key is configured.
    """
    plain = doc.pop("secret", None)
    if plain is None:
        return doc
    if is_encrypted(plain):
        doc["secret_enc"] = plain
        doc["secret_unavailable"] = False
        return doc
    if not plain:
        doc["secret_enc"] = None
        doc["secret_unavailable"] = True
        return doc
    try:
        doc["secret_enc"] = encrypt_secret(str(plain))
        doc["secret_fp"] = fingerprint(str(plain))
        doc["secret_unavailable"] = False
    except SecretCodecError:
        doc["secret_enc"] = None
        doc["secret_unavailable"] = True
    return doc
