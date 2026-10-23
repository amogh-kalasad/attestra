"""Engagement scan-login credential store (opaque secret_ref + Fernet files)."""

from attestra.credentials.store import (
    EncryptedLocalStore,
    delete_secret,
    get_secret,
    get_store,
    put_secret,
    reset_ephemeral_key,
    resolve_fernet_key,
    rotate_secret,
    set_store,
)
from attestra.secret_store import SecretsError

__all__ = [
    "EncryptedLocalStore",
    "SecretsError",
    "delete_secret",
    "get_secret",
    "get_store",
    "put_secret",
    "reset_ephemeral_key",
    "resolve_fernet_key",
    "rotate_secret",
    "set_store",
]
