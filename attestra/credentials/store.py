"""Engagement scan-login credential store.

Stores secrets outside normal DB columns as opaque ``secret_ref`` values of the
form ``cred:t{tid}:e{eid}:{uuid}``. Callers persist only the reference; the
plaintext never enters SQL columns or logs.

Backends
--------
* **EncryptedLocalStore** (default for engagement credentials): Fernet-encrypts
  each secret and writes ciphertext under
  ``DATA_DIR/tenants/{tid}/credentials/{ref_hash}`` with restrictive permissions.
* **Vault / OpenBao**: ``ATTESTRA_SECRETS_BACKEND=vault|openbao`` drives the
  platform ``attestra.secret_store`` provider, which is currently **read-only**
  for platform secrets (pepper, session, OIDC). Engagement credentials always use
  EncryptedLocalStore until KV write support lands.

Environment
-----------
* ``ATTESTRA_CREDENTIAL_FERNET_KEY`` — url-safe base64 32-byte Fernet key (required
  outside ephemeral mode).
* ``ATTESTRA_CREDENTIAL_ALLOW_EPHEMERAL=1`` — tests/dev only: generate a process-local
  Fernet key when the env key is unset. Production must set the key explicitly.
* ``ATTESTRA_SECRETS_BACKEND`` — documented above; does not change engagement writes.

Module functions: ``put_secret``, ``get_secret``, ``delete_secret``, ``rotate_secret``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import uuid
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from attestra import config
from attestra.secret_store import SecretsError

_REF_RE = re.compile(r"^cred:t(?P<tid>\d+):e(?P<eid>\d+):(?P<uid>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$")

_DIR_MODE = 0o700
_FILE_MODE = 0o600

_ephemeral_key: bytes | None = None
_ephemeral_lock = threading.Lock()

_store: EncryptedLocalStore | None = None
_store_lock = threading.Lock()


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes")


def resolve_fernet_key(env: dict[str, str] | None = None) -> bytes:
    """Return the Fernet key bytes, or raise SecretsError if not configured."""
    global _ephemeral_key
    env = os.environ if env is None else env
    raw = (env.get("ATTESTRA_CREDENTIAL_FERNET_KEY") or "").strip()
    if raw:
        try:
            key = raw.encode("ascii")
            Fernet(key)  # validate shape early
            return key
        except Exception:
            raise SecretsError("invalid ATTESTRA_CREDENTIAL_FERNET_KEY") from None
    if _truthy(env.get("ATTESTRA_CREDENTIAL_ALLOW_EPHEMERAL")):
        with _ephemeral_lock:
            if _ephemeral_key is None:
                _ephemeral_key = Fernet.generate_key()
            return _ephemeral_key
    raise SecretsError("credential encryption key not configured")


def reset_ephemeral_key() -> None:
    """Clear the process-local ephemeral key (tests)."""
    global _ephemeral_key
    with _ephemeral_lock:
        _ephemeral_key = None


def parse_secret_ref(secret_ref: str) -> tuple[int, int, str]:
    """Return ``(tenant_id, engagement_id, uuid)`` or raise SecretsError."""
    m = _REF_RE.match(secret_ref or "")
    if not m:
        raise SecretsError("invalid secret_ref")
    return int(m.group("tid")), int(m.group("eid")), m.group("uid")


def _ref_hash(secret_ref: str) -> str:
    return hashlib.sha256(secret_ref.encode("utf-8")).hexdigest()


def _restrictive_chmod(path: Path, mode: int) -> None:
    try:
        path.chmod(mode)
    except OSError:
        pass


class EncryptedLocalStore:
    """Fernet-encrypted engagement credential files under DATA_DIR."""

    name = "encrypted_local"

    def __init__(
        self,
        *,
        root: Path | None = None,
        key: bytes | None = None,
        env: dict[str, str] | None = None,
    ):
        self._root_override = root
        self._key = key if key is not None else resolve_fernet_key(env)
        self._fernet = Fernet(self._key)

    def __repr__(self) -> str:
        return f"EncryptedLocalStore(root={self.root!r})"

    @property
    def root(self) -> Path:
        if self._root_override is not None:
            return self._root_override
        return Path(config.DATA_DIR)

    def _cred_dir(self, tenant_id: int) -> Path:
        return self.root / "tenants" / str(tenant_id) / "credentials"

    def _path_for(self, secret_ref: str) -> Path:
        tid, _, _ = parse_secret_ref(secret_ref)
        return self._cred_dir(tid) / _ref_hash(secret_ref)

    def put_secret(self, tenant_id: int, engagement_id: int, label: str, value: str) -> str:
        if not isinstance(tenant_id, int) or tenant_id < 1:
            raise SecretsError("tenant_id must be a positive int")
        if not isinstance(engagement_id, int) or engagement_id < 1:
            raise SecretsError("engagement_id must be a positive int")
        if not isinstance(value, str) or value == "":
            raise SecretsError("secret value must be a non-empty string")
        secret_ref = f"cred:t{tenant_id}:e{engagement_id}:{uuid.uuid4()}"
        self._write(secret_ref, label=str(label or ""), value=value)
        return secret_ref

    def get_secret(self, secret_ref: str) -> str:
        path = self._path_for(secret_ref)
        if not path.is_file():
            raise SecretsError("secret not found")
        try:
            token = path.read_bytes()
            payload = json.loads(self._fernet.decrypt(token).decode("utf-8"))
        except (OSError, InvalidToken, json.JSONDecodeError, UnicodeDecodeError, TypeError, KeyError):
            raise SecretsError("secret not found") from None
        value = payload.get("value")
        if not isinstance(value, str):
            raise SecretsError("secret not found")
        return value

    def delete_secret(self, secret_ref: str) -> None:
        path = self._path_for(secret_ref)
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            raise SecretsError(f"failed to delete secret ({type(exc).__name__})") from None

    def rotate_secret(self, secret_ref: str, new_value: str) -> str:
        if not isinstance(new_value, str) or new_value == "":
            raise SecretsError("secret value must be a non-empty string")
        path = self._path_for(secret_ref)
        if not path.is_file():
            raise SecretsError("secret not found")
        label = ""
        try:
            payload = json.loads(self._fernet.decrypt(path.read_bytes()).decode("utf-8"))
            if isinstance(payload.get("label"), str):
                label = payload["label"]
        except (OSError, InvalidToken, json.JSONDecodeError, UnicodeDecodeError, TypeError):
            raise SecretsError("secret not found") from None
        tid, eid, _ = parse_secret_ref(secret_ref)
        self._write(secret_ref, label=label, value=new_value, tenant_id=tid, engagement_id=eid)
        return secret_ref

    def _write(
        self,
        secret_ref: str,
        *,
        label: str,
        value: str,
        tenant_id: int | None = None,
        engagement_id: int | None = None,
    ) -> None:
        tid, eid, _ = parse_secret_ref(secret_ref)
        if tenant_id is not None and tenant_id != tid:
            raise SecretsError("secret_ref tenant mismatch")
        if engagement_id is not None and engagement_id != eid:
            raise SecretsError("secret_ref engagement mismatch")
        folder = self._cred_dir(tid)
        folder.mkdir(parents=True, exist_ok=True)
        _restrictive_chmod(folder, _DIR_MODE)
        payload: dict[str, Any] = {
            "ref": secret_ref,
            "label": label,
            "tenant_id": tid,
            "engagement_id": eid,
            "value": value,
        }
        token = self._fernet.encrypt(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        path = folder / _ref_hash(secret_ref)
        # Write via temp then replace so readers never see a partial file.
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(token)
        _restrictive_chmod(tmp, _FILE_MODE)
        tmp.replace(path)
        _restrictive_chmod(path, _FILE_MODE)


def get_store() -> EncryptedLocalStore:
    """Return the process credential store (EncryptedLocalStore)."""
    global _store
    with _store_lock:
        if _store is None:
            _store = EncryptedLocalStore()
        return _store


def set_store(store: EncryptedLocalStore | None) -> None:
    """Override the process store (tests). ``None`` rebuilds on next use."""
    global _store
    with _store_lock:
        _store = store


def put_secret(tenant_id: int, engagement_id: int, label: str, value: str) -> str:
    """Store ``value`` and return an opaque ``secret_ref``."""
    return get_store().put_secret(tenant_id, engagement_id, label, value)


def get_secret(secret_ref: str) -> str:
    """Return the plaintext for ``secret_ref``; raises SecretsError if missing."""
    return get_store().get_secret(secret_ref)


def delete_secret(secret_ref: str) -> None:
    """Remove the ciphertext for ``secret_ref`` (idempotent if already gone)."""
    get_store().delete_secret(secret_ref)


def rotate_secret(secret_ref: str, new_value: str) -> str:
    """Replace the secret at ``secret_ref``; returns the same ref."""
    return get_store().rotate_secret(secret_ref, new_value)
