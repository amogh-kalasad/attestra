"""Secrets provider (Step 6.4): environment (default) or Vault/OpenBao KV v2.

    ATTESTRA_SECRETS_BACKEND=env | vault
    ATTESTRA_VAULT_ADDR=https://vault.example:8200
    ATTESTRA_VAULT_TOKEN / ATTESTRA_VAULT_TOKEN_FILE   (token file preferred in k8s)
    ATTESTRA_VAULT_KV_MOUNT=secret   ATTESTRA_VAULT_KV_PATH=attestra
    ATTESTRA_VAULT_NAMESPACE=        (optional, Vault Enterprise / OpenBao namespaces)

Logical secret names map to KV keys: ``api_key_pepper``, ``session_secret``,
``oidc_client_secret``. A key missing in Vault falls back to the env value.
Secret values are never logged.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

HttpGet = Callable[[str, dict[str, str]], dict[str, Any]]


class SecretsError(Exception):
    pass


class EnvSecretsProvider:
    name = "env"

    def get(self, key: str, default: str = "") -> str:
        # Env values are already read into attestra.config; callers pass them as default.
        return default


def _http_get(url: str, headers: dict[str, str], *, timeout: float = 5.0) -> dict[str, Any]:
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - scheme checked by caller
        return json.loads(resp.read(1_000_000).decode("utf-8"))


class VaultKV2Provider:
    """Reads one KV v2 secret (``GET /v1/<mount>/data/<path>``) and caches its keys."""

    name = "vault"

    def __init__(
        self,
        addr: str,
        token: str,
        *,
        mount: str = "secret",
        path: str = "attestra",
        namespace: str = "",
        ttl_s: float = 300.0,
        http_get: HttpGet | None = None,
    ):
        if not addr.lower().startswith(("https://", "http://")):
            raise SecretsError("ATTESTRA_VAULT_ADDR must be an http(s) URL")
        if not token:
            raise SecretsError("Vault token missing (ATTESTRA_VAULT_TOKEN or ATTESTRA_VAULT_TOKEN_FILE)")
        self.url = f"{addr.rstrip('/')}/v1/{mount.strip('/')}/data/{path.strip('/')}"
        self._headers = {"X-Vault-Token": token, "Accept": "application/json"}
        if namespace:
            self._headers["X-Vault-Namespace"] = namespace
        self.ttl_s = ttl_s
        self._http_get = http_get or _http_get
        self._data: dict[str, str] | None = None
        self._fetched_at = 0.0
        self._lock = threading.Lock()

    def __repr__(self) -> str:  # never show the token
        return f"VaultKV2Provider(url={self.url!r})"

    def _load(self) -> dict[str, str]:
        with self._lock:
            if self._data is None or time.monotonic() - self._fetched_at > self.ttl_s:
                try:
                    doc = self._http_get(self.url, dict(self._headers))
                except Exception as exc:
                    raise SecretsError(f"Vault read failed for {self.url}: {type(exc).__name__}") from None
                data = ((doc or {}).get("data") or {}).get("data")
                if not isinstance(data, dict):
                    raise SecretsError("unexpected Vault KV v2 response (missing data.data)")
                self._data = {str(k): str(v) for k, v in data.items()}
                self._fetched_at = time.monotonic()
            return self._data

    def get(self, key: str, default: str = "") -> str:
        value = self._load().get(key)
        return value if value else default


_provider: EnvSecretsProvider | VaultKV2Provider | None = None
_provider_lock = threading.Lock()


def provider_from_env(env: dict[str, str] | None = None, *, http_get: HttpGet | None = None):
    env = os.environ if env is None else env
    backend = env.get("ATTESTRA_SECRETS_BACKEND", "env").strip().lower()
    if backend in ("", "env"):
        return EnvSecretsProvider()
    if backend in ("vault", "openbao"):
        token = env.get("ATTESTRA_VAULT_TOKEN", "")
        token_file = env.get("ATTESTRA_VAULT_TOKEN_FILE", "")
        if not token and token_file:
            token = Path(token_file).read_text(encoding="utf-8").strip()
        return VaultKV2Provider(
            env.get("ATTESTRA_VAULT_ADDR", ""),
            token,
            mount=env.get("ATTESTRA_VAULT_KV_MOUNT", "secret"),
            path=env.get("ATTESTRA_VAULT_KV_PATH", "attestra"),
            namespace=env.get("ATTESTRA_VAULT_NAMESPACE", ""),
            http_get=http_get,
        )
    raise SecretsError(f"unknown ATTESTRA_SECRETS_BACKEND {backend!r}")


def get_provider():
    global _provider
    with _provider_lock:
        if _provider is None:
            _provider = provider_from_env()
        return _provider


def set_provider(provider) -> None:
    """Override the provider (tests, or explicit wiring). ``None`` re-reads env on next use."""
    global _provider
    with _provider_lock:
        _provider = provider


def get_secret(key: str, default: str = "") -> str:
    return get_provider().get(key, default)
