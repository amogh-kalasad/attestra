"""Step 6.4: secrets provider (env default, Vault/OpenBao KV v2 over mocked HTTP)."""

from __future__ import annotations

import pytest

FAKE = "unit-test-value-not-a-secret"


def _kv(data):
    return {"data": {"data": data, "metadata": {"version": 1}}}


@pytest.fixture(autouse=True)
def _reset_provider():
    from attestra import secret_store

    secret_store.set_provider(None)
    yield
    secret_store.set_provider(None)


def test_env_is_default():
    from attestra.secret_store import EnvSecretsProvider, provider_from_env

    p = provider_from_env({})
    assert isinstance(p, EnvSecretsProvider)
    assert p.get("api_key_pepper", "from-env") == "from-env"


def test_vault_kv2_request_and_cache():
    from attestra.secret_store import provider_from_env

    calls = []

    def http_get(url, headers):
        calls.append((url, headers))
        return _kv({"api_key_pepper": FAKE})

    env = {"ATTESTRA_SECRETS_BACKEND": "vault", "ATTESTRA_VAULT_ADDR": "http://127.0.0.1:8200/",
           "ATTESTRA_VAULT_TOKEN": "t-unit", "ATTESTRA_VAULT_KV_PATH": "attestra/prod",
           "ATTESTRA_VAULT_NAMESPACE": "team"}
    p = provider_from_env(env, http_get=http_get)
    assert p.get("api_key_pepper") == FAKE
    assert p.get("session_secret", "fallback") == "fallback"  # missing key -> env fallback
    assert len(calls) == 1
    url, headers = calls[0]
    assert url == "http://127.0.0.1:8200/v1/secret/data/attestra/prod"
    assert headers["X-Vault-Token"] == "t-unit" and headers["X-Vault-Namespace"] == "team"
    assert "t-unit" not in repr(p)


def test_vault_token_file(tmp_path):
    from attestra.secret_store import provider_from_env

    f = tmp_path / "token"
    f.write_text("t-file\n", encoding="utf-8")
    seen = {}

    def http_get(url, headers):
        seen.update(headers)
        return _kv({"k": "v"})

    p = provider_from_env({"ATTESTRA_SECRETS_BACKEND": "openbao", "ATTESTRA_VAULT_ADDR": "https://bao.example",
                           "ATTESTRA_VAULT_TOKEN_FILE": str(f)}, http_get=http_get)
    assert p.get("k") == "v" and seen["X-Vault-Token"] == "t-file"


def test_vault_errors_do_not_leak_token():
    from attestra.secret_store import SecretsError, VaultKV2Provider, provider_from_env

    with pytest.raises(SecretsError, match="token missing"):
        provider_from_env({"ATTESTRA_SECRETS_BACKEND": "vault", "ATTESTRA_VAULT_ADDR": "https://v.example"})
    with pytest.raises(SecretsError, match="http"):
        VaultKV2Provider("file:///etc", "t")
    with pytest.raises(SecretsError, match="unknown"):
        provider_from_env({"ATTESTRA_SECRETS_BACKEND": "aws"})

    def boom(url, headers):
        raise OSError("connection refused t-secret-token")

    p = VaultKV2Provider("https://v.example", "t-secret-token", http_get=boom)
    with pytest.raises(SecretsError) as exc:
        p.get("x")
    assert "t-secret-token" not in str(exc.value)
    with pytest.raises(SecretsError, match="data.data"):
        VaultKV2Provider("https://v.example", "t", http_get=lambda u, h: {"data": {}}).get("x")


def test_pepper_and_session_use_provider(fresh_db):
    from attestra import secret_store
    from attestra.auth.keys import hash_api_key
    from attestra.auth.session import issue_session, read_session

    before = hash_api_key("raw")
    tok = issue_session(1, "u")
    secret_store.set_provider(secret_store.VaultKV2Provider(
        "https://v.example", "t", http_get=lambda u, h: _kv({"api_key_pepper": FAKE, "session_secret": FAKE})))
    assert hash_api_key("raw") != before
    assert read_session(tok) is None  # signed with the env secret, rejected under the vault secret
    assert read_session(issue_session(1, "u"))["uid"] == 1
