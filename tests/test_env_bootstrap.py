"""Install-time .env Fernet key bootstrap."""

from __future__ import annotations

import os

from cryptography.fernet import Fernet

from attestra.env_bootstrap import (
    FERNET_KEY_NAME,
    SESSION_SECRET_NAME,
    ensure_credential_fernet_key,
    ensure_env_file,
    ensure_local_testing_env,
    generate_fernet_key,
    read_env_assignment,
)
from attestra.runner.scanners.base import join_docker_host_path


# @lat: [[interfaces#Configuration#Credential Fernet install bootstrap]]
def test_generate_fernet_key_is_valid():
    key = generate_fernet_key()
    Fernet(key.encode("ascii"))


# @lat: [[interfaces#Configuration#Credential Fernet install bootstrap#Creates env and key]]
def test_ensure_creates_env_and_key(tmp_path, monkeypatch):
    example = tmp_path / ".env.example"
    example.write_text(
        "APP_ENV=local\n# ATTESTRA_CREDENTIAL_FERNET_KEY=\n",
        encoding="utf-8",
    )
    env_path = tmp_path / ".env"
    monkeypatch.delenv(FERNET_KEY_NAME, raising=False)

    result = ensure_credential_fernet_key(env_path, example_path=example)
    assert result.created_env_file is True
    assert result.generated is True
    assert result.already_set is False
    value = read_env_assignment(env_path)
    assert value
    Fernet(value.encode("ascii"))
    assert os.environ.get(FERNET_KEY_NAME) == value


# @lat: [[interfaces#Configuration#Credential Fernet install bootstrap#Idempotent]]
def test_ensure_does_not_overwrite_existing_key(tmp_path, monkeypatch):
    env_path = tmp_path / ".env"
    existing = generate_fernet_key()
    env_path.write_text(f"APP_ENV=local\n{FERNET_KEY_NAME}={existing}\n", encoding="utf-8")
    monkeypatch.setenv(FERNET_KEY_NAME, "should-not-change")

    result = ensure_credential_fernet_key(env_path, example_path=tmp_path / "missing.example")
    assert result.created_env_file is False
    assert result.generated is False
    assert result.already_set is True
    assert read_env_assignment(env_path) == existing
    assert os.environ.get(FERNET_KEY_NAME) == "should-not-change"


# @lat: [[interfaces#Configuration#Credential Fernet install bootstrap#Fills empty assignment]]
def test_ensure_fills_empty_assignment(tmp_path, monkeypatch):
    env_path = tmp_path / ".env"
    env_path.write_text(f"APP_ENV=local\n{FERNET_KEY_NAME}=\n", encoding="utf-8")
    monkeypatch.delenv(FERNET_KEY_NAME, raising=False)

    result = ensure_credential_fernet_key(env_path)
    assert result.generated is True
    value = read_env_assignment(env_path)
    assert value
    Fernet(value.encode("ascii"))
    text = env_path.read_text(encoding="utf-8")
    assert text.count(FERNET_KEY_NAME) == 1


def test_join_docker_host_path_keeps_windows_separators():
    """Linux workers must not insert a slash into a Windows host data path."""
    got = join_docker_host_path(r"C:\Github\attestra\data", "auth-secrets")
    assert got == r"C:\Github\attestra\data\auth-secrets"
    assert "/" not in got


def test_join_docker_host_path_posix():
    assert join_docker_host_path("/var/lib/attestra/data", "raw") == "/var/lib/attestra/data/raw"


def test_local_testing_fills_missing_flags_and_keeps_real_secrets(tmp_path):
    env_path = tmp_path / ".env"
    existing = generate_fernet_key()
    env_path.write_text(
        f"APP_ENV=local\n{FERNET_KEY_NAME}={existing}\n"
        f"{SESSION_SECRET_NAME}=attestra-dev-session-change-me\n",
        encoding="utf-8",
    )
    result = ensure_local_testing_env(env_path, data_dir=tmp_path / "data")
    text = env_path.read_text(encoding="utf-8")
    assert read_env_assignment(env_path, FERNET_KEY_NAME) == existing
    assert "ATTESTRA_AUTH_WEB_ENABLED=1" in text
    assert "ATTESTRA_AUTOMATED_VAPT_ENABLED=1" in text
    assert "ATTESTRA_AUTH_SECRET_DIR=/data/auth-secrets" in text
    assert "ATTESTRA_INITIAL_TEST_RUN_CREDITS=10" in text
    session = read_env_assignment(env_path, SESSION_SECRET_NAME)
    assert session and session != "attestra-dev-session-change-me"
    pepper = read_env_assignment(env_path, "ATTESTRA_API_KEY_PEPPER")
    assert pepper and pepper != "attestra-dev-pepper-change-me"
    assert str((tmp_path / "data").resolve()) in text
    assert "ATTESTRA_CREDENTIAL_FERNET_KEY" not in result.changed_keys
    # Second run is a no-op for flags that are already set.
    again = ensure_local_testing_env(env_path, data_dir=tmp_path / "data")
    assert again.changed_keys == ()


def test_ensure_env_file_copies_example(tmp_path):
    example = tmp_path / ".env.example"
    example.write_text("APP_ENV=local\n", encoding="utf-8")
    target = tmp_path / ".env"
    assert ensure_env_file(target, example_path=example) is True
    assert target.read_text(encoding="utf-8") == "APP_ENV=local\n"
    assert ensure_env_file(target, example_path=example) is False
