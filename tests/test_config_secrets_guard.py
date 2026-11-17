"""K-04 + FND-02 startup guards in ``config.validate_runtime_config``."""

from __future__ import annotations

import pytest

from attestra import config
from attestra.config import ConfigurationError


@pytest.fixture
def clean_env(monkeypatch):
    for k in ("APP_ENV", "ATTESTRA_API_KEY_PEPPER", "ATTESTRA_SESSION_SECRET",
              "BYPASS_TARGET_OWNERSHIP_VERIFICATION", "BYPASS_SIGNED_AUTHORIZATION_VERIFICATION",
              "ATTESTRA_INTRUSIVE_ALLOWED_ENVIRONMENTS"):
        monkeypatch.delenv(k, raising=False)
    yield monkeypatch
    monkeypatch.setattr(config, "INTRUSIVE_ALLOWED_ENVIRONMENTS", None, raising=False)


@pytest.mark.parametrize("env", ["staging", "production"])
def test_default_secrets_rejected_outside_dev(clean_env, env):
    clean_env.setenv("APP_ENV", env)
    with pytest.raises(ConfigurationError) as exc:
        config.validate_runtime_config()
    msg = str(exc.value)
    assert "ATTESTRA_API_KEY_PEPPER" in msg and "ATTESTRA_SESSION_SECRET" in msg
    assert "attestra-dev" not in msg  # never echo values


def test_custom_secrets_accepted_in_production(clean_env):
    clean_env.setenv("APP_ENV", "production")
    clean_env.setenv("ATTESTRA_API_KEY_PEPPER", "x" * 40)
    clean_env.setenv("ATTESTRA_SESSION_SECRET", "y" * 40)
    config.validate_runtime_config()


@pytest.mark.parametrize("env", [None, "local", "test", "development"])
def test_defaults_allowed_for_local(clean_env, env):
    if env:
        clean_env.setenv("APP_ENV", env)
    config.validate_runtime_config()


def test_production_in_intrusive_allowlist_fails_startup(clean_env):
    clean_env.setenv("ATTESTRA_INTRUSIVE_ALLOWED_ENVIRONMENTS", "dev,production")
    with pytest.raises(ConfigurationError, match="production"):
        config.validate_runtime_config()
    assert config.INTRUSIVE_ALLOWED_ENVIRONMENTS == frozenset()


def test_default_allowlist_is_dev_demo(clean_env):
    config.validate_runtime_config()
    assert config.INTRUSIVE_ALLOWED_ENVIRONMENTS == frozenset({"dev", "demo"})


def test_new_feature_flags_default_off():
    for name in ("AUTOMATED_VAPT_SSRF", "AUTOMATED_VAPT_UPLOAD", "AUTOMATED_VAPT_STORED_XSS", "PLANNER_ENABLED",
                 "GUIDED_PLANS_ENABLED", "PROBES_WEB_SAFE", "API_IMPORT_ENABLED", "GRAPHQL_PROBE",
                 "DISCOVERY_ENABLED", "TENANT_STRICT", "MAINTENANCE_ENABLED", "INTEL_AUTO_REFRESH"):
        assert getattr(config, name) is False, name
    assert config.RUN_VALIDITY_MODE == "enforce"
