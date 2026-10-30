"""Runtime settings, read from environment variables."""

from __future__ import annotations

import os
from pathlib import Path

DATA_DIR = Path(os.environ.get("ATTESTRA_DATA_DIR", Path.cwd() / "data")).resolve()

# Google Safe Browsing (webcheck). Off by default; needs both flag and API key.
# ATTESTRA_GSB_ENABLED=1 and ATTESTRA_GSB_API_KEY=... — key is never logged or stored.
# Production default is PostgreSQL 16 (Phase 6.1), e.g.
#   ATTESTRA_DATABASE_URL=postgresql+psycopg://attestra_app:***@db:5432/attestra
# (install the ``postgres`` extra). SQLite stays as the zero-config local/dev fallback.
POSTGRES_URL_EXAMPLE = "postgresql+psycopg://attestra_app:change-me@localhost:5432/attestra"
DATABASE_URL = os.environ.get("ATTESTRA_DATABASE_URL", f"sqlite:///{DATA_DIR / 'attestra.db'}")

# Remediation SLA in days per severity. Critical within 30 days aligns with PCI DSS 6.3.3.
SLA_DAYS = {"critical": 30, "high": 60, "medium": 90, "low": 180, "info": None}

RAW_DIR = DATA_DIR / "raw"
SCANNER_TIMEOUT_S = int(os.environ.get("ATTESTRA_SCANNER_TIMEOUT_S", "600"))
SCAN_RATE_PER_ASSET = int(os.environ.get("ATTESTRA_SCAN_RATE_PER_ASSET", "10"))
JOB_MAX_ATTEMPTS = int(os.environ.get("ATTESTRA_JOB_MAX_ATTEMPTS", "3"))
JOB_STALE_HEARTBEAT_S = int(os.environ.get("ATTESTRA_JOB_STALE_HEARTBEAT_S", "120"))
# Phase 6.2: scan orchestration. inline = polling durable worker; temporal = Temporal workflows.
ORCHESTRATOR = os.environ.get("ATTESTRA_ORCHESTRATOR", "inline")
TEMPORAL_ADDRESS = os.environ.get("ATTESTRA_TEMPORAL_ADDRESS", "localhost:7233")
TEMPORAL_NAMESPACE = os.environ.get("ATTESTRA_TEMPORAL_NAMESPACE", "default")
TEMPORAL_TASK_QUEUE = os.environ.get("ATTESTRA_TEMPORAL_TASK_QUEUE", "attestra-scans")

API_KEY_PEPPER = os.environ.get("ATTESTRA_API_KEY_PEPPER", "attestra-dev-pepper-change-me")
SESSION_SECRET = os.environ.get("ATTESTRA_SESSION_SECRET", "attestra-dev-session-change-me")
API_RATE_LIMIT = int(os.environ.get("ATTESTRA_API_RATE_LIMIT", "120"))

OIDC_ENABLED = os.environ.get("ATTESTRA_OIDC_ENABLED", "").lower() in ("1", "true", "yes")
OIDC_ISSUER = os.environ.get("ATTESTRA_OIDC_ISSUER", "")
OIDC_CLIENT_ID = os.environ.get("ATTESTRA_OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = os.environ.get("ATTESTRA_OIDC_CLIENT_SECRET", "")

# Step 6.4: bearer JWT validation (Keycloak access tokens). Local API keys/sessions stay the default.
OIDC_AUDIENCE = os.environ.get("ATTESTRA_OIDC_AUDIENCE", "")  # empty -> OIDC_CLIENT_ID
OIDC_JWKS_URL = os.environ.get("ATTESTRA_OIDC_JWKS_URL", "")  # empty -> <issuer>/protocol/openid-connect/certs
OIDC_ALGORITHMS = os.environ.get("ATTESTRA_OIDC_ALGORITHMS", "RS256,ES256")
OIDC_USERNAME_CLAIM = os.environ.get("ATTESTRA_OIDC_USERNAME_CLAIM", "preferred_username")
OIDC_TENANT_CLAIM = os.environ.get("ATTESTRA_OIDC_TENANT_CLAIM", "attestra_tenant_id")
OIDC_AUTO_PROVISION = os.environ.get("ATTESTRA_OIDC_AUTO_PROVISION", "true").lower() in ("1", "true", "yes")
# Secrets backend (attestra/secret_store.py): env (default) or vault (Vault/OpenBao KV v2).
SECRETS_BACKEND = os.environ.get("ATTESTRA_SECRETS_BACKEND", "env")

STORAGE_BACKEND = os.environ.get("ATTESTRA_STORAGE", "local")
S3_BUCKET = os.environ.get("ATTESTRA_S3_BUCKET", "")
S3_ENDPOINT = os.environ.get("ATTESTRA_S3_ENDPOINT", "")
S3_OBJECT_LOCK = os.environ.get("ATTESTRA_S3_OBJECT_LOCK", "").lower() in ("1", "true", "yes")

# CISA KEV and FIRST EPSS feed URLs (VERIFY periodically)
KEV_URL = os.environ.get(
    "ATTESTRA_KEV_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
)
EPSS_URL = os.environ.get(
    "ATTESTRA_EPSS_URL",
    "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
)

# Digests must include @sha256:. Replace VERIFY placeholders after `docker inspect` when pinning real images.
# Each image can be set with ATTESTRA_IMAGE_<TOOL> (for example ATTESTRA_IMAGE_TESTSSL).
_PLACEHOLDER_IMAGES = {
    "zap": "ghcr.io/zaproxy/zaproxy@sha256:0000000000000000000000000000000000000000000000000000000000000001",
    "trivy": "ghcr.io/aquasecurity/trivy@sha256:0000000000000000000000000000000000000000000000000000000000000002",
    "nuclei": "docker.io/projectdiscovery/nuclei@sha256:0000000000000000000000000000000000000000000000000000000000000003",
    "semgrep": "docker.io/returntocorp/semgrep@sha256:0000000000000000000000000000000000000000000000000000000000000004",
    "testssl": "docker.io/drwetter/testssl.sh@sha256:0000000000000000000000000000000000000000000000000000000000000005",
    "naabu": "docker.io/projectdiscovery/naabu@sha256:0000000000000000000000000000000000000000000000000000000000000006",
    "gitleaks": "docker.io/zricethezav/gitleaks@sha256:0000000000000000000000000000000000000000000000000000000000000007",
    "checkov": "docker.io/bridgecrew/checkov@sha256:0000000000000000000000000000000000000000000000000000000000000008",
}
SCANNER_IMAGES = {
    tool: os.environ.get(f"ATTESTRA_IMAGE_{tool.upper()}", default) for tool, default in _PLACEHOLDER_IMAGES.items()
}
# Persistent scanner caches (nuclei templates, trivy DB) so each run does not download them again.
SCANNER_CACHE_DIR = Path(os.environ.get("ATTESTRA_SCANNER_CACHE_DIR", DATA_DIR / "scanner-cache")).resolve()

# Evidence upload size cap (API + proof screenshot). Portal uses a stricter 5 MB cap.
EVIDENCE_MAX_BYTES = int(os.environ.get("ATTESTRA_EVIDENCE_MAX_BYTES", str(20 * 1024 * 1024)))


def image_is_placeholder(image: str) -> bool:
    """True for the built-in all-zero digests, which point at no real image."""
    digest = image.split("@sha256:", 1)[-1] if "@sha256:" in image else ""
    return bool(digest) and digest[:-1].strip("0") == ""


def ensure_dirs() -> None:
    for sub in ("evidence", "imports", "reports", "keys", "raw", "tenants", "feeds", "packs"):
        (DATA_DIR / sub).mkdir(parents=True, exist_ok=True)


def require_image_digest(image: str) -> str:
    """Refuse floating tags; every scanner image must be digest-pinned."""
    if "@sha256:" not in image:
        raise ValueError(f"scanner image must be pinned with @sha256: digest, got {image!r}")
    return image


# Authenticated website testing (market-gap Phase 6). Off by default.
AUTH_WEB_ENABLED = os.environ.get("ATTESTRA_AUTH_WEB_ENABLED", "").lower() in ("1", "true", "yes")
AUTH_WEB_MAX_ROUTES = int(os.environ.get("ATTESTRA_AUTH_WEB_MAX_ROUTES", "100"))
AUTH_WEB_MAX_DEPTH = int(os.environ.get("ATTESTRA_AUTH_WEB_MAX_DEPTH", "5"))
AUTH_WEB_MAX_DURATION_S = int(os.environ.get("ATTESTRA_AUTH_WEB_MAX_DURATION_S", "600"))
AUTH_WEB_RATE_PER_HOST = float(os.environ.get("ATTESTRA_AUTH_WEB_RATE_PER_HOST", "2"))
AUTH_WEB_CONCURRENCY = int(os.environ.get("ATTESTRA_AUTH_WEB_CONCURRENCY", "2"))
# Credential encryption: see attestra.credentials.store (ATTESTRA_CREDENTIAL_FERNET_KEY).

# Elite automated security-testing orchestrator. Off by default.
AUTOMATED_VAPT_ENABLED = os.environ.get("ATTESTRA_AUTOMATED_VAPT_ENABLED", "").lower() in (
    "1",
    "true",
    "yes",
)

# Feature flags. Changing these requires restarting the API and any workers
# (no hot reload). Bypass flags default to false and only activate in an
# allowlisted APP_ENV (local / test / development).
_ON_OFF_VALUES = frozenset({"ON", "OFF"})
_APP_ENV_KNOWN = frozenset({"local", "test", "development", "staging", "production"})
_APP_ENV_BYPASS_ALLOWLIST = frozenset({"local", "test", "development"})
_APP_ENV_PROHIBITED_BYPASS = frozenset({"staging", "production"})
_BOOL_TRUE = frozenset({"1", "true", "yes"})
_BOOL_FALSE = frozenset({"0", "false", "no"})
BYPASS_STATUS = "BYPASSED_LOCAL"

_REMOVED_OWNERSHIP = (
    "OWNERSHIP_VERIFICATION was removed. Use APP_ENV with "
    "BYPASS_TARGET_OWNERSHIP_VERIFICATION (default false; allowlisted "
    "APP_ENV: local, test, development)."
)
_REMOVED_SIGNED_AUTH = (
    "SIGNED_AUTHORIZATION was removed. Use APP_ENV with "
    "BYPASS_SIGNED_AUTHORIZATION_VERIFICATION (default false; allowlisted "
    "APP_ENV: local, test, development)."
)


class ConfigurationError(ValueError):
    """Invalid runtime configuration that must stop process startup."""


def _parse_on_off(name: str, value: str | None = None) -> str:
    """Return ``ON`` or ``OFF``. Missing/blank → ``ON``; else fail closed."""
    if value is None:
        value = os.environ.get(name)
    if value is None or not str(value).strip():
        return "ON"
    normalized = str(value).strip().upper()
    if normalized not in _ON_OFF_VALUES:
        raise ConfigurationError(
            f"{name} must be ON or OFF, got {value!r}. "
            "Fix the environment variable and restart the application or worker."
        )
    return normalized


def _parse_bool_default_false(name: str, value: str | None = None) -> bool:
    """Parse a boolean env flag. Missing/blank → False. Malformed → ConfigurationError."""
    if value is None:
        value = os.environ.get(name)
    if value is None or not str(value).strip():
        return False
    normalized = str(value).strip().lower()
    if normalized in _BOOL_TRUE:
        return True
    if normalized in _BOOL_FALSE:
        return False
    raise ConfigurationError(
        f"{name} must be true/false/1/0/yes/no (case-insensitive), got {value!r}. "
        "Fix the environment variable and restart the application or worker."
    )


def parse_subscription_service(value: str | None = None) -> str:
    """Return ``ON`` or ``OFF`` for ``SUBSCRIPTION_SERVICE``.

    Missing or blank values default to ``ON``. Any other value raises
    [[attestra/config.py#ConfigurationError]] so callers fail closed.
    """
    return _parse_on_off("SUBSCRIPTION_SERVICE", value)


def get_subscription_service() -> str:
    """Current ``SUBSCRIPTION_SERVICE`` value (``ON`` or ``OFF``), re-read from the environment."""
    return parse_subscription_service()


def subscription_enforcement_enabled() -> bool:
    """True when organization test-run credit limits must be enforced.

    When False (``SUBSCRIPTION_SERVICE=OFF``), credit balance checks and
    consumption are bypassed. Authentication, tenant isolation, scope
    validation, SSRF protections, signed-authorization rules, audit logging,
    and other non-subscription controls remain enforced.
    """
    return get_subscription_service() == "ON"


def parse_app_env(value: str | None = None) -> str | None:
    """Return normalized ``APP_ENV`` or ``None`` when unset/blank.

    Unknown non-empty values raise [[attestra/config.py#ConfigurationError]].
    """
    if value is None:
        value = os.environ.get("APP_ENV")
    if value is None or not str(value).strip():
        return None
    normalized = str(value).strip().lower()
    if normalized not in _APP_ENV_KNOWN:
        raise ConfigurationError(
            f"APP_ENV must be one of {sorted(_APP_ENV_KNOWN)}, got {value!r}. "
            "Fix the environment variable and restart the application or worker."
        )
    return normalized


def get_app_env() -> str | None:
    """Current ``APP_ENV`` (normalized) or ``None`` when unset."""
    return parse_app_env()


def parse_bypass_target_ownership_verification(value: str | None = None) -> bool:
    """Requested ownership bypass. Default **false** when unset."""
    return _parse_bool_default_false("BYPASS_TARGET_OWNERSHIP_VERIFICATION", value)


def parse_bypass_signed_authorization_verification(value: str | None = None) -> bool:
    """Requested signed-authorization bypass. Default **false** when unset."""
    return _parse_bool_default_false("BYPASS_SIGNED_AUTHORIZATION_VERIFICATION", value)


def ownership_bypass_active() -> bool:
    """True only when ownership bypass is requested and ``APP_ENV`` is allowlisted."""
    if not parse_bypass_target_ownership_verification():
        return False
    env = parse_app_env()
    return env in _APP_ENV_BYPASS_ALLOWLIST


def signed_authorization_bypass_active() -> bool:
    """True only when signed-auth bypass is requested and ``APP_ENV`` is allowlisted."""
    if not parse_bypass_signed_authorization_verification():
        return False
    env = parse_app_env()
    return env in _APP_ENV_BYPASS_ALLOWLIST


def ownership_verification_required() -> bool:
    """True when web/api/host targets must have ownership verified before scan.

    When False, only the local-testing ownership gate is skipped
    (``BYPASS_TARGET_OWNERSHIP_VERIFICATION`` in an allowlisted ``APP_ENV``).
    UI verify/confirm, token storage, and ownership audit stay available.
    Auth, tenant isolation, scope, SSRF, rate limits, and other controls remain enforced.
    Never fabricates ``ownership_verified_at``.
    """
    return not ownership_bypass_active()


def signed_authorization_required() -> bool:
    """True when imports/scans must have a currently valid signed authorization.

    When False, only the local-testing signed-authorization gates are skipped
    (``BYPASS_SIGNED_AUTHORIZATION_VERIFICATION`` in an allowlisted ``APP_ENV``).
    Document download RBAC, tenant isolation, ownership verification, SSRF,
    and audit stay enforced. UI may still record authorizations.
    """
    return not signed_authorization_bypass_active()


def validate_runtime_config() -> None:
    """Validate env-backed settings that must fail startup on error.

    Call from API lifespan and CLI serve/worker/init so API, workers,
    schedules, and CLI share one configuration path. Re-reads
    ``SUBSCRIPTION_SERVICE``, ``APP_ENV``, and both ``BYPASS_*`` flags.
    Bypass flags default to false; enabling them outside an allowlisted
    ``APP_ENV`` rejects startup.
    """
    global SUBSCRIPTION_SERVICE, APP_ENV
    global BYPASS_TARGET_OWNERSHIP_VERIFICATION, BYPASS_SIGNED_AUTHORIZATION_VERIFICATION

    SUBSCRIPTION_SERVICE = parse_subscription_service()
    APP_ENV = parse_app_env()
    own_req = parse_bypass_target_ownership_verification()
    auth_req = parse_bypass_signed_authorization_verification()
    BYPASS_TARGET_OWNERSHIP_VERIFICATION = own_req
    BYPASS_SIGNED_AUTHORIZATION_VERIFICATION = auth_req

    if own_req or auth_req:
        if APP_ENV is None:
            raise ConfigurationError(
                "BYPASS_* flags require APP_ENV to be set to an allowlisted value "
                f"({sorted(_APP_ENV_BYPASS_ALLOWLIST)}). Missing APP_ENV fails closed."
            )
        if APP_ENV in _APP_ENV_PROHIBITED_BYPASS:
            raise ConfigurationError(
                f"Bypass flags must not be enabled when APP_ENV={APP_ENV!r}. "
                "Set BYPASS_TARGET_OWNERSHIP_VERIFICATION and "
                "BYPASS_SIGNED_AUTHORIZATION_VERIFICATION to false in staging/production."
            )
        if APP_ENV not in _APP_ENV_BYPASS_ALLOWLIST:
            raise ConfigurationError(
                f"Bypass flags are not allowed for APP_ENV={APP_ENV!r}. "
                f"Allowlist: {sorted(_APP_ENV_BYPASS_ALLOWLIST)}."
            )


SUBSCRIPTION_SERVICE = parse_subscription_service()
APP_ENV = parse_app_env()
BYPASS_TARGET_OWNERSHIP_VERIFICATION = parse_bypass_target_ownership_verification()
BYPASS_SIGNED_AUTHORIZATION_VERIFICATION = parse_bypass_signed_authorization_verification()


def parse_ownership_verification(value: str | None = None) -> str:
    """Removed. Raises [[attestra/config.py#ConfigurationError]] directing callers to migrate."""
    raise ConfigurationError(_REMOVED_OWNERSHIP)


def get_ownership_verification() -> str:
    """Removed. Raises [[attestra/config.py#ConfigurationError]] directing callers to migrate."""
    raise ConfigurationError(_REMOVED_OWNERSHIP)


def parse_signed_authorization(value: str | None = None) -> str:
    """Removed. Raises [[attestra/config.py#ConfigurationError]] directing callers to migrate."""
    raise ConfigurationError(_REMOVED_SIGNED_AUTH)


def get_signed_authorization() -> str:
    """Removed. Raises [[attestra/config.py#ConfigurationError]] directing callers to migrate."""
    raise ConfigurationError(_REMOVED_SIGNED_AUTH)


def __getattr__(name: str):
    """Reject legacy ``OWNERSHIP_VERIFICATION`` / ``SIGNED_AUTHORIZATION`` module globals."""
    if name == "OWNERSHIP_VERIFICATION":
        raise ConfigurationError(_REMOVED_OWNERSHIP)
    if name == "SIGNED_AUTHORIZATION":
        raise ConfigurationError(_REMOVED_SIGNED_AUTH)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# Organization test-run credits (master Phase 2). Initial allocation is configurable.
INITIAL_TEST_RUN_CREDITS = max(0, int(os.environ.get("ATTESTRA_INITIAL_TEST_RUN_CREDITS", "3")))
# Refund a consumed credit when admission fails before the run is queued/dispatched.
CREDIT_REFUND_ON_PRE_START_FAILURE = os.environ.get(
    "ATTESTRA_CREDIT_REFUND_ON_PRE_START_FAILURE", "ON"
).strip().upper() in ("ON", "1", "TRUE", "YES")
# Do not auto-refund merely because a started scan later fails (explicit opt-in).
CREDIT_REFUND_ON_POST_START_FAILURE = os.environ.get(
    "ATTESTRA_CREDIT_REFUND_ON_POST_START_FAILURE", "OFF"
).strip().upper() in ("ON", "1", "TRUE", "YES")
