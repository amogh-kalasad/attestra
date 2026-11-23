"""Runtime settings, read from environment variables."""

from __future__ import annotations

import os
from pathlib import Path

DATA_DIR = Path(os.environ.get("ATTESTRA_DATA_DIR", Path.cwd() / "data")).resolve()

# Google Safe Browsing (webcheck). Off by default; needs both flag and API key.
# ATTESTRA_GSB_ENABLED=1 and ATTESTRA_GSB_API_KEY=... — key is never logged or stored.

# Runtime is MongoDB only. ATTESTRA_PERSISTENCE is retained for older deploy env files.
PERSISTENCE_BACKEND = os.environ.get("ATTESTRA_PERSISTENCE", "mongo").strip().lower() or "mongo"
MONGODB_URI = os.environ.get("ATTESTRA_MONGODB_URI", "mongodb://127.0.0.1:27017/?replicaSet=rs0")
MONGODB_DB = os.environ.get("ATTESTRA_MONGODB_DB", "attestra")

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

API_KEY_PEPPER = os.environ.get("ATTESTRA_API_KEY_PEPPER", "attestra-dev-pepper-change-me")  # K-04: default refused in staging/production
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

# Default durable artifact store follows persistence: GridFS when mongo, else local files.
_STORAGE_DEFAULT = "mongo" if PERSISTENCE_BACKEND == "mongo" else "local"
STORAGE_BACKEND = os.environ.get("ATTESTRA_STORAGE", _STORAGE_DEFAULT)
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
    # WP4 passive discovery (VERIFY: replace with real digests after `docker inspect`).
    "subfinder": "docker.io/projectdiscovery/subfinder@sha256:0000000000000000000000000000000000000000000000000000000000000009",
    "dnsx": "docker.io/projectdiscovery/dnsx@sha256:000000000000000000000000000000000000000000000000000000000000000a",
    "httpx": "docker.io/projectdiscovery/httpx@sha256:000000000000000000000000000000000000000000000000000000000000000b",
    # AASI AI scanners — all-zero digests refused until ops pins real images.
    # Build: docker/aasi/Dockerfiles; Promptfoo: ghcr.io/promptfoo/promptfoo (see docker/aasi/README.md).
    "garak": "attestra/garak@sha256:000000000000000000000000000000000000000000000000000000000000000c",
    "promptfoo": "ghcr.io/promptfoo/promptfoo@sha256:000000000000000000000000000000000000000000000000000000000000000d",
    "safelabs": "attestra/safelabs@sha256:000000000000000000000000000000000000000000000000000000000000000e",
    "pyrit": "attestra/pyrit-worker@sha256:000000000000000000000000000000000000000000000000000000000000000f",
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


# AASI (Attestra Agentic Security Intelligence). Off by default.
# When off, AASI routes must not expose reasoning; deterministic workflows unchanged.
AASI_ENABLED = os.environ.get("ATTESTRA_AASI", "off").strip().lower() in ("1", "true", "yes", "on")
AASI_MAX_ITERATIONS = int(os.environ.get("ATTESTRA_AASI_MAX_ITERATIONS", "8"))
AASI_MAX_TASKS = int(os.environ.get("ATTESTRA_AASI_MAX_TASKS", "32"))
AASI_MAX_MODEL_CALLS = int(os.environ.get("ATTESTRA_AASI_MAX_MODEL_CALLS", "40"))
AASI_MAX_TOKENS = int(os.environ.get("ATTESTRA_AASI_MAX_TOKENS", "50000"))
AASI_MAX_WALL_CLOCK_S = int(os.environ.get("ATTESTRA_AASI_MAX_WALL_CLOCK_S", "1800"))
AASI_RETRY_LIMIT = int(os.environ.get("ATTESTRA_AASI_RETRY_LIMIT", "2"))
AASI_REQUIRE_APPROVAL = os.environ.get("ATTESTRA_AASI_REQUIRE_APPROVAL", "on").strip().lower() not in (
    "0",
    "false",
    "no",
    "off",
)

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

# Body-level write mutation (T22 POST/PUT/PATCH object-id swaps). Off by default.
# Sends only occur when this is on AND APP_ENV is local/test/development.
AUTOMATED_VAPT_MUTATION = os.environ.get("ATTESTRA_AUTOMATED_VAPT_MUTATION", "0").lower() in (
    "1",
    "true",
    "yes",
)


def _flag(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


# --- Upgrade INT (WP1-WP4). Every new feature flag is OFF by default. ---------------------------
# Intrusive tests (SSRF / UPLOAD / XSSSTORE / T22) are decided by the *target asset's* environment,
# never by APP_ENV. Allowed environments default to dev,demo; "production" is rejected at startup.
INTRUSIVE_ALLOWED_ENVIRONMENTS_RAW = os.environ.get("ATTESTRA_INTRUSIVE_ALLOWED_ENVIRONMENTS", "dev,demo")
# Parsed by validate_runtime_config(); until then intrusive_policy falls back to the env var.
INTRUSIVE_ALLOWED_ENVIRONMENTS: frozenset[str] | None = None
AUTOMATED_VAPT_SSRF = _flag("ATTESTRA_AUTOMATED_VAPT_SSRF")
AUTOMATED_VAPT_UPLOAD = _flag("ATTESTRA_AUTOMATED_VAPT_UPLOAD")
AUTOMATED_VAPT_STORED_XSS = _flag("ATTESTRA_AUTOMATED_VAPT_STORED_XSS")
# enforce (default): non-VALID cases never PASS and confirmed findings are capped to POTENTIAL.
# observe: compute and display validity only. ATTESTRA_RUN_VALIDITY is accepted as an alias.
RUN_VALIDITY_MODE = (
    os.environ.get("ATTESTRA_RUN_VALIDITY_MODE") or os.environ.get("ATTESTRA_RUN_VALIDITY") or "enforce"
).strip().lower()
if RUN_VALIDITY_MODE not in ("enforce", "observe"):
    RUN_VALIDITY_MODE = "enforce"
PLANNER_ENABLED = _flag("ATTESTRA_AUTOMATED_VAPT_PLANNER")
GUIDED_PLANS_ENABLED = _flag("ATTESTRA_GUIDED_PLANS")
# WP2 safe web/API probes.
PROBES_WEB_SAFE = _flag("ATTESTRA_PROBES_WEB_SAFE")
API_IMPORT_ENABLED = _flag("ATTESTRA_API_IMPORT_ENABLED")
GRAPHQL_PROBE = _flag("ATTESTRA_GRAPHQL_PROBE")
# WP4 attack surface / operations. TENANT_STRICT must stay off until the system call sites use
# SYSTEM_SCOPE (done by INT) and the operator has verified admin views.
DISCOVERY_ENABLED = _flag("ATTESTRA_DISCOVERY_ENABLED", "")
TENANT_STRICT = _flag("ATTESTRA_TENANT_STRICT", "")
MAINTENANCE_ENABLED = _flag("ATTESTRA_MAINTENANCE_ENABLED", "")
# WP3 threat-intel scheduled refresh (runs from the maintenance tick).
INTEL_AUTO_REFRESH = _flag("ATTESTRA_INTEL_AUTO_REFRESH", "")

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

    validate_intrusive_allowlist()
    validate_default_secrets(APP_ENV)


_DEFAULT_API_KEY_PEPPER = "attestra-dev-pepper-change-me"
_DEFAULT_SESSION_SECRET = "attestra-dev-session-change-me"


def validate_intrusive_allowlist(raw: str | None = None) -> frozenset[str]:
    """Parse ``ATTESTRA_INTRUSIVE_ALLOWED_ENVIRONMENTS``; ``production`` fails startup (FND-02)."""
    global INTRUSIVE_ALLOWED_ENVIRONMENTS, INTRUSIVE_ALLOWED_ENVIRONMENTS_RAW
    from attestra.automated_vapt.core.intrusive_policy import AllowlistError, parse_allowed_environments

    if raw is None:
        raw = os.environ.get("ATTESTRA_INTRUSIVE_ALLOWED_ENVIRONMENTS", "dev,demo")
    try:
        envs = parse_allowed_environments(raw)
    except AllowlistError as exc:
        INTRUSIVE_ALLOWED_ENVIRONMENTS = frozenset()  # fail closed even if the caller swallows the error
        raise ConfigurationError(str(exc)) from exc
    INTRUSIVE_ALLOWED_ENVIRONMENTS_RAW = raw
    INTRUSIVE_ALLOWED_ENVIRONMENTS = envs
    return envs


def validate_default_secrets(app_env: str | None = None) -> None:
    """K-04: the built-in dev pepper / session secret are refused when APP_ENV is staging/production.

    Only compares against the public default strings; never logs or returns the configured values.
    """
    env = app_env if app_env is not None else parse_app_env()
    if env not in _APP_ENV_PROHIBITED_BYPASS:
        return
    bad: list[str] = []
    if os.environ.get("ATTESTRA_API_KEY_PEPPER", _DEFAULT_API_KEY_PEPPER) == _DEFAULT_API_KEY_PEPPER:
        bad.append("ATTESTRA_API_KEY_PEPPER")
    if os.environ.get("ATTESTRA_SESSION_SECRET", _DEFAULT_SESSION_SECRET) == _DEFAULT_SESSION_SECRET:
        bad.append("ATTESTRA_SESSION_SECRET")
    if bad:
        raise ConfigurationError(
            f"{', '.join(bad)} still use the built-in development default while APP_ENV={env!r}. "
            "Set strong unique values and restart the application or worker."
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
