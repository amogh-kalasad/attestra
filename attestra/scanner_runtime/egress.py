"""Target-bound egress helpers for native (shared-venv) scanner runs.

A shared process / venv is not network isolation. Adapters may call these
helpers before spawning a scanner so the pinned destination is re-checked and
subprocess env does not inherit host secrets. HTTP_PROXY alone is not enough.
"""
# @lat: [[aasi#V5.1 native target-bound egress]]

from __future__ import annotations

import os
import re
from typing import Mapping

from attestra.runner.authorization import AuthorizationError, validate_resolved_ips
from attestra.runner.dns_pin import PinnedTarget

# Keys / prefixes never passed into a scanner subprocess (host credentials).
_SECRET_ENV_EXACT = frozenset(
    {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_SECURITY_TOKEN",
        "AWS_DEFAULT_REGION",
        "AWS_REGION",
        "AWS_PROFILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_CONFIG_FILE",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "MONGO_URI",
        "MONGODB_URI",
        "MONGO_URL",
        "MONGODB_URL",
        "ATTESTRA_MONGO_URI",
        "ATTESTRA_MONGODB_URI",
        "ATTESTRA_SESSION_SECRET",
        "ATTESTRA_SESSION",
    }
)

_SECRET_ENV_PREFIXES = (
    "AWS_",
    "MONGO",
    "MONGODB",
    "ATTESTRA_SESSION",
)

_SECRET_SUBSTRING = re.compile(
    r"(SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|APIKEY|CREDENTIAL|PRIVATE_KEY)",
    re.IGNORECASE,
)

# Enough for the child to start; not a substitute for network isolation.
_SYSTEM_ESSENTIALS = frozenset(
    {
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "WINDIR",
        "COMSPEC",
        "TEMP",
        "TMP",
        "TMPDIR",
        "HOME",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "APPDATA",
        "LOCALAPPDATA",
        "USER",
        "USERNAME",
        "LOGNAME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TZ",
        "TERM",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "PYTHONPATH",
        "VIRTUAL_ENV",
        "NUMBER_OF_PROCESSORS",
        "PROCESSOR_ARCHITECTURE",
        "OS",
        "HOMEBREW_PREFIX",
    }
)


def _pin_missing(pinned: PinnedTarget | None) -> bool:
    if pinned is None:
        return True
    host = (getattr(pinned, "host", None) or "").strip()
    ip = (getattr(pinned, "ip", None) or "").strip()
    return not host or not ip


def assert_target_egress_allowed(pinned: PinnedTarget, *, allow_private: bool) -> None:
    """Refuse scanner start when the pin is missing or the pinned IP is blocked.

    Reuses ``validate_resolved_ips`` so cloud metadata / CGNAT / link-local
    ranges stay denied even when ``allow_private`` is true. Does not authorize
    engagement scope by itself — call after the gate pin.
    """
    if _pin_missing(pinned):
        raise AuthorizationError("egress refused: pinned target missing")
    validate_resolved_ips([pinned.ip], allow_private=allow_private)


def _is_secret_env_key(key: str) -> bool:
    if key in _SECRET_ENV_EXACT:
        return True
    upper = key.upper()
    for prefix in _SECRET_ENV_PREFIXES:
        if upper.startswith(prefix):
            return True
    if _SECRET_SUBSTRING.search(key):
        return True
    return False


def _keep_env_key(key: str) -> bool:
    """True when a parent env key may be copied into the scanner env."""
    if _is_secret_env_key(key):
        return False
    if key in _SYSTEM_ESSENTIALS:
        return True
    # Non-secret Attestra config (images, timeouts, flags) for adapters.
    if key.startswith("ATTESTRA_"):
        return True
    return False


def scanner_process_env(*, extra: dict | None = None, base: Mapping[str, str] | None = None) -> dict:
    """Build a sanitized env dict for a native scanner subprocess.

    Strips AWS / Mongo / ``ATTESTRA_SESSION*`` and other secret-shaped keys from
    ``base`` (default ``os.environ``), keeps PATH and common system essentials,
    sets ``ATTESTRA_SCANNER_JOB=1``, then applies ``extra`` (also secret-stripped).
    """
    src = os.environ if base is None else base
    out: dict[str, str] = {}
    for key, value in src.items():
        if value is None or not _keep_env_key(key):
            continue
        out[key] = str(value)

    out["ATTESTRA_SCANNER_JOB"] = "1"

    if extra:
        for key, value in extra.items():
            k = str(key)
            if value is None or _is_secret_env_key(k):
                continue
            out[k] = str(value)
        out["ATTESTRA_SCANNER_JOB"] = "1"

    return out
