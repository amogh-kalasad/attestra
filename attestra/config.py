"""Runtime settings, read from environment variables."""

from __future__ import annotations

import os
from pathlib import Path

DATA_DIR = Path(os.environ.get("ATTESTRA_DATA_DIR", Path.cwd() / "data")).resolve()
DATABASE_URL = os.environ.get("ATTESTRA_DATABASE_URL", f"sqlite:///{DATA_DIR / 'attestra.db'}")

# Remediation SLA in days per severity. Critical within 30 days aligns with PCI DSS 6.3.3.
SLA_DAYS = {"critical": 30, "high": 60, "medium": 90, "low": 180, "info": None}

RAW_DIR = DATA_DIR / "raw"
SCANNER_TIMEOUT_S = int(os.environ.get("ATTESTRA_SCANNER_TIMEOUT_S", "600"))
SCAN_RATE_PER_ASSET = int(os.environ.get("ATTESTRA_SCAN_RATE_PER_ASSET", "10"))
JOB_MAX_ATTEMPTS = int(os.environ.get("ATTESTRA_JOB_MAX_ATTEMPTS", "3"))
JOB_STALE_HEARTBEAT_S = int(os.environ.get("ATTESTRA_JOB_STALE_HEARTBEAT_S", "120"))

API_KEY_PEPPER = os.environ.get("ATTESTRA_API_KEY_PEPPER", "attestra-dev-pepper-change-me")
SESSION_SECRET = os.environ.get("ATTESTRA_SESSION_SECRET", "attestra-dev-session-change-me")
API_RATE_LIMIT = int(os.environ.get("ATTESTRA_API_RATE_LIMIT", "120"))

OIDC_ENABLED = os.environ.get("ATTESTRA_OIDC_ENABLED", "").lower() in ("1", "true", "yes")
OIDC_ISSUER = os.environ.get("ATTESTRA_OIDC_ISSUER", "")
OIDC_CLIENT_ID = os.environ.get("ATTESTRA_OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = os.environ.get("ATTESTRA_OIDC_CLIENT_SECRET", "")

# Digests must include @sha256:. Replace VERIFY placeholders after `docker inspect` when pinning real images.
SCANNER_IMAGES = {
    "zap": os.environ.get(
        "ATTESTRA_IMAGE_ZAP",
        "ghcr.io/zaproxy/zaproxy@sha256:0000000000000000000000000000000000000000000000000000000000000001",
    ),
    "trivy": os.environ.get(
        "ATTESTRA_IMAGE_TRIVY",
        "ghcr.io/aquasecurity/trivy@sha256:0000000000000000000000000000000000000000000000000000000000000002",
    ),
    "nuclei": os.environ.get(
        "ATTESTRA_IMAGE_NUCLEI",
        "docker.io/projectdiscovery/nuclei@sha256:0000000000000000000000000000000000000000000000000000000000000003",
    ),
    "semgrep": os.environ.get(
        "ATTESTRA_IMAGE_SEMGREP",
        "docker.io/returntocorp/semgrep@sha256:0000000000000000000000000000000000000000000000000000000000000004",
    ),
}


def ensure_dirs() -> None:
    for sub in ("evidence", "imports", "reports", "keys", "raw", "tenants"):
        (DATA_DIR / sub).mkdir(parents=True, exist_ok=True)


def require_image_digest(image: str) -> str:
    """Refuse floating tags; every scanner image must be digest-pinned."""
    if "@sha256:" not in image:
        raise ValueError(f"scanner image must be pinned with @sha256: digest, got {image!r}")
    return image
