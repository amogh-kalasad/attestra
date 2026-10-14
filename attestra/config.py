"""Runtime settings, read from environment variables."""

from __future__ import annotations

import os
from pathlib import Path

DATA_DIR = Path(os.environ.get("ATTESTRA_DATA_DIR", Path.cwd() / "data")).resolve()
DATABASE_URL = os.environ.get("ATTESTRA_DATABASE_URL", f"sqlite:///{DATA_DIR / 'attestra.db'}")

# Remediation SLA in days per severity. Critical within 30 days aligns with PCI DSS 6.3.3.
SLA_DAYS = {"critical": 30, "high": 60, "medium": 90, "low": 180, "info": None}


def ensure_dirs() -> None:
    for sub in ("evidence", "imports", "reports", "keys"):
        (DATA_DIR / sub).mkdir(parents=True, exist_ok=True)
