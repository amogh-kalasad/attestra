"""Map findings to OWASP Top 10, ASVS, and WSTG references."""
# @lat: [[compliance#OWASP references]]

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

DATA = Path(__file__).parent / "data"


@lru_cache(maxsize=1)
def _catalog() -> dict:
    return yaml.safe_load((DATA / "owasp.yaml").read_text(encoding="utf-8")) or {}


def get_asvs() -> dict[str, str]:
    """Return CWE → ASVS id map."""
    return {str(k): v.get("asvs", "") for k, v in (_catalog().get("cwe") or {}).items()}


def get_wstg() -> dict[str, str]:
    return {str(k): v.get("wstg", "") for k, v in (_catalog().get("cwe") or {}).items()}


def get_top10() -> dict[str, str]:
    return dict(_catalog().get("top10_2021") or {})


def map_finding_to_owasp(finding) -> dict[str, str]:
    """Return owasp_top10, asvs_ref, wstg_ref for a finding (by CWE)."""
    cwe = getattr(finding, "cwe", None)
    if not cwe:
        return {"owasp_top10": "", "asvs_ref": "", "wstg_ref": ""}
    entry = (_catalog().get("cwe") or {}).get(cwe) or (_catalog().get("cwe") or {}).get(str(cwe)) or {}
    top = entry.get("top10") or ""
    title = get_top10().get(top, "")
    label = f"{top}: {title}" if top and title else top
    return {
        "owasp_top10": label,
        "asvs_ref": entry.get("asvs") or "",
        "wstg_ref": entry.get("wstg") or "",
    }
