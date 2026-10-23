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


def get_llm_top10() -> dict[str, str]:
    """OWASP Top 10 for LLM Applications 2025: id -> name."""
    return dict(_catalog().get("llm_top10_2025") or {})


def top10_category_id(label: str) -> str:
    """Extract A01–A10 (or LLM01–LLM10) from a finding OWASP label."""
    text = (label or "").strip()
    if not text:
        return ""
    token = text.split(":", 1)[0].strip().upper()
    if token.startswith("A") and len(token) >= 2 and token[1:3].isdigit():
        return token[:3]
    if token.startswith("LLM") and len(token) >= 5 and token[3:5].isdigit():
        return token[:5]
    return token


def group_findings_by_top10(findings) -> list[dict]:
    """Group findings under OWASP Top 10 2021 categories for the report view.

    Categories follow ``top10_2021`` order. Findings without a mapped Top 10 id
    land in an Unmapped group at the end.
    """
    catalog = get_top10()
    buckets: dict[str, list] = {cid: [] for cid in catalog}
    unmapped: list = []
    for f in findings:
        cid = top10_category_id(getattr(f, "owasp_top10", "") or "")
        if cid in buckets:
            buckets[cid].append(f)
        else:
            unmapped.append(f)
    groups = [
        {"id": cid, "title": title, "heading": f"{cid}: {title}", "findings": buckets[cid]}
        for cid, title in catalog.items()
    ]
    if unmapped:
        groups.append(
            {"id": "", "title": "Unmapped", "heading": "Unmapped", "findings": unmapped}
        )
    return groups


def should_show_llm_top10(frameworks=None, findings=None) -> bool:
    """True when ISO 42001 is in scope or AI-related findings are present."""
    fws = {str(x) for x in (frameworks or [])}
    if "iso_42001_2023" in fws:
        return True
    for f in findings or []:
        cwe = getattr(f, "cwe", None)
        if cwe in (1427, 77, 400, 770):
            return True
        title = (getattr(f, "title", "") or "").lower()
        if "prompt injection" in title or "llm" in title:
            return True
    return False


def group_findings_by_llm_top10(findings) -> list[dict]:
    """Optional LLM Top 10 2025 groups using catalog ids and iso42001 CWE maps."""
    catalog = get_llm_top10()
    cwe_to_ids: dict[int, list[str]] = {}
    try:
        from attestra.compliance import iso42001

        for lid, meta in iso42001.llm_top10().items():
            for w in meta.get("cwe") or []:
                cwe_to_ids.setdefault(int(w), []).append(str(lid))
    except Exception:
        pass
    buckets: dict[str, list] = {cid: [] for cid in catalog}
    for f in findings or []:
        cwe = getattr(f, "cwe", None)
        ids = cwe_to_ids.get(int(cwe), []) if cwe else []
        for lid in ids:
            if lid in buckets:
                buckets[lid].append(f)
    return [
        {
            "id": cid,
            "title": title,
            "heading": f"{cid}: {title}",
            "findings": buckets[cid],
        }
        for cid, title in catalog.items()
    ]


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
