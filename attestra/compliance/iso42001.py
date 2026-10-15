"""ISO/IEC 42001:2023 pack helpers: check register, OWASP LLM Top 10 (2025) map, SoA draft.

The 42001 pack YAML carries per-ref check types, verification steps and an LLM Top 10 map next
to the usual controls/titles. The engine ignores those extra keys, so they are read here.
This is a readiness / reference view, not a certification (certification bodies follow
ISO/IEC 42006).
"""
# @lat: [[compliance]]

from __future__ import annotations

from functools import lru_cache

import yaml

from attestra.compliance import engine

FRAMEWORK = "iso_42001_2023"
CHECK_TYPES = ("tool", "evidence", "assessor")
STRENGTHS = ("full", "partial")
SOA_IMPLEMENTATION_MAP = {
    "met": "implemented",
    "no_exceptions": "implemented",
    "partial": "partial",
    "not_met": "not_implemented",
}


@lru_cache(maxsize=1)
def load_pack() -> dict:
    path = engine.DATA / "packs" / f"{FRAMEWORK}.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def clear_cache() -> None:
    load_pack.cache_clear()


def titles() -> dict[str, str]:
    return dict(load_pack().get("titles") or {})


def annex_a_refs() -> list[str]:
    return [r for r in titles() if r.startswith("A.")]


def clause_refs() -> list[str]:
    return [r for r in titles() if r.startswith("Clause ")]


def checks() -> dict[str, dict]:
    return dict(load_pack().get("checks") or {})


def llm_top10() -> dict[str, dict]:
    return dict(load_pack().get("llm_top10") or {})


def llm_ids_for_ref(ref: str) -> list[str]:
    return sorted(k for k, v in llm_top10().items() if ref in (v.get("controls") or []))


def check_register_rows(results) -> list[list]:
    """One row per control result: ref, title, status, proposed, check types, verification, LLM ids, CWEs."""
    chk = checks()
    llm = llm_top10()
    rows = []
    for r in results:
        c = chk.get(r.ref) or {}
        ids = llm_ids_for_ref(r.ref)
        cwes = sorted({int(w) for i in ids for w in (llm[i].get("cwe") or [])})
        rows.append([
            r.ref, r.title, r.status, r.proposed,
            "+".join(c.get("check_type") or []),
            " | ".join(c.get("verify") or []),
            ";".join(ids),
            ";".join(f"CWE-{w}" for w in cwes),
            ";".join(map(str, r.finding_ids)),
        ])
    return rows


CHECK_REGISTER_HEADER = [
    "ref", "title", "status", "proposed", "check_type", "verification", "owasp_llm_2025", "cwe", "finding_ids",
]
LLM_MAP_HEADER = ["id", "name", "controls", "cwe", "strength", "active_test", "rationale"]
SOA_DRAFT_HEADER = ["control_ref", "title", "applicable", "implementation", "justification", "basis"]


def llm_map_rows() -> list[list]:
    return [
        [k, v.get("name", ""), ";".join(v.get("controls") or []),
         ";".join(f"CWE-{w}" for w in (v.get("cwe") or [])), v.get("strength", ""),
         bool(v.get("active_test")), str(v.get("rationale") or "").strip()]
        for k, v in sorted(llm_top10().items())
    ]


def soa_draft_rows(results) -> list[list]:
    """Statement of Applicability draft (clause 6.1.3) for the 38 Annex A controls.

    Built from the current roll-up, not stored: the persisted SoA table is keyed by
    (engagement, control_ref) with no framework column, and 42001 refs such as A.8.3 clash
    with ISO 27001 refs, so editable 42001 SoA rows need a schema change (see docs/ISO_42001.md).
    """
    rows = []
    for r in results:
        if not r.ref.startswith("A."):
            continue
        st = r.status
        applicable = st != "not_applicable"
        rows.append([
            r.ref, r.title, applicable,
            SOA_IMPLEMENTATION_MAP.get(st, "planned") if applicable else "not_implemented",
            "" if applicable else (r.rationale or "Not applicable"),
            r.rationale if r.confirmed else r.reason,
        ])
    return rows