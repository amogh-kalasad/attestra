"""Resolve finding concepts to Phase 7 remediation packs and format text."""

from __future__ import annotations

from typing import Any

from attestra.remediation.packs import REMEDIATION_PACKS, Pack, pack_for_concept

# @lat: [[findings#Remediation packs (Phase 7)]]

_CSP_CONCEPTS = frozenset({"header:csp-missing", "header:csp-weak"})
_PERMISSIONS_TITLE_MARKERS = (
    "permissions-policy",
    "permissions policy",
    "feature-policy",
    "feature policy",
)

_MARKDOWN_SECTIONS = (
    ("Root cause", "root_cause"),
    ("Recommended fix", "recommended_fix"),
    ("Configuration examples", "config_examples"),
    ("Code example", "code_example"),
    ("Compatibility", "compatibility"),
    ("Verification steps", "verification_steps"),
    ("Retest instructions", "retest_instructions"),
)


def _title_of(finding: Any) -> str:
    return str(getattr(finding, "title", None) or "").strip()


def _title_looks_like_permissions_policy(title: str) -> bool:
    low = title.lower()
    return any(m in low for m in _PERMISSIONS_TITLE_MARKERS)


def _concepts_from_crossmerge(finding: Any) -> list[str]:
    """Use crossmerge.concepts_for when the finding looks like a scanner row."""
    try:
        from attestra.crossmerge import concepts_for
    except Exception:
        return []
    tools = getattr(finding, "tools", None) or []
    rule_ids = getattr(finding, "rule_ids", None) or []
    if not tools and not rule_ids and not getattr(finding, "rule_id", None):
        # Still allow title-only rows through concepts_for (empty → frozenset).
        pass
    try:
        return sorted(concepts_for(finding, []))
    except Exception:
        return []


def _concepts_from_title(title: str) -> list[str]:
    """Match pack title_match substrings (longest / most specific first)."""
    if not title:
        return []
    low = title.lower()
    scored: list[tuple[int, str]] = []
    for concept, pack in REMEDIATION_PACKS.items():
        best = 0
        for substr in pack.get("title_match") or []:
            s = str(substr).lower()
            if s and s in low:
                best = max(best, len(s))
        if best:
            scored.append((best, concept))
    scored.sort(key=lambda t: (-t[0], t[1]))
    return [c for _, c in scored]


def resolve_concepts(finding: Any) -> list[str]:
    """Return concept keys for a finding (crossmerge first, then title patterns)."""
    found: list[str] = []
    seen: set[str] = set()
    for key in _concepts_from_crossmerge(finding) + _concepts_from_title(_title_of(finding)):
        if key not in seen:
            seen.add(key)
            found.append(key)
    title = _title_of(finding)
    if _title_looks_like_permissions_policy(title):
        # Never attribute CSP concepts to Permissions-Policy findings.
        found = [c for c in found if c not in _CSP_CONCEPTS]
        if "header:permissions-policy-missing" not in found:
            found.insert(0, "header:permissions-policy-missing")
    return found


def _filter_csp_for_permissions(title: str, concepts: list[str]) -> list[str]:
    if _title_looks_like_permissions_policy(title):
        return [c for c in concepts if c not in _CSP_CONCEPTS]
    return concepts


def pack_for_finding(finding: Any) -> Pack | None:
    """Pick the best remediation pack for a finding, or None.

    Prefers a single exact concept that has a pack. Never returns a CSP pack
    for Permissions-Policy titles (ENG1 F-7 class mismatch).
    """
    title = _title_of(finding)
    concepts = _filter_csp_for_permissions(title, resolve_concepts(finding))

    if _title_looks_like_permissions_policy(title):
        pack = pack_for_concept("header:permissions-policy-missing")
        if pack is not None:
            return pack

    with_packs = [c for c in concepts if c in REMEDIATION_PACKS]
    if len(with_packs) == 1:
        return pack_for_concept(with_packs[0])
    if len(with_packs) > 1:
        # Prefer the first concept from crossmerge/title ranking that is registered.
        return pack_for_concept(with_packs[0])

    # Title-only fallback already folded into resolve_concepts; nothing left.
    return None


def format_remediation_markdown(pack: Pack | None) -> str:
    """Compose the seven remediation sections as Markdown."""
    if not pack:
        return ""
    lines: list[str] = []
    concept = pack.get("concept") or ""
    if concept:
        lines.extend([f"## Remediation (`{concept}`)", ""])
    for heading, key in _MARKDOWN_SECTIONS:
        lines.append(f"### {heading}")
        lines.append("")
        value = pack.get(key)
        if key == "config_examples" and isinstance(value, dict):
            if not value:
                lines.append("_None_")
            else:
                for server, snippet in value.items():
                    lines.append(f"**{server}**")
                    lines.append("")
                    lines.append("```")
                    lines.append(str(snippet).rstrip())
                    lines.append("```")
                    lines.append("")
            # trailing blank already added per snippet; keep section gap
            if lines and lines[-1] != "":
                lines.append("")
            continue
        text = str(value or "").strip() or "_None_"
        lines.append(text)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def remediation_for_finding(finding: Any) -> dict[str, Any]:
    """Return pack fields plus ``recommendation_text`` for legacy recommendation."""
    pack = pack_for_finding(finding)
    if pack is None:
        return {
            "concept": None,
            "recommendation_text": "",
            "root_cause": "",
            "recommended_fix": "",
            "config_examples": {},
            "code_example": "",
            "compatibility": "",
            "verification_steps": "",
            "retest_instructions": "",
        }
    out = dict(pack)
    md = format_remediation_markdown(pack)
    # Legacy recommendation field: concise fix + verification, not full config dump.
    parts = [
        str(pack.get("recommended_fix") or "").strip(),
        str(pack.get("verification_steps") or "").strip(),
    ]
    out["recommendation_text"] = "\n\n".join(p for p in parts if p)
    out["recommendation_markdown"] = md
    return out
