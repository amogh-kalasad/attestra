"""Confidence-based cross-tool finding consolidation (master Phase 6).

Exact fingerprint matches remain authoritative. Soft matches merge only at high
confidence; ambiguous pairs stay separate and are flagged for review.
"""
# @lat: [[findings#Deduplication#Cross-tool deduplication]]

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from attestra.fingerprint import normalize_location, normalize_title

# Display names for "Detected by" (keys stay stored as importer tool ids).
TOOL_DISPLAY_NAMES = {
    "zap": "OWASP ZAP",
    "nuclei": "Nuclei",
    "trivy": "Trivy",
    "semgrep": "Semgrep",
    "sarif": "SARIF",
    "testssl": "testssl.sh",
    "webcheck": "webcheck",
    "gitleaks": "Gitleaks",
    "checkov": "Checkov",
    "naabu": "naabu",
    "prowler": "Prowler",
    "kube_bench": "kube-bench",
    "burp": "Burp",
    "nessus": "Nessus",
    "observatory": "Observatory",
    "ssllabs": "SSL Labs",
    "cyclonedx": "CycloneDX",
    "dependency_track": "Dependency-Track",
}

MERGE_THRESHOLD = 0.85
AMBIGUOUS_THRESHOLD = 0.55


@dataclass(frozen=True)
class MatchResult:
    confidence: float
    rationale: str
    finding: Any | None = None  # Finding row when matched


def tool_display_name(tool: str) -> str:
    key = (tool or "").strip().lower()
    return TOOL_DISPLAY_NAMES.get(key, tool or "unknown")


def detected_by_label(tools: list[str] | None) -> str:
    names = [tool_display_name(t) for t in (tools or []) if t]
    return ", ".join(names) if names else "—"


def _bare_location(location: str) -> str:
    """Strip trailing ` [param: …]` suffixes used on stored Finding.location."""
    loc = (location or "").strip()
    marker = " [param:"
    if marker in loc:
        loc = loc.split(marker, 1)[0].strip()
    return loc


def _host_only(location: str) -> str:
    loc = normalize_location(_bare_location(location))
    if "://" in loc:
        return urlsplit(loc).netloc.lower()
    return loc.split("/")[0].lower()


def score_observation_against_finding(
    *,
    tool: str,
    location: str,
    cwe: int | None,
    cves: list[str],
    title: str,
    param: str = "",
    package: str = "",
    asset_id: int | None,
    finding: Any,
) -> MatchResult:
    """Score how likely an observation is the same underlying issue as ``finding``.

    Does not merge on title, CVE, CWE, severity, or hostname alone.
    """
    score = 0.0
    reasons: list[str] = []

    f_loc = normalize_location(_bare_location(finding.location or ""))
    o_loc = normalize_location(location or "")
    same_loc = bool(o_loc and f_loc and o_loc == f_loc)
    same_host = bool(_host_only(location) and _host_only(location) == _host_only(finding.location or ""))

    if asset_id is not None and finding.asset_id is not None:
        if asset_id == finding.asset_id:
            score += 0.15
            reasons.append("same_asset")
        else:
            return MatchResult(0.0, "different_asset", finding)

    f_cves = {str(c).upper() for c in (finding.cves or [])}
    o_cves = {str(c).upper() for c in (cves or [])}
    cve_hit = bool(f_cves & o_cves)

    f_param = ""
    if " [param:" in (finding.location or ""):
        f_param = (finding.location or "").split(" [param:", 1)[1].rstrip("]").strip().lower()
    # Prefer explicit param from observation; finding may only encode it in location.
    o_param = (param or "").strip().lower()

    f_pkg = (package or "").strip().lower()  # observation package
    # Package often lives on the finding location for SCA rows.
    finding_pkg = ""
    if "@" in (finding.location or ""):
        finding_pkg = (finding.location or "").split("@")[-1].split(":")[0].lower()

    if cve_hit and same_loc:
        score += 0.55
        reasons.append("cve_and_location")
    elif cve_hit and (f_pkg and finding_pkg and f_pkg == finding_pkg):
        score += 0.55
        reasons.append("cve_and_package")
    elif cve_hit and same_host and (f_pkg and finding_pkg and f_pkg == finding_pkg):
        score += 0.5
        reasons.append("cve_package_host")
    elif cve_hit and not same_loc and not (f_pkg and finding_pkg):
        # CVE alone is insufficient.
        score += 0.2
        reasons.append("cve_only")

    if cwe and finding.cwe and int(cwe) == int(finding.cwe):
        if same_loc:
            score += 0.35
            reasons.append("cwe_and_location")
        else:
            score += 0.1
            reasons.append("cwe_only")

    if o_param or f_param:
        if o_param and f_param and o_param == f_param and same_loc:
            score += 0.25
            reasons.append("same_param")
        elif o_param and f_param and o_param != f_param:
            score -= 0.35
            reasons.append("different_param")

    # Cross-tool same CWE+location+param is the ZAP/Nuclei SQLi case.
    tools = [str(t).lower() for t in (finding.tools or [])]
    if tool and tool.lower() not in tools and same_loc and cwe and finding.cwe and int(cwe) == int(finding.cwe):
        if (not o_param and not f_param) or (o_param and f_param and o_param == f_param):
            score += 0.2
            reasons.append("cross_tool")

    if same_loc and normalize_title(title) == normalize_title(finding.title or ""):
        score += 0.1
        reasons.append("same_title_location")
    elif same_host and normalize_title(title) == normalize_title(finding.title or ""):
        score += 0.05
        reasons.append("same_title_host")

    score = max(0.0, min(1.0, score))
    rationale = "+".join(reasons) if reasons else "no_signals"
    return MatchResult(score, rationale, finding)


def find_best_soft_match(
    *,
    engagement_findings: list[Any],
    tool: str,
    location: str,
    cwe: int | None,
    cves: list[str],
    title: str,
    param: str = "",
    package: str = "",
    asset_id: int | None,
) -> MatchResult:
    """Best soft match among existing engagement findings (excludes exact-fp path)."""
    best = MatchResult(0.0, "none", None)
    for f in engagement_findings:
        got = score_observation_against_finding(
            tool=tool,
            location=location,
            cwe=cwe,
            cves=cves,
            title=title,
            param=param,
            package=package,
            asset_id=asset_id,
            finding=f,
        )
        if got.confidence > best.confidence:
            best = got
    return best


def classify_match(confidence: float) -> str:
    if confidence >= MERGE_THRESHOLD:
        return "merge"
    if confidence >= AMBIGUOUS_THRESHOLD:
        return "ambiguous"
    return "new"


def _param_from_stored_location(location: str) -> str:
    loc = location or ""
    marker = " [param:"
    if marker not in loc:
        return ""
    return loc.split(marker, 1)[1].rstrip("]").strip()


def suggest_historical_duplicates(findings: list[Any]) -> list[dict[str, Any]]:
    """Non-destructive scan for probable historical duplicates within one engagement.

    Returns suggestion rows only; never merges or deletes.
    """
    suggestions: list[dict[str, Any]] = []
    rows = list(findings)
    for i, a in enumerate(rows):
        for b in rows[i + 1 :]:
            if set(a.tools or []) & set(b.tools or []):
                continue  # same tool pair — leave alone
            got = score_observation_against_finding(
                tool=(b.tools or ["?"])[0],
                location=_bare_location(b.location or ""),
                cwe=b.cwe,
                cves=list(b.cves or []),
                title=b.title or "",
                param=_param_from_stored_location(b.location or ""),
                package="",
                asset_id=b.asset_id,
                finding=a,
            )
            kind = classify_match(got.confidence)
            if kind == "new":
                continue
            suggestions.append(
                {
                    "finding_a_id": a.id,
                    "finding_b_id": b.id,
                    "confidence": round(got.confidence, 3),
                    "rationale": got.rationale,
                    "action": "merge_candidate" if kind == "merge" else "review",
                    "tools_a": list(a.tools or []),
                    "tools_b": list(b.tools or []),
                }
            )
    suggestions.sort(key=lambda r: (-r["confidence"], r["finding_a_id"], r["finding_b_id"]))
    return suggestions
