"""Cross-tool merge: present the same issue reported by different tools as one finding.

Rows are linked, never deleted. A related row gets ``merged_into_id`` pointing at the
group's primary row and keeps its own severity, status, evidence, comments and audit
history. Display code (engagement page, technical report, Markdown export) shows one
finding per group whose severity is the highest of the group, plus a Sources list with
each tool's own severity and evidence.

Matching is deliberately conservative. Two findings are linked only when they come from
different tools, sit on the same host (and the same target when both have one), and:

1. share a CVE id; or
2. map to the same well-known issue in :data:`CONCEPT_RULES` (missing security headers
   between ZAP, webcheck and nuclei; TLS/certificate issues between testssl and nuclei),
   with exactly one candidate per tool for that issue on that host; or
3. share a specific (non-generic) CWE and an overlapping URL path.

A group never holds two rows from the same tool, so two distinct ZAP rules can never be
chained together through a third tool.
"""
# @lat: [[findings#Deduplication#Cross-tool merge]]

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Iterable
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra.fingerprint import caa_host, normalize_location

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
FALSE_POSITIVE = "false_positive"

# CWEs shared by many unrelated checks; on their own they do not identify one issue.
GENERIC_CWES = frozenset(
    {16, 20, 200, 284, 285, 295, 296, 297, 298, 310, 311, 319, 326, 327, 345, 358, 524, 525, 693, 710}
)

# Tool labels: title case, acronyms and product spellings kept.
_TOOL_LABELS = {
    "zap": "ZAP",
    "nuclei": "Nuclei",
    "testssl": "Testssl",
    "naabu": "Naabu",
    "webcheck": "Webcheck",
    "trivy": "Trivy",
    "semgrep": "Semgrep",
    "gitleaks": "Gitleaks",
    "sarif": "SARIF",
    "checkov": "Checkov",
    "prowler": "Prowler",
    "kube_bench": "Kube-bench",
    "burp": "Burp",
    "nessus": "Nessus",
    "observatory": "Observatory",
    "ssllabs": "SSL Labs",
}

# Explicit equivalents. Each entry: concept key -> {tool: [(rule-id regex, title regex)]}.
# A finding maps to a concept when, for one of its tools, any (rule, title) pair matches
# (both regexes, case-insensitive; "" matches anything). Nuclei sub-checks are matched on
# "template:matcher" (observation original_id), e.g. http-missing-security-headers:x-frame-options.
_H = "http-missing-security-headers"
CONCEPT_RULES: dict[str, dict[str, list[tuple[str, str]]]] = {
    # --- Missing security headers (ZAP / webcheck / nuclei) ---
    "header:hsts-missing": {
        "zap": [(r"^10035$", r"strict-transport-security header not set")],
        "webcheck": [(r"^webcheck/hsts-present$", r"")],
        "nuclei": [(rf"^{_H}:strict-transport-security$", r"")],
    },
    "header:csp-missing": {
        "zap": [(r"^10038$", r"content security policy \(csp\) header not set")],
        "nuclei": [(rf"^{_H}:content-security-policy$", r"")],
    },
    "header:x-frame-options-missing": {
        "zap": [(r"^10020$", r"missing anti-clickjacking header")],
        "nuclei": [(rf"^{_H}:x-frame-options$", r"")],
    },
    "header:x-content-type-options-missing": {
        "zap": [(r"^10021$", r"x-content-type-options header missing")],
        "webcheck": [(r"^webcheck/x-content-type-options$", r"")],
        "nuclei": [(rf"^{_H}:x-content-type-options$", r"")],
    },
    "header:coep-missing": {
        "zap": [(r"^90004$", r"cross-origin-embedder-policy header missing")],
        "nuclei": [(rf"^{_H}:cross-origin-embedder-policy$", r"")],
    },
    "header:coop-missing": {
        "zap": [(r"^90004$", r"cross-origin-opener-policy header missing")],
        "nuclei": [(rf"^{_H}:cross-origin-opener-policy$", r"")],
    },
    "header:corp-missing": {
        "zap": [(r"^90004$", r"cross-origin-resource-policy header missing")],
        "nuclei": [(rf"^{_H}:cross-origin-resource-policy$", r"")],
    },
    # --- TLS / certificate (testssl / nuclei) ---
    "tls:sslv3-offered": {
        "testssl": [(r"^SSLv3$", r"")],
        "nuclei": [(r"^deprecated-tls:ssl_3\.0$", r"")],
    },
    "tls:tls1.0-offered": {
        "testssl": [(r"^TLS1$", r"")],
        "nuclei": [(r"^deprecated-tls:tls_1\.0$", r"")],
    },
    "tls:tls1.1-offered": {
        "testssl": [(r"^TLS1_1$", r"")],
        "nuclei": [(r"^deprecated-tls:tls_1\.1$", r"")],
    },
    "tls:cert-expired": {
        "testssl": [(r"^cert_(notAfter|expirationStatus)$", r"^tls: certificate expired$")],
        "webcheck": [(r"^webcheck/cert-expiry$", r"^tls: certificate expired$")],
        "nuclei": [(r"^expired-ssl$", r"")],
    },
    "tls:cert-untrusted": {
        "testssl": [(r"^cert_chain_of_trust$", r"")],
        "nuclei": [(r"^(self-signed-ssl|untrusted-root-certificate)$", r"")],
    },
    "tls:cert-hostname-mismatch": {
        "testssl": [(r"^cert_trust$", r"")],
        "nuclei": [(r"^mismatched-ssl-certificate$", r"")],
    },
    "tls:cert-revoked": {
        "testssl": [(r"^cert_(ocspRevoked|crlRevoked)$", r"")],
        "nuclei": [(r"^revoked-ssl-certificate$", r"")],
    },
}
# CSP weaknesses with identical semantics in ZAP 10055 and webcheck C10 titles.
_CSP_WEAK_TITLE = re.compile(r"^csp: ([a-z-]+) (unsafe-inline|unsafe-eval)$", re.IGNORECASE)
_CSP_WEAK_TOOLS = frozenset({"zap", "webcheck"})

_COMPILED = {
    concept: {
        tool: [(re.compile(r, re.IGNORECASE), re.compile(t, re.IGNORECASE)) for r, t in pairs]
        for tool, pairs in per_tool.items()
    }
    for concept, per_tool in CONCEPT_RULES.items()
}
_HOSTPORT = re.compile(r"^[a-z0-9.-]+(:\d{1,5})?$", re.IGNORECASE)


# ----------------------------------------------------------------- small helpers
def sev_rank(sev: str | None) -> int:
    return SEV_RANK.get((sev or "").strip().lower(), 0)


def title_case(word: str) -> str:
    w = (word or "").strip()
    return w[:1].upper() + w[1:].lower() if w else ""


def tool_label(tool: str) -> str:
    key = (tool or "").strip().lower()
    if key in _TOOL_LABELS:
        return _TOOL_LABELS[key]
    from attestra.dedup import tool_display_name

    name = tool_display_name(tool)
    return name[:1].upper() + name[1:] if name else "Unknown"


def _bare(location: str) -> str:
    loc = (location or "").strip()
    if " [param:" in loc:
        loc = loc.split(" [param:", 1)[0].strip()
    return loc


def site_key(location: str) -> str:
    """Lowercase hostname for a URL or ``host[:port]`` location; "" for files, images, etc."""
    loc = _bare(location)
    if not loc:
        return ""
    if "://" in loc:
        try:
            host = urlsplit(loc).hostname or ""
        except ValueError:
            return ""
        return host.lower().rstrip(".")
    if _HOSTPORT.match(loc) and "." in loc:
        return caa_host(loc).rstrip(".")
    return ""


def _url_path_keys(f: Any) -> set[str]:
    out: set[str] = set()
    urls = [f.location or ""]
    aff = getattr(f, "affected_urls", None) or []
    if not isinstance(aff, str):
        urls.extend(str(u) for u in aff)
    for u in urls:
        loc = _bare(u)
        if "://" not in loc:
            continue
        try:
            parts = urlsplit(loc)
        except ValueError:
            continue
        host = (parts.hostname or "").lower()
        path = parts.path.rstrip("/") or "/"
        out.add(f"{host}{path}")
    return out


def _rule_keys(f: Any, obs: list[Any]) -> list[tuple[str, str, str]]:
    """(tool, rule key, title) tuples from the finding and its observations."""
    keys: list[tuple[str, str, str]] = []
    tools = [str(t).lower() for t in (f.tools or [])]
    for o in obs:
        tool = (o.tool or "").lower()
        for rid in list(o.rule_ids or []) + ([o.original_id] if o.original_id else []):
            keys.append((tool, str(rid), o.title or f.title or ""))
    if not obs or len(tools) == 1:
        tool = tools[0] if tools else ""
        for rid in f.rule_ids or []:
            keys.append((tool, str(rid), f.title or ""))
        if not f.rule_ids:
            keys.append((tool, "", f.title or ""))
    return keys


def concepts_for(f: Any, obs: list[Any]) -> frozenset[str]:
    """Well-known issue keys this finding maps to (empty when it maps to none)."""
    found: set[str] = set()
    for tool, rid, title in _rule_keys(f, obs):
        for concept, per_tool in _COMPILED.items():
            for rx_rule, rx_title in per_tool.get(tool, []):
                if rx_rule.search(rid) and rx_title.search(title.strip()):
                    found.add(concept)
        if tool in _CSP_WEAK_TOOLS:
            m = _CSP_WEAK_TITLE.match(title.strip())
            if m:
                found.add(f"csp:{m.group(1).lower()}:{m.group(2).lower()}")
    return frozenset(found)


def _obs_by_finding(s: Session, ids: list[int]) -> dict[int, list[Any]]:
    from attestra.models import FindingObservation

    out: dict[int, list[Any]] = defaultdict(list)
    if not ids:
        return out
    for i in range(0, len(ids), 500):
        chunk = ids[i : i + 500]
        for o in s.scalars(
            select(FindingObservation)
            .where(FindingObservation.finding_id.in_(chunk))
            .order_by(FindingObservation.id)
        ):
            out[o.finding_id].append(o)
    return out


# ----------------------------------------------------------------- matching
class _Info:
    __slots__ = ("f", "tools", "site", "loc", "cves", "cwe", "paths", "concepts")

    def __init__(self, f: Any, obs: list[Any]):
        self.f = f
        self.tools = frozenset(str(t).lower() for t in (f.tools or []) if t)
        self.site = site_key(f.location or "")
        self.loc = normalize_location(_bare(f.location or "")).lower()
        self.cves = frozenset(str(c).upper() for c in (f.cves or []) if c)
        self.cwe = f.cwe
        self.paths = _url_path_keys(f)
        self.concepts = concepts_for(f, obs)


def match_reason(a: _Info, b: _Info, ambiguous: set[tuple[str, str, str]] | None = None) -> tuple[int, str] | None:
    """(strength, rationale) when ``a`` and ``b`` are the same issue; None otherwise.

    Lower strength is stronger: 0 = CVE, 1 = mapping table, 2 = CWE + path.
    """
    if not a.tools or not b.tools or (a.tools & b.tools):
        return None  # same tool: separate rules by design
    fa, fb = a.f, b.f
    if fa.asset_id is not None and fb.asset_id is not None and fa.asset_id != fb.asset_id:
        return None
    if a.site or b.site:
        if a.site != b.site:
            return None  # never across hosts
    elif not a.loc or a.loc != b.loc:
        return None  # no host (code, image): only the exact same location
    shared_cve = sorted(a.cves & b.cves)
    if shared_cve:
        return 0, f"cve:{shared_cve[0]}"
    if a.concepts and b.concepts:
        if len(a.concepts) == 1 and a.concepts == b.concepts:
            concept = next(iter(a.concepts))
            amb = ambiguous or set()
            if any((a.site, concept, t) in amb for t in a.tools | b.tools):
                return None
            return 1, f"map:{concept}"
        return None  # mapped to different (or several) known issues: keep apart
    if a.cwe and a.cwe == b.cwe and a.cwe not in GENERIC_CWES:
        if a.paths and b.paths and (a.paths & b.paths):
            return 2, f"cwe:CWE-{a.cwe}+path"
        if not a.site and a.loc and a.loc == b.loc:
            return 2, f"cwe:CWE-{a.cwe}+location"
    return None


def _ambiguous_concepts(infos: list[_Info]) -> set[tuple[str, str, str]]:
    """(site, concept, tool) with more than one candidate row: never auto-link those."""
    count: dict[tuple[str, str, str], int] = defaultdict(int)
    for i in infos:
        if len(i.concepts) != 1:
            continue
        concept = next(iter(i.concepts))
        for t in i.tools:
            count[(i.site, concept, t)] += 1
    return {k for k, n in count.items() if n > 1}


def _choose_primary(members: Iterable[Any]) -> Any:
    return min(members, key=lambda f: (f.status == FALSE_POSITIVE, -sev_rank(f.severity), f.id))


def compute_groups(findings: list[Any], obs_by: dict[int, list[Any]]) -> list[tuple[Any, dict[int, str]]]:
    """Groups of 2+ linked findings as (primary, {related id: rationale})."""
    infos = [_Info(f, obs_by.get(f.id, [])) for f in findings]
    amb = _ambiguous_concepts(infos)
    edges: list[tuple[int, int, int, str]] = []
    by_site: dict[str, list[_Info]] = defaultdict(list)
    for i in infos:
        by_site[i.site or "\x00" + i.loc].append(i)
    for bucket in by_site.values():
        for x in range(len(bucket)):
            for y in range(x + 1, len(bucket)):
                got = match_reason(bucket[x], bucket[y], amb)
                if got:
                    a, b = sorted((bucket[x].f.id, bucket[y].f.id))
                    edges.append((got[0], a, b, got[1]))
    edges.sort()
    parent: dict[int, int] = {i.f.id: i.f.id for i in infos}
    tools: dict[int, frozenset[str]] = {i.f.id: i.tools for i in infos}
    reason: dict[int, str] = {}

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for _, a, b, why in edges:
        ra, rb = find(a), find(b)
        if ra == rb or (tools[ra] & tools[rb]):
            continue  # a group never holds two rows from one tool
        parent[rb] = ra
        tools[ra] = tools[ra] | tools[rb]
        reason.setdefault(b, why)
        reason.setdefault(a, why)
    groups: dict[int, list[Any]] = defaultdict(list)
    for i in infos:
        groups[find(i.f.id)].append(i.f)
    out: list[tuple[Any, dict[int, str]]] = []
    for members in groups.values():
        if len(members) < 2:
            continue
        primary = _choose_primary(members)
        out.append((primary, {m.id: reason.get(m.id, "linked") for m in members if m.id != primary.id}))
    out.sort(key=lambda g: g[0].id)
    return out


# ----------------------------------------------------------------- persistence
def recompute(s: Session, engagement_id: int, *, actor: str = "system") -> dict:
    """Re-link cross-tool duplicates for one engagement. Never deletes or edits severities."""
    from attestra import audit
    from attestra.models import Finding

    rows = list(s.scalars(select(Finding).where(Finding.engagement_id == engagement_id).order_by(Finding.id)))
    obs_by = _obs_by_finding(s, [f.id for f in rows])
    groups = compute_groups(rows, obs_by)
    want: dict[int, tuple[int, str]] = {}
    for primary, related in groups:
        for rid, why in related.items():
            want[rid] = (primary.id, why[:500])
    linked = unlinked = 0
    for f in rows:
        target = want.get(f.id)
        cur = (f.merged_into_id, f.merge_rationale or "") if f.merged_into_id else None
        if target == cur:
            continue
        if target is None:
            prev = f.merged_into_id
            f.merged_into_id = None
            f.merge_rationale = ""
            unlinked += 1
            audit.record(s, actor, "finding.cross_unmerge", "finding", f.id, previous_primary=prev)
        else:
            f.merged_into_id, f.merge_rationale = target
            linked += 1
            audit.record(
                s, actor, "finding.cross_merge", "finding", f.id,
                primary=target[0], rationale=target[1],
            )
    s.flush()
    return {"groups": len(groups), "related": len(want), "linked": linked, "unlinked": unlinked}


def recompute_safely(s: Session, engagement_id: int, *, actor: str = "system") -> dict | None:
    """``recompute`` inside a savepoint; a failure never blocks the caller (imports)."""
    try:
        with s.begin_nested():
            return recompute(s, engagement_id, actor=actor)
    except Exception:  # noqa: BLE001
        return None


# ----------------------------------------------------------------- display
def _tool_severity(f: Any, tool: str, obs: list[Any]) -> str:
    sevs = [o.severity for o in obs if (o.tool or "").lower() == tool and o.severity]
    if sevs:
        return max(sevs, key=sev_rank)
    return f.severity or "info"


def _evidence(obs: list[Any], tool: str, limit: int = 3) -> list[str]:
    out: list[str] = []
    for o in obs:
        if (o.tool or "").lower() != tool:
            continue
        for r in o.evidence_refs or []:
            r = str(r).strip()
            if r and r not in out:
                out.append(r[:300])
            if len(out) >= limit:
                return out
    return out



def build_sources(members: list[Any], obs_by: dict[int, list[Any]]) -> list[dict]:
    """One row per (finding, tool): that tool's own severity and evidence."""
    out: list[dict] = []
    for m in members:
        obs = obs_by.get(m.id, [])
        for tool in [str(t).lower() for t in (m.tools or []) if t] or [""]:
            sev = _tool_severity(m, tool, obs) if tool else (m.severity or "info")
            rule_ids = []
            for o in obs:
                if (o.tool or "").lower() == tool and o.original_id and o.original_id not in rule_ids:
                    rule_ids.append(o.original_id)
            out.append(
                {
                    "tool": tool,
                    "tool_label": tool_label(tool) if tool else "Unknown",
                    "severity": sev,
                    "severity_label": title_case(sev),
                    "finding_id": m.id,
                    "title": m.title,
                    "status": m.status,
                    "status_label": " ".join(title_case(w) for w in (m.status or "").split("_")),
                    "location": m.location or "",
                    "rule_ids": rule_ids[:5],
                    "evidence": _evidence(obs, tool),
                    "rationale": getattr(m, "merge_rationale", "") or "",
                }
            )
    return out


def severity_label(effective: str, sources: list[dict]) -> str:
    """'High (ZAP: Low, Nuclei: High)'; just 'High' with fewer than two sources."""
    head = title_case(effective)
    if len(sources) < 2:
        return head
    parts = [f"{src['tool_label']}: {src['severity_label']}" for src in sources]
    return f"{head} ({', '.join(parts)})"


def _annotate(primary: Any, members: list[Any], obs_by: dict[int, list[Any]]) -> None:
    sources = build_sources(members, obs_by)
    live = [m for m in members if m.status != FALSE_POSITIVE] or members
    effective = max((m.severity or "info" for m in live), key=sev_rank)
    primary.cross_sources = sources
    primary.cross_related = [m for m in members if m.id != primary.id]
    primary.effective_severity = effective
    primary.severity_label = severity_label(effective, sources)


def collapse(s: Session, findings: list[Any]) -> list[Any]:
    """One entry per cross-tool group (order kept), annotated with Sources.

    Each returned finding gets transient ``cross_sources``, ``cross_related``,
    ``effective_severity`` and ``severity_label`` attributes. Related rows are folded
    into their group's primary; the primary is the highest-severity row that is not a
    false positive, so ``primary.severity`` is the group's effective severity.
    """
    rows = list(findings)
    if not rows:
        return rows
    groups: dict[int, list[Any]] = defaultdict(list)
    for f in rows:
        groups[getattr(f, "merged_into_id", None) or f.id].append(f)
    obs_by = _obs_by_finding(s, [f.id for f in rows])
    keep: dict[int, Any] = {}
    for members in groups.values():
        primary = _choose_primary(members) if len(members) > 1 else members[0]
        _annotate(primary, members, obs_by)
        keep[primary.id] = primary
    return [f for f in rows if f.id in keep]


def group_view(s: Session, f: Any) -> dict:
    """Sources for one finding's group (finding detail page)."""
    from attestra.models import Finding

    root = f.merged_into_id or f.id
    members = list(
        s.scalars(
            select(Finding)
            .where(Finding.engagement_id == f.engagement_id)
            .where((Finding.id == root) | (Finding.merged_into_id == root))
            .order_by(Finding.id)
        )
    )
    if f not in members:
        members.append(f)
    obs_by = _obs_by_finding(s, [m.id for m in members])
    primary = _choose_primary(members) if len(members) > 1 else f
    sources = build_sources(members, obs_by)
    live = [m for m in members if m.status != FALSE_POSITIVE] or members
    effective = max((m.severity or "info" for m in live), key=sev_rank)
    return {
        "cross_sources": sources,
        "cross_primary_id": primary.id,
        "cross_related": [m for m in members if m.id != f.id],
        "severity_label": severity_label(effective, sources),
    }
