"""Report-time consolidation: one entry per issue in generated reports.

Database rows are never changed. Runs after :func:`attestra.crossmerge.collapse` on the
reportable finding list and does two passes:

1. **Same-tool grouping** - rows from one scanner with the same rule and title on
   different URLs (for example Nuclei ``http-missing-security-headers:<header>`` once per
   page) become one entry that lists every affected URL.
2. **Cross-tool issue merge** - entries from different tools that describe the same issue
   on the same host (missing header X between ZAP / Nuclei / webcheck; weak CSP; weak
   HSTS; deprecated X-XSS-Protection) become one entry with every tool under
   Detected by / Sources.

Each merged entry is a :class:`ReportFinding`: a read-only view over the primary row
(highest severity, open first) with merged URLs, tools, evidence and member ids.
Setting attributes on it never touches the ORM row, so nothing is flushed to the DB.
Singletons are returned unchanged (the original ORM object).
"""
# @lat: [[reports#Generation]]

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from attestra import crossmerge
from attestra.models import OPEN_STATUSES

FALSE_POSITIVE = "false_positive"
# Tools whose per-URL rows are safe to fold together (scanner output, not manual work).
_NO_URL_GROUPING = frozenset({"", "automated_vapt", "manual", "evidence"})

# Extra report-level issue concepts (broader than crossmerge's conservative DB links).
# concept -> (canonical title, {tool: [(rule/original-id regex, title regex)]})
_REPORT_CONCEPTS: dict[str, tuple[str, dict[str, list[tuple[str, str]]]]] = {
    "report:csp-weak": (
        "Weak Content Security Policy (CSP)",
        {
            "zap": [(r"^10055(-\d+)?$", r"")],
            "nuclei": [(r"^(weak-csp-detect|csp-[a-z0-9-]*(wildcard|unsafe)[a-z0-9-]*)(:.*)?$", r"")],
            "webcheck": [(r"", r"^csp: .*(unsafe-inline|unsafe-eval|wildcard)")],
        },
    ),
    "report:hsts-weak": (
        "Weak HTTP Strict-Transport-Security (HSTS) configuration",
        {
            "zap": [(r"^10035(-\d+)?$", r"^(?!.*header not set).*")],
            "nuclei": [(r"^weak-hsts-detect(:.*)?$", r"")],
            "webcheck": [(r"^webcheck/hsts-(max-age|weak|multiple)", r"")],
        },
    ),
    "report:x-xss-protection": (
        "Deprecated or misconfigured X-XSS-Protection header",
        {
            "zap": [(r"^10016(-\d+)?$", r"")],
            "nuclei": [(r"^xss-deprecated-header(:.*)?$", r"")],
            "webcheck": [(r"^webcheck/x-xss-protection", r"")],
        },
    ),
}
_REPORT_COMPILED = {
    concept: (
        title,
        {
            tool: [(re.compile(r, re.IGNORECASE), re.compile(t, re.IGNORECASE)) for r, t in pairs]
            for tool, pairs in per_tool.items()
        },
    )
    for concept, (title, per_tool) in _REPORT_CONCEPTS.items()
}


class ReportFinding:
    """Read-only merged view of a finding group for report templates."""

    def __init__(self, primary: Any, **overrides: Any) -> None:
        object.__setattr__(self, "_primary", primary)
        object.__setattr__(self, "_over", dict(overrides))

    def __getattr__(self, name: str) -> Any:
        over = object.__getattribute__(self, "_over")
        if name in over:
            return over[name]
        return getattr(object.__getattribute__(self, "_primary"), name)

    def __setattr__(self, name: str, value: Any) -> None:
        object.__getattribute__(self, "_over")[name] = value

    @property
    def primary(self) -> Any:
        return object.__getattribute__(self, "_primary")

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<ReportFinding F-{self.id} {self.title!r} members={self.member_ids}>"


# ----------------------------------------------------------------- helpers
def member_rows(f: Any) -> list[Any]:
    """Underlying ORM rows behind a (possibly merged) report entry."""
    rows = getattr(f, "report_members", None)
    if rows:
        return list(rows)
    out = [f]
    for r in getattr(f, "cross_related", None) or []:
        if r is not f and r not in out:
            out.append(r)
    return out


def member_ids(f: Any) -> list[int]:
    ids = getattr(f, "member_ids", None)
    return list(ids) if ids else [f.id]


def _tools(f: Any) -> list[str]:
    return [str(t).lower() for t in (f.tools or []) if t]


def _rule_keys(f: Any, obs: list[Any]) -> list[str]:
    keys: list[str] = []
    for o in obs:
        if o.original_id and o.original_id not in keys:
            keys.append(str(o.original_id))
    if not keys:
        keys = [str(r) for r in (f.rule_ids or [])]
    return keys


def _pretty_matcher(template: str, matcher: str) -> str:
    if "header" in template.lower():
        return "-".join(p[:1].upper() + p[1:] for p in matcher.split("-"))
    return matcher


def _matcher_title(f: Any, obs: list[Any]) -> str | None:
    """'HTTP Missing Security Headers: X-Frame-Options' for template:matcher rows."""
    keys = _rule_keys(f, obs)
    if not keys or not all(":" in k for k in keys):
        return None
    pairs = {tuple(k.split(":", 1)) for k in keys}
    if len(pairs) != 1:
        return None
    template, matcher = next(iter(pairs))
    matcher = matcher.strip()
    if not matcher:
        return None
    pretty = _pretty_matcher(template, matcher)
    base = (f.title or "").strip()
    if pretty.lower() in base.lower():
        return None
    return f"{base}: {pretty}"


def _sort_key(f: Any) -> tuple:
    return (
        f.status == FALSE_POSITIVE,
        f.status not in OPEN_STATUSES,
        -crossmerge.sev_rank(f.severity),
        f.id,
    )


def _url_list(rows: list[Any]) -> list[str]:
    out: list[str] = []
    for r in rows:
        aff = r.affected_urls or []
        items = [aff] if isinstance(aff, str) else list(aff)
        for u in [r.location or ""] + [str(x) for x in items]:
            u = (u or "").strip()
            if u and u not in out:
                out.append(u)
    return out


def _status_label(status: str) -> str:
    from attestra.reports.labels import status_label

    return status_label(status)


def _severity_label(sev: str) -> str:
    from attestra.reports.labels import severity_label

    return severity_label(sev)


def _sources(rows: list[Any], obs_by: dict[int, list[Any]]) -> list[dict]:
    """One row per (tool, title): that tool's severity, finding ids and URL count."""
    buckets: dict[tuple[str, str], list[Any]] = {}
    for r in rows:
        for tool in _tools(r) or [""]:
            buckets.setdefault((tool, (r.title or "").strip()), []).append(r)
    out: list[dict] = []
    for (tool, title), members in buckets.items():
        sev = max(
            (crossmerge._tool_severity(m, tool, obs_by.get(m.id, [])) if tool else (m.severity or "info") for m in members),
            key=crossmerge.sev_rank,
        )
        statuses = sorted({m.status for m in members})
        urls = _url_list(members)
        ev: list[str] = []
        for m in members:
            for e in crossmerge._evidence(obs_by.get(m.id, []), tool):
                if e not in ev and len(ev) < 3:
                    ev.append(e)
        rule_ids: list[str] = []
        for m in members:
            for k in _rule_keys(m, [o for o in obs_by.get(m.id, []) if (o.tool or "").lower() == tool]):
                if k not in rule_ids:
                    rule_ids.append(k)
        out.append(
            {
                "tool": tool,
                "tool_label": crossmerge.tool_label(tool) if tool else "Unknown",
                "severity": sev,
                "severity_label": _severity_label(sev),
                "finding_id": members[0].id,
                "finding_ids": [m.id for m in members],
                "finding_refs": ", ".join(f"F-{m.id}" for m in members),
                "title": title,
                "status": statuses[0] if len(statuses) == 1 else "mixed",
                "status_label": ", ".join(_status_label(s) for s in statuses),
                "location": urls[0] if len(urls) == 1 else (f"{len(urls)} URLs" if urls else ""),
                "rule_ids": rule_ids[:5],
                "evidence": ev,
                "rationale": "",
            }
        )
    return out


def _tool_severity_label(effective: str, sources: list[dict]) -> str:
    per_tool: dict[str, str] = {}
    for src in sources:
        cur = per_tool.get(src["tool_label"])
        if cur is None or crossmerge.sev_rank(src["severity"]) > crossmerge.sev_rank(cur):
            per_tool[src["tool_label"]] = src["severity"]
    head = _severity_label(effective)
    if len(per_tool) < 2:
        return head
    return f"{head} ({', '.join(f'{t}: {_severity_label(s)}' for t, s in per_tool.items())})"


def _build(rows: list[Any], obs_by: dict[int, list[Any]], *, title: str | None = None, rationale: str = "") -> Any:
    rows = sorted({id(r): r for r in rows}.values(), key=_sort_key)
    live = [r for r in rows if r.status != FALSE_POSITIVE] or rows
    primary = live[0]
    if len(rows) == 1 and not title:
        return primary
    effective = max((r.severity or "info" for r in live), key=crossmerge.sev_rank)
    tools: list[str] = []
    for r in rows:
        for t in r.tools or []:
            if t and t not in tools:
                tools.append(t)
    rule_ids: list[str] = []
    for r in rows:
        for k in r.rule_ids or []:
            if k not in rule_ids:
                rule_ids.append(k)
    cves: list[str] = []
    for r in rows:
        for c in r.cves or []:
            if c not in cves:
                cves.append(c)
    evidence: list[Any] = []
    seen_ev: set[int] = set()
    for r in rows:
        for e in r.evidence or []:
            if e.id not in seen_ev:
                seen_ev.add(e.id)
                evidence.append(e)
    refs: list[str] = []
    for r in rows:
        items = [r.references] if isinstance(r.references, str) else list(r.references or [])
        for ref in items:
            if ref and ref not in refs:
                refs.append(ref)
    cvss = [r.cvss_score for r in rows if r.cvss_score is not None]
    epss = [r.epss for r in rows if r.epss is not None]
    sources = _sources(rows, obs_by)
    titles: list[str] = []
    for r in rows:
        t = (r.title or "").strip()
        if t and t not in titles:
            titles.append(t)
    statuses = {r.status for r in live}
    open_live = [r for r in live if r.status in OPEN_STATUSES]
    return ReportFinding(
        primary,
        title=title or primary.title,
        severity=effective,
        effective_severity=effective,
        severity_label=_tool_severity_label(effective, sources),
        status=primary.status if len(statuses) == 1 or not open_live else open_live[0].status,
        risk_score=max(float(r.risk_score or 0.0) for r in live),
        tools=tools,
        rule_ids=rule_ids,
        cves=cves,
        kev=any(bool(r.kev) for r in live),
        cvss_score=max(cvss) if cvss else None,
        epss=max(epss) if epss else None,
        occurrences=sum(int(r.occurrences or 1) for r in rows),
        affected_urls=_url_list(rows),
        references=refs,
        evidence=evidence,
        cross_sources=sources,
        cross_related=[r for r in rows if r is not primary],
        report_members=rows,
        member_ids=[r.id for r in rows],
        issues_covered=titles if len(titles) > 1 else [],
        report_merge_rationale=rationale,
    )


# ----------------------------------------------------------------- passes
def _report_concept(rows: list[Any], obs_by: dict[int, list[Any]]) -> str | None:
    found: set[str] = set()
    for f in rows:
        obs = obs_by.get(f.id, [])
        for tool in _tools(f):
            keys = _rule_keys(f, [o for o in obs if (o.tool or "").lower() == tool]) or [""]
            titles = [(f.title or "").strip()] + [(o.title or "").strip() for o in obs if (o.tool or "").lower() == tool]
            for concept, (_, per_tool) in _REPORT_COMPILED.items():
                for rx_rule, rx_title in per_tool.get(tool, []):
                    if any(rx_rule.search(k) for k in keys) and any(rx_title.search(t) for t in titles):
                        found.add(concept)
    if len(found) == 1:
        return next(iter(found))
    if found:
        return None
    concepts: set[str] = set()
    for f in rows:
        concepts |= set(crossmerge.concepts_for(f, obs_by.get(f.id, [])))
    csp = {c for c in concepts if c.startswith("csp:")}
    if csp and csp == concepts:
        return "report:csp-weak"
    if len(concepts) == 1:
        return next(iter(concepts))
    return None


def _site(rows: list[Any]) -> str:
    for r in rows:
        s = crossmerge.site_key(r.location or "")
        if s:
            return s
    return ""


def consolidate(s: Any, findings: list[Any], obs_by: dict[int, list[Any]] | None = None) -> list[Any]:
    """Return the report finding list with per-URL and cross-tool duplicates folded."""
    rows = [f for f in findings if f.status != FALSE_POSITIVE]
    if not rows:
        return rows
    if obs_by is None:
        ids: list[int] = []
        for f in rows:
            ids.extend(m.id for m in member_rows(f))
        obs_by = crossmerge._obs_by_finding(s, ids)
    order = {f.id: i for i, f in enumerate(rows)}

    # Pass 1: same tool, same rule + title, different URLs.
    groups: dict[tuple, list[Any]] = defaultdict(list)
    for f in rows:
        members = [m for m in member_rows(f) if m.status != FALSE_POSITIVE] or [f]
        tools = tuple(sorted(_tools(f)))
        if len(members) > 1 or len(tools) != 1 or tools[0] in _NO_URL_GROUPING:
            groups[("single", f.id)].append(f)
            continue
        key = (
            "url",
            tools[0],
            (f.title or "").strip().lower(),
            tuple(sorted(_rule_keys(f, obs_by.get(f.id, [])))),
            f.cwe,
            crossmerge.site_key(f.location or ""),
            f.status in OPEN_STATUSES,
        )
        groups[key].append(f)
    entries: list[tuple[int, list[Any], str | None, str]] = []
    for key, fs in groups.items():
        members: list[Any] = []
        for f in fs:
            members.extend(m for m in member_rows(f) if m.status != FALSE_POSITIVE)
        members = members or fs
        first = min(order[f.id] for f in fs)
        title = _matcher_title(fs[0], obs_by.get(fs[0].id, [])) if key[0] == "url" else None
        why = f"{len(fs)} {crossmerge.tool_label(key[1])} results on different URLs" if key[0] == "url" and len(fs) > 1 else ""
        entries.append((first, members, title, why))

    # Pass 2: different entries describing the same issue on the same host.
    by_concept: dict[tuple[str, str], list[int]] = defaultdict(list)
    for idx, (_, members, _, _) in enumerate(entries):
        concept = _report_concept(members, obs_by)
        if concept:
            by_concept[(_site(members), concept)].append(idx)
    absorbed: set[int] = set()
    merged: list[tuple[int, list[Any], str | None, str]] = []
    for (site, concept), idxs in by_concept.items():
        if len(idxs) < 2:
            continue
        all_members: list[Any] = []
        for i in idxs:
            all_members.extend(entries[i][1])
        tools = {t for m in all_members for t in _tools(m)}
        if len(tools) < 2:
            # One scanner's distinct rules (e.g. ZAP 10055 unsafe-eval vs unsafe-inline) stay
            # separate; this pass only removes overlap *between* tools.
            continue
        canon = _REPORT_COMPILED.get(concept, (None,))[0]
        title = canon
        if not title:
            # Header concepts: keep the most descriptive primary title (non-Nuclei first).
            best = sorted(all_members, key=lambda m: ("nuclei" in _tools(m), _sort_key(m)))[0]
            title = best.title
        why = f"same issue ({concept}) reported by {', '.join(sorted(crossmerge.tool_label(t) for t in tools))}"
        merged.append((min(entries[i][0] for i in idxs), all_members, title, why))
        absorbed.update(idxs)
    final = [e for i, e in enumerate(entries) if i not in absorbed] + merged
    final.sort(key=lambda e: e[0])
    out = [_build(members, obs_by, title=title, rationale=why) for _, members, title, why in final]
    return out
