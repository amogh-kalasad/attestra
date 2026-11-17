"""Passive discovery pipeline: observations → deduplicated, scored candidates (A-01).

Inputs are *observations* from passive sources (CT logs, subfinder output, dnsx
resolution, httpx probe metadata) that were produced elsewhere or injected by tests.
The pipeline:

1. normalizes every name and drops invalid ones;
2. keeps only names under an apex that is itself in the signed scope, and drops names
   matching a deny rule (out-of-scope names are counted, never stored);
3. merges observations per name deterministically (same input → same output order and
   values, whatever order the sources arrived in);
4. optionally enriches with DNS chain / wildcard / takeover / cloud correlation through
   an injected resolver;
5. returns candidates in ``pending`` state. Nothing here creates assets or scans.
"""
# @lat: [[attack-surface-and-platform#Passive discovery]]

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from attestra.discovery import cloud_correlation, dns_chain, require_enabled, takeover_fingerprints
from attestra.discovery.candidates import Candidate, Observation, score_confidence
from attestra.discovery.normalize import host_denied, normalize_hostname, under_apex

MAX_CANDIDATES = 5000


@dataclass
class PipelineResult:
    apex: str
    candidates: list[Candidate] = field(default_factory=list)
    excluded_out_of_scope: int = 0
    excluded_invalid: int = 0
    errors: dict[str, str] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)
    truncated: bool = False

    def summary(self) -> dict:
        return {
            "apex": self.apex,
            "candidates": len(self.candidates),
            "excluded_out_of_scope": self.excluded_out_of_scope,
            "excluded_invalid": self.excluded_invalid,
            "errors": dict(self.errors),
            "sources": list(self.sources),
            "truncated": self.truncated,
        }


def apex_in_scope(apex: str, allowed_hosts: Iterable[str]) -> bool:
    a = (apex or "").strip(".").lower()
    return bool(a) and "." in a and a in {h.strip(".").lower() for h in allowed_hosts or ()}


def merge_observations(
    observations: Iterable[Observation],
    *,
    apex: str,
    allowed_hosts: Iterable[str],
    deny_hosts: Iterable[str] = (),
) -> PipelineResult:
    apex_l = (apex or "").strip(".").lower()
    res = PipelineResult(apex=apex_l)
    if not apex_in_scope(apex_l, allowed_hosts):
        # R14 parity: discovery only runs for an apex that is on the signed allow-list.
        raise ValueError(f"apex {apex_l or '(empty)'} is not in the signed scope")
    grouped: dict[str, list[Observation]] = {}
    for ob in observations:
        name = normalize_hostname(ob.name)
        if not name:
            res.excluded_invalid += 1
            continue
        if not under_apex(name, apex_l) or host_denied(name, deny_hosts):
            res.excluded_out_of_scope += 1
            continue
        grouped.setdefault(name, []).append(ob)
    for name in sorted(grouped):
        if len(res.candidates) >= MAX_CANDIDATES:
            res.truncated = True
            break
        obs = sorted(grouped[name], key=lambda o: (o.source, o.seen_at or "", repr(sorted((o.detail or {}).items()))))
        sources = tuple(sorted({o.source for o in obs}))
        seen = sorted(o.seen_at for o in obs if o.seen_at)
        cand = Candidate(
            name=name,
            apex=apex_l,
            sources=sources,
            first_seen=seen[0] if seen else "",
            last_seen=seen[-1] if seen else "",
            provenance=[{"source": o.source, "seen_at": o.seen_at, "detail": dict(o.detail or {})} for o in obs],
            in_scope=True,
        )
        _apply_source_details(cand, obs)
        cand.confidence = score_confidence(cand.sources, cand.resolution)
        res.candidates.append(cand)
    res.sources = sorted({s for c in res.candidates for s in c.sources})
    return res


def _apply_source_details(cand: Candidate, obs: list[Observation]) -> None:
    """Fold dnsx / httpx details already present in observations into the candidate."""
    for o in obs:
        d = o.detail or {}
        if o.source == "dnsx":
            status = str(d.get("status") or "").upper()
            if d.get("a") or d.get("aaaa"):
                cand.addresses = tuple(sorted(set(cand.addresses) | set(d.get("a") or []) | set(d.get("aaaa") or [])))
                cand.resolution = "resolved"
            elif status == "NXDOMAIN" and cand.resolution == "unknown":
                cand.resolution = "nxdomain"
            elif status == "SERVFAIL" and cand.resolution == "unknown":
                cand.resolution = "servfail"
            if d.get("cname"):
                cand.cnames = tuple(dict.fromkeys([*cand.cnames, *[str(x).lower().rstrip(".") for x in d["cname"]]]))
        elif o.source == "httpx":
            keep = {k: d[k] for k in ("status_code", "title", "tech", "cdn", "webserver", "scheme") if k in d}
            if keep:
                cand.http = {**cand.http, **keep}
    if cand.cnames or cand.name:
        cand.cloud = cloud_correlation.correlate(cand.name, cand.cnames)


def enrich_with_dns(
    result: PipelineResult,
    resolver: dns_chain.Resolver,
    *,
    http_lookup: Callable[[str], tuple[int | None, str | None]] | None = None,
) -> PipelineResult:
    """Resolve each candidate's CNAME chain, mark wildcard answers, assess takeover.

    ``http_lookup(name) -> (status, body)`` is optional and must be a passive/pre-fetched
    source (fixtures in tests); the pipeline never fetches pages itself.
    """
    wildcard = dns_chain.detect_wildcard(result.apex, resolver)
    for cand in result.candidates:
        chain = dns_chain.follow_cname_chain(cand.name, resolver)
        label = dns_chain.classify(chain, wildcard)
        cand.resolution = label
        cand.cnames = tuple(chain.chain) or cand.cnames
        cand.addresses = tuple(chain.addresses) or cand.addresses
        status, body = (None, None)
        if http_lookup is not None:
            try:
                status, body = http_lookup(cand.name)
            except Exception:  # noqa: BLE001
                status, body = (None, None)
        cand.takeover = takeover_fingerprints.assess(
            chain, http_body=body, http_status=status, wildcard=(label == "wildcard")
        ).as_dict()
        cand.takeover["chain"] = chain.as_dict()
        cand.cloud = cloud_correlation.correlate(cand.name, cand.cnames)
        cand.confidence = score_confidence(cand.sources, cand.resolution)
    return result


SourceFn = Callable[[str], list[Observation]]


def run_passive_discovery(
    *,
    apex: str,
    allowed_hosts: Iterable[str],
    sources: dict[str, SourceFn],
    deny_hosts: Iterable[str] = (),
    resolver: dns_chain.Resolver | None = None,
) -> PipelineResult:
    """Run each passive source, merge, and (optionally) enrich. Flag-gated.

    A failing source is recorded in ``errors`` and the others still count.
    """
    require_enabled()
    if not apex_in_scope(apex, allowed_hosts):
        raise ValueError(f"apex {apex} is not in the signed scope")
    collected: list[Observation] = []
    errors: dict[str, str] = {}
    for name in sorted(sources):
        try:
            collected.extend(sources[name](apex))
        except Exception as exc:  # noqa: BLE001 - one bad source must not stop the run
            errors[name] = f"{type(exc).__name__}: {str(exc)[:200]}"
    res = merge_observations(collected, apex=apex, allowed_hosts=allowed_hosts, deny_hosts=deny_hosts)
    res.errors.update(errors)
    if resolver is not None:
        enrich_with_dns(res, resolver)
    return res


def observations_from_ct(suggestions, *, source: str = "ct") -> list[Observation]:
    """``ct_suggestions.CtSuggestion`` rows → observations (issuer kept as provenance)."""
    out: list[Observation] = []
    for sug in suggestions or ():
        name = getattr(sug, "name", None) or (sug.get("name") if isinstance(sug, dict) else None)
        if not name:
            continue
        first = getattr(sug, "first_seen", None) or (sug.get("first_seen") if isinstance(sug, dict) else "") or ""
        issuer = getattr(sug, "issuer", None) or (sug.get("issuer") if isinstance(sug, dict) else "") or ""
        out.append(Observation(name=str(name), source=source, seen_at=str(first), detail={"issuer": str(issuer)[:200]}))
    return out
