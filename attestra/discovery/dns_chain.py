"""CNAME chain traversal and wildcard detection with an injectable resolver (A-05).

Every function takes a ``resolver`` callable ``resolver(name, rtype) -> DnsAnswer`` so
tests use fixtures and nothing touches real DNS unless a caller explicitly passes
:func:`dnspython_resolver` (and discovery is enabled). Status values mirror DNS rcodes:
``NOERROR``, ``NXDOMAIN``, ``SERVFAIL``, ``TIMEOUT``, ``NODATA``.
"""
# @lat: [[attack-surface-and-platform#DNS chain and takeover fingerprints]]

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field

from attestra.discovery.normalize import normalize_hostname

MAX_HOPS = 10
STATUSES = ("NOERROR", "NXDOMAIN", "SERVFAIL", "TIMEOUT", "NODATA")


@dataclass(frozen=True)
class DnsAnswer:
    status: str = "NOERROR"
    records: tuple[str, ...] = ()


Resolver = Callable[[str, str], DnsAnswer]


@dataclass
class ChainResult:
    name: str
    chain: list[str] = field(default_factory=list)  # CNAME targets in order (excludes name)
    terminal: str = ""  # last name in the chain (name itself when no CNAME)
    status: str = "NOERROR"  # status of the terminal lookup
    addresses: list[str] = field(default_factory=list)
    loop: bool = False
    truncated: bool = False
    error: str = ""

    @property
    def dangling(self) -> bool:
        """CNAME present but its target does not exist (classic takeover precondition)."""
        return bool(self.chain) and self.status == "NXDOMAIN"

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "chain": list(self.chain),
            "terminal": self.terminal,
            "status": self.status,
            "addresses": list(self.addresses),
            "loop": self.loop,
            "truncated": self.truncated,
            "dangling": self.dangling,
            "error": self.error,
        }


def _resolution_label(status: str) -> str:
    return {"NOERROR": "resolved", "NXDOMAIN": "nxdomain", "SERVFAIL": "servfail", "TIMEOUT": "timeout", "NODATA": "nodata"}.get(
        status, "unknown"
    )


def follow_cname_chain(name: str, resolver: Resolver, *, max_hops: int = MAX_HOPS) -> ChainResult:
    """Follow CNAMEs from ``name`` until an A/AAAA answer, an error, a loop or ``max_hops``."""
    start = normalize_hostname(name) or str(name).lower().rstrip(".")
    res = ChainResult(name=start, terminal=start)
    seen = {start}
    current = start
    for _ in range(max_hops + 1):
        try:
            ans = resolver(current, "CNAME")
        except Exception as exc:  # noqa: BLE001 - resolver bugs become TIMEOUT-like errors
            res.status, res.error = "SERVFAIL", f"resolver error: {type(exc).__name__}"
            return res
        if ans.status in ("NXDOMAIN", "SERVFAIL", "TIMEOUT"):
            res.status = ans.status
            return res
        target = next((r for r in ans.records if r), "")
        if not target:
            break
        target = target.lower().rstrip(".")
        if target in seen:
            res.loop = True
            res.status = "SERVFAIL"
            res.error = f"CNAME loop at {target}"
            return res
        if len(res.chain) >= max_hops:
            res.truncated = True
            res.error = f"more than {max_hops} CNAME hops"
            return res
        res.chain.append(target)
        seen.add(target)
        res.terminal = current = target
    addrs: list[str] = []
    status = "NODATA"
    for rtype in ("A", "AAAA"):
        try:
            ans = resolver(current, rtype)
        except Exception as exc:  # noqa: BLE001
            res.status, res.error = "SERVFAIL", f"resolver error: {type(exc).__name__}"
            return res
        if ans.status == "NXDOMAIN":
            res.status = "NXDOMAIN"
            return res
        if ans.status in ("SERVFAIL", "TIMEOUT") and not addrs:
            status = ans.status
            continue
        if ans.records:
            addrs.extend(ans.records)
            status = "NOERROR"
    res.addresses = sorted(set(addrs))
    res.status = status
    return res


def wildcard_probe_label(apex: str, salt: str = "attestra-wc") -> str:
    """Deterministic, unlikely-to-exist label for one apex (no randomness in tests)."""
    return "wc-" + hashlib.sha256(f"{salt}|{apex}".encode()).hexdigest()[:20]


def detect_wildcard(apex: str, resolver: Resolver) -> frozenset[str]:
    """Addresses a non-existent label under ``apex`` resolves to (empty = no wildcard)."""
    probe = f"{wildcard_probe_label(apex)}.{apex.strip('.').lower()}"
    chain = follow_cname_chain(probe, resolver, max_hops=3)
    if chain.status != "NOERROR":
        return frozenset()
    return frozenset(chain.addresses)


def classify(chain: ChainResult, wildcard_addresses: frozenset[str] = frozenset()) -> str:
    """Resolution label for a candidate: wildcard answers do not count as "resolved"."""
    if chain.status == "NOERROR" and wildcard_addresses and chain.addresses and set(chain.addresses) <= wildcard_addresses:
        return "wildcard"
    return _resolution_label(chain.status)


def dnspython_resolver(*, timeout_s: float = 3.0) -> Resolver:  # pragma: no cover - real DNS
    """Real resolver (dnspython) with a short lifetime. Only for explicit, enabled use."""
    import dns.exception
    import dns.resolver

    r = dns.resolver.Resolver()
    r.lifetime = timeout_s
    r.timeout = timeout_s

    def _resolve(name: str, rtype: str) -> DnsAnswer:
        try:
            ans = r.resolve(name, rtype, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return DnsAnswer("NXDOMAIN")
        except dns.resolver.NoNameservers:
            return DnsAnswer("SERVFAIL")
        except dns.exception.Timeout:
            return DnsAnswer("TIMEOUT")
        if ans.rrset is None:
            return DnsAnswer("NODATA")
        return DnsAnswer("NOERROR", tuple(str(x).rstrip(".") for x in ans.rrset))

    return _resolve
