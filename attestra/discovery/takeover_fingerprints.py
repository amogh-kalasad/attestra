"""Passive subdomain-takeover fingerprints (A-05).

:func:`assess` combines a CNAME chain (:mod:`attestra.discovery.dns_chain`) with an
optional, already-fetched HTTP body/status and returns ``suspected``, ``not_suspected``
or ``inconclusive``. Guards against false positives:

* a provider error page without a CNAME to that provider is **not** suspected;
* SERVFAIL / TIMEOUT / CNAME loops / wildcard answers are ``inconclusive``;
* the result is a label only; ``claim_attempted`` is always False.
"""
# @lat: [[attack-surface-and-platform#DNS chain and takeover fingerprints]]

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

from attestra.discovery.dns_chain import ChainResult

DATA_FILE = Path(__file__).with_name("data") / "takeover_signatures.yaml"
SUSPECTED, NOT_SUSPECTED, INCONCLUSIVE = "suspected", "not_suspected", "inconclusive"


@dataclass(frozen=True)
class Signature:
    id: str
    name: str
    cname_suffixes: tuple[str, ...]
    cname_contains: tuple[str, ...] = ()
    fingerprints: tuple[str, ...] = ()
    nxdomain_indicates: bool = False
    http_status: tuple[int, ...] = ()
    contains_suffix: str = ""

    def matches_name(self, host: str) -> bool:
        h = host.lower().rstrip(".")
        if any(h == s or h.endswith("." + s) for s in self.cname_suffixes):
            return True
        if self.cname_contains and self.contains_suffix and h.endswith("." + self.contains_suffix):
            return any(c in h for c in self.cname_contains)
        return False


@dataclass
class Assessment:
    status: str
    provider: str = ""
    reasons: list[str] = field(default_factory=list)
    claim_attempted: bool = False

    def as_dict(self) -> dict:
        return {"status": self.status, "provider": self.provider, "reasons": list(self.reasons), "claim_attempted": False}


@lru_cache(maxsize=1)
def load_signatures(path: str | None = None) -> tuple[Signature, ...]:
    doc = yaml.safe_load(Path(path or DATA_FILE).read_text(encoding="utf-8")) or {}
    out: list[Signature] = []
    for row in doc.get("providers") or []:
        out.append(
            Signature(
                id=str(row["id"]),
                name=str(row.get("name") or row["id"]),
                cname_suffixes=tuple(str(s).lower() for s in row.get("cname_suffixes") or ()),
                cname_contains=tuple(str(s).lower() for s in row.get("cname_contains") or ()),
                fingerprints=tuple(str(s) for s in row.get("fingerprints") or ()),
                nxdomain_indicates=bool(row.get("nxdomain_indicates")),
                http_status=tuple(int(x) for x in row.get("http_status") or ()),
                contains_suffix=str(row.get("contains_suffix") or "").lower(),
            )
        )
    return tuple(out)


def provider_for_chain(chain: ChainResult, signatures=None) -> Signature | None:
    sigs = signatures or load_signatures()
    for host in chain.chain:
        for sig in sigs:
            if sig.matches_name(host):
                return sig
    return None


def assess(
    chain: ChainResult,
    *,
    http_body: str | None = None,
    http_status: int | None = None,
    wildcard: bool = False,
    signatures=None,
) -> Assessment:
    if chain.loop or chain.truncated:
        return Assessment(INCONCLUSIVE, reasons=["CNAME loop or too many hops"])
    sig = provider_for_chain(chain, signatures)
    if sig is None:
        reasons = ["no CNAME to a known takeover-prone provider"]
        if http_body and any(fp and fp in http_body for s in (signatures or load_signatures()) for fp in s.fingerprints):
            reasons.append("provider-like error text ignored without a matching CNAME")
        return Assessment(NOT_SUSPECTED, reasons=reasons)
    if wildcard:
        return Assessment(INCONCLUSIVE, sig.id, ["name only resolves through a wildcard record"])
    if chain.status in ("SERVFAIL", "TIMEOUT"):
        return Assessment(INCONCLUSIVE, sig.id, [f"DNS {chain.status} while following the chain"])
    if chain.status == "NXDOMAIN":
        if sig.nxdomain_indicates:
            return Assessment(SUSPECTED, sig.id, [f"CNAME to {sig.name} target that does not exist (NXDOMAIN)"])
        return Assessment(INCONCLUSIVE, sig.id, [f"dangling CNAME to {sig.name}; provider needs an HTTP fingerprint to confirm"])
    if http_body:
        hit = next((fp for fp in sig.fingerprints if fp and fp in http_body), "")
        if hit and (not sig.http_status or http_status is None or int(http_status) in sig.http_status):
            return Assessment(SUSPECTED, sig.id, [f"CNAME to {sig.name} and its unclaimed-resource page"])
    return Assessment(NOT_SUSPECTED, sig.id, [f"CNAME to {sig.name} answers normally"])
