"""Passive DNS posture checks (CAA, AAAA, SPF, TLSA).

Returns the same check-dict shape used by webcheck findings:
``{"id", "title", "severity", "cwe", "description", "location", ...}``.

``resolver`` is injectable for tests. Supported forms:

* ``dict`` mapping ``(name, rdtype)`` → ``list[str]`` (rdtype e.g. ``"CAA"``, ``"TXT"``)
* object with ``resolve(name, rdtype) -> list[str]``
* callable ``(name, rdtype) -> list[str]``

Missing keys / empty lists / raised lookup errors mean "no records".
When ``resolver`` is omitted and dnspython is not installed, returns a single
skipped note dict (does not crash). Lead adds dnspython in a later phase.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

VERIFY_PREFIX = "attestra-verify="
_LOOKUP_TIMEOUT_S = 5.0

ResolveFn = Callable[[str, str], list[str]]


def dns_checks(host: str, resolver: Any = None) -> list[dict]:
    """Run DNS posture checks for ``host``; return finding dicts (may be empty)."""
    host = (host or "").strip().strip(".").lower()
    if not host:
        return []

    if resolver is None:
        resolve = _default_resolve()
        if resolve is None:
            return [_skipped_note(host)]
    else:
        resolve = _bind_resolver(resolver)

    findings: list[dict] = []

    if not _has_caa(host, resolve):
        findings.append(
            {
                "id": "dns-caa",
                "title": "DNS: no CAA record",
                "severity": "low",
                "cwe": 16,
                "description": (
                    f"No CAA record was found on {host} or any parent domain. "
                    "Publish CAA so only approved CAs may issue certificates for this name."
                ),
                "location": host,
            }
        )

    if not resolve(host, "AAAA"):
        findings.append(
            {
                "id": "dns-aaaa",
                "title": "DNS: no IPv6 (AAAA) address",
                "severity": "info",
                "cwe": 16,
                "description": f"No AAAA record for {host}; the host has no published IPv6 address.",
                "location": host,
            }
        )

    mx = resolve(host, "MX")
    txt = [_redact_txt(t) for t in resolve(host, "TXT")]
    has_spf = any(_is_spf(t) for t in txt)
    if not mx and not has_spf:
        findings.append(
            {
                "id": "dns-spf",
                "title": "DNS: no SPF record on host without MX",
                "severity": "info",
                "cwe": 16,
                "description": (
                    f"{host} has neither MX nor a TXT record starting with v=spf1. "
                    "Publish SPF (or MX if the host receives mail) to reduce spoofing risk."
                ),
                "location": host,
            }
        )

    tlsa_name = f"_443._tcp.{host}"
    if not resolve(tlsa_name, "TLSA"):
        findings.append(
            {
                "id": "dns-tlsa",
                "title": "DNS: no DANE (TLSA) record",
                "severity": "info",
                "cwe": 16,
                "description": (
                    f"No TLSA record at {tlsa_name}. "
                    "DANE is optional; publish TLSA if you pin TLS certificates in DNS."
                ),
                "location": host,
            }
        )

    return findings


def _skipped_note(host: str) -> dict:
    return {
        "id": "dns-skipped",
        "title": "DNS checks skipped",
        "severity": "info",
        "cwe": 16,
        "description": "dnspython not installed",
        "location": host,
        "skipped": True,
    }


def _bind_resolver(resolver: Any) -> ResolveFn:
    if isinstance(resolver, Mapping):
        table = resolver

        def from_dict(name: str, rdtype: str) -> list[str]:
            n = name.strip(".").lower()
            t = rdtype.upper()
            for key in ((n, t), (name, rdtype), (n, rdtype), (name, t)):
                if key in table:
                    return [str(x) for x in (table[key] or [])]
            return []

        return from_dict

    if hasattr(resolver, "resolve") and callable(resolver.resolve):

        def from_obj(name: str, rdtype: str) -> list[str]:
            try:
                return [str(x) for x in (resolver.resolve(name, rdtype) or [])]
            except Exception:
                return []

        return from_obj

    if callable(resolver):

        def from_callable(name: str, rdtype: str) -> list[str]:
            try:
                return [str(x) for x in (resolver(name, rdtype) or [])]
            except Exception:
                return []

        return from_callable

    raise TypeError(
        "resolver must be a dict[(name, rdtype)] -> list[str], "
        "an object with resolve(name, rdtype), or a callable"
    )


def _default_resolve() -> ResolveFn | None:
    try:
        import dns.resolver  # type: ignore[import-untyped]
    except ImportError:
        return None

    def resolve(name: str, rdtype: str) -> list[str]:
        try:
            answers = dns.resolver.resolve(name, rdtype, lifetime=_LOOKUP_TIMEOUT_S)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except Exception:
            return []
        out: list[str] = []
        for rdata in answers:
            if rdtype.upper() == "TXT":
                strings = getattr(rdata, "strings", None)
                if strings is not None:
                    text = "".join(s.decode() if isinstance(s, bytes) else str(s) for s in strings)
                else:
                    text = str(rdata).strip().strip('"')
                out.append(text)
            else:
                out.append(str(rdata).strip())
        return out

    return resolve


def _caa_parents(host: str) -> list[str]:
    """Host then parents down to the registrable-looking apex (exclude bare TLD)."""
    labels = host.strip(".").lower().split(".")
    if len(labels) < 2:
        return [host] if host else []
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


def _has_caa(host: str, resolve: ResolveFn) -> bool:
    return any(bool(resolve(name, "CAA")) for name in _caa_parents(host))


def _is_spf(txt: str) -> bool:
    return txt.lstrip().lower().startswith("v=spf1")


def _redact_txt(value: str) -> str:
    """Drop ownership-verify TXT payloads so they never appear in findings."""
    text = value or ""
    if VERIFY_PREFIX in text:
        # Replace the verify token payload; keep other TXT content usable for SPF checks.
        parts = text.split()
        redacted: list[str] = []
        for p in parts:
            if p.startswith(VERIFY_PREFIX) or p.lower().startswith(VERIFY_PREFIX):
                redacted.append(f"{VERIFY_PREFIX}<redacted>")
            else:
                redacted.append(p)
        return " ".join(redacted)
    return text
