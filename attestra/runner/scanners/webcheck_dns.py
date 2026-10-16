"""Passive DNS posture checks (CAA, AAAA, SPF, TLSA, email, DNSSEC).

Returns the same check-dict shape used by webcheck findings:
``{"id", "title", "severity", "cwe", "description", "location", ...}``.

``resolver`` is injectable for tests. Supported forms:

* ``dict`` mapping ``(name, rdtype)`` → ``list[str]`` (rdtype e.g. ``"CAA"``, ``"TXT"``)
* object with ``resolve(name, rdtype) -> list[str]``
* callable ``(name, rdtype) -> list[str]``

Missing keys / empty lists / raised lookup errors mean "no records".
When ``resolver`` is omitted and dnspython is not installed, returns a single
skipped note dict (does not crash). Lead adds dnspython in a later phase.

Email checks (DMARC, DKIM, MTA-STS, TLS-RPT) and DNSSEC use the apex domain
when that apex is in scope. MTA-STS policy HTTP fetch runs only when
``mta-sts.<apex>`` is in scope, at most once per call.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

VERIFY_PREFIX = "attestra-verify="
_LOOKUP_TIMEOUT_S = 5.0

# Fixed DKIM selector list only — never guess beyond this.
DKIM_SELECTORS: tuple[str, ...] = (
    "default",
    "selector1",
    "selector2",
    "google",
    "k1",
    "mail",
    "dkim",
    "s1",
    "s2",
)

ResolveFn = Callable[[str, str], list[str]]
FetchFn = Callable[[str], str | None]

_DMARC_TAG_RE = re.compile(r"(?i)(?:^|;)\s*([a-z]+)\s*=\s*([^;]*)")
_DKIM_TAG_RE = re.compile(r"(?i)(?:^|;)\s*([a-z]+)\s*=\s*([^;]*)")


@dataclass
class DnsCheckResult:
    """Findings, notes, and C5 check rows from one DNS posture pass."""

    findings: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    checks: list[dict] = field(default_factory=list)


def dns_checks(
    host: str,
    resolver: Any = None,
    *,
    scope: Any = None,
    fetch_url: FetchFn | None = None,
) -> list[dict]:
    """Run DNS posture checks for ``host``; return finding dicts (may be empty)."""
    return dns_posture(host, resolver=resolver, scope=scope, fetch_url=fetch_url).findings


def dns_posture(
    host: str,
    resolver: Any = None,
    *,
    scope: Any = None,
    fetch_url: FetchFn | None = None,
) -> DnsCheckResult:
    """Run DNS posture checks; return findings, notes, and pass/fail/N/A rows."""
    host = (host or "").strip().strip(".").lower()
    if not host:
        return DnsCheckResult()

    if resolver is None:
        resolve = _default_resolve()
        if resolve is None:
            note = _skipped_note(host)
            return DnsCheckResult(findings=[note], notes=[note["description"]])
    else:
        resolve = _bind_resolver(resolver)

    result = DnsCheckResult()
    _run_basic_checks(host, resolve, result)
    _run_email_and_dnssec(host, resolve, result, scope=scope, fetch_url=fetch_url)
    return result


def _run_basic_checks(host: str, resolve: ResolveFn, result: DnsCheckResult) -> None:
    from attestra.checks import FAILED, PASSED, check_row

    if not _has_caa(host, resolve):
        finding = {
            "id": "dns-caa",
            "title": "DNS: no CAA record",
            "severity": "low",
            "cwe": 16,
            "description": (
                f"No CAA record was found on {host} or any parent domain. "
                "Publish CAA so only approved CAs may issue certificates for this name."
            ),
            "location": host,
            "recommendation": (
                "Add a CAA record at the apex (and any names that need their own policy) "
                "listing only the CAs you use, for example: 0 issue \"letsencrypt.org\"."
            ),
        }
        result.findings.append(finding)
        result.checks.append(
            check_row(
                check_id="dns-caa",
                name="DNS CAA record",
                status=FAILED,
                source="webcheck",
                evidence=finding["description"][:200],
            )
        )
    else:
        result.checks.append(
            check_row(check_id="dns-caa", name="DNS CAA record", status=PASSED, source="webcheck")
        )

    if not resolve(host, "AAAA"):
        finding = {
            "id": "dns-aaaa",
            "title": "DNS: no IPv6 (AAAA) address",
            "severity": "info",
            "cwe": 16,
            "description": f"No AAAA record for {host}; the host has no published IPv6 address.",
            "location": host,
            "recommendation": "Publish AAAA if the host should be reachable over IPv6.",
        }
        result.findings.append(finding)
        result.checks.append(
            check_row(
                check_id="dns-aaaa",
                name="DNS AAAA (IPv6) address",
                status=FAILED,
                source="webcheck",
                evidence=finding["description"][:200],
            )
        )
    else:
        result.checks.append(
            check_row(
                check_id="dns-aaaa",
                name="DNS AAAA (IPv6) address",
                status=PASSED,
                source="webcheck",
            )
        )

    mx = resolve(host, "MX")
    txt = [_redact_txt(t) for t in resolve(host, "TXT")]
    has_spf = any(_is_spf(t) for t in txt)
    if not mx and not has_spf:
        finding = {
            "id": "dns-spf",
            "title": "DNS: no SPF record on host without MX",
            "severity": "info",
            "cwe": 16,
            "description": (
                f"{host} has neither MX nor a TXT record starting with v=spf1. "
                "Publish SPF (or MX if the host receives mail) to reduce spoofing risk."
            ),
            "location": host,
            "recommendation": (
                "Publish a TXT record starting with v=spf1 that lists your sending hosts, "
                "or add MX if this name receives mail."
            ),
        }
        result.findings.append(finding)
        result.checks.append(
            check_row(
                check_id="dns-spf",
                name="DNS SPF when host has no MX",
                status=FAILED,
                source="webcheck",
                evidence=finding["description"][:200],
            )
        )
    else:
        result.checks.append(
            check_row(
                check_id="dns-spf",
                name="DNS SPF when host has no MX",
                status=PASSED,
                source="webcheck",
                evidence="MX or SPF present" if (mx or has_spf) else "",
            )
        )

    tlsa_name = f"_443._tcp.{host}"
    if not resolve(tlsa_name, "TLSA"):
        finding = {
            "id": "dns-tlsa",
            "title": "DNS: no DANE (TLSA) record",
            "severity": "info",
            "cwe": 16,
            "description": (
                f"No TLSA record at {tlsa_name}. "
                "DANE is optional; publish TLSA if you pin TLS certificates in DNS."
            ),
            "location": host,
            "recommendation": "Publish a TLSA record at _443._tcp.<host> if you use DANE.",
        }
        result.findings.append(finding)
        result.checks.append(
            check_row(
                check_id="dns-tlsa",
                name="DNS TLSA (DANE) record",
                status=FAILED,
                source="webcheck",
                evidence=finding["description"][:200],
            )
        )
    else:
        result.checks.append(
            check_row(
                check_id="dns-tlsa",
                name="DNS TLSA (DANE) record",
                status=PASSED,
                source="webcheck",
            )
        )


def _run_email_and_dnssec(
    host: str,
    resolve: ResolveFn,
    result: DnsCheckResult,
    *,
    scope: Any,
    fetch_url: FetchFn | None,
) -> None:
    from attestra.checks import FAILED, PASSED, SKIPPED, check_row

    apex = _apex_domain(host)
    if not _host_allowed(apex, scope):
        result.notes.append(f"skipped: apex {apex} not in scope for email/DNSSEC checks")
        for cid, name in (
            ("dns-dmarc", "DNS DMARC policy"),
            ("dns-dkim", "DNS DKIM on common selectors"),
            ("dns-mta-sts", "DNS MTA-STS policy"),
            ("dns-tls-rpt", "DNS TLS-RPT record"),
            ("dns-dnssec", "DNSSEC DS and RRSIG"),
        ):
            result.checks.append(
                check_row(
                    check_id=cid,
                    name=name,
                    status=SKIPPED,
                    source="webcheck",
                    evidence=f"apex {apex} not in scope",
                )
            )
        return

    mx = resolve(apex, "MX")
    has_mx = bool(mx)

    # --- DMARC ---
    dmarc_name = f"_dmarc.{apex}"
    dmarc_txts = [_redact_txt(t) for t in resolve(dmarc_name, "TXT")]
    dmarc_rec = _first_dmarc(dmarc_txts)
    dmarc_findings: list[dict] = []
    dmarc_pass = False

    if not has_mx:
        if dmarc_rec and dmarc_rec.get("p") in ("quarantine", "reject"):
            result.notes.append(
                f"good practice: DMARC p={dmarc_rec['p']} on {apex} (no MX; email checks not applicable)"
            )
        result.checks.append(
            check_row(
                check_id="dns-dmarc",
                name="DNS DMARC policy",
                status=PASSED,
                source="webcheck",
                evidence="not applicable (no MX)",
            )
        )
    elif dmarc_rec is None:
        if dmarc_txts:
            finding = _finding(
                "dns-dmarc-bad-syntax",
                "DNS: DMARC record has bad syntax",
                "low",
                (
                    f"TXT at {dmarc_name} does not look like a valid v=DMARC1 record. "
                    "Fix the syntax so receivers can apply the policy."
                ),
                apex,
                recommendation=(
                    "Publish a single TXT at _dmarc.<domain> starting with v=DMARC1; "
                    "set p=quarantine or p=reject and add a rua= mailto address."
                ),
            )
            dmarc_findings.append(finding)
        else:
            finding = _finding(
                "dns-dmarc-missing",
                "DNS: no DMARC record",
                "medium",
                (
                    f"No DMARC TXT record at {dmarc_name}. "
                    "Publish DMARC so receivers know how to handle unauthenticated mail."
                ),
                apex,
                recommendation=(
                    "Add TXT at _dmarc.<domain>: v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>. "
                    "Move to p=reject once reports look clean."
                ),
            )
            dmarc_findings.append(finding)
    else:
        policy = dmarc_rec.get("p")
        if policy is None or policy not in ("none", "quarantine", "reject"):
            finding = _finding(
                "dns-dmarc-bad-syntax",
                "DNS: DMARC record has bad syntax",
                "low",
                (
                    f"DMARC at {dmarc_name} is missing a valid p= tag "
                    "(expected none, quarantine, or reject)."
                ),
                apex,
                recommendation="Set p=quarantine or p=reject on the DMARC record.",
            )
            dmarc_findings.append(finding)
        elif policy == "none":
            finding = _finding(
                "dns-dmarc-p-none",
                "DNS: DMARC policy is p=none",
                "low",
                (
                    f"DMARC at {dmarc_name} uses p=none, so receivers only monitor. "
                    "Raise the policy to quarantine or reject once ready."
                ),
                apex,
                recommendation="Change DMARC p=none to p=quarantine, then p=reject.",
            )
            dmarc_findings.append(finding)
        else:
            dmarc_pass = True

        if not dmarc_rec.get("rua"):
            finding = _finding(
                "dns-dmarc-no-rua",
                "DNS: DMARC has no rua reporting address",
                "info",
                (
                    f"DMARC at {dmarc_name} has no rua= tag. "
                    "Add a mailto reporting address so you can see authentication failures."
                ),
                apex,
                recommendation="Add rua=mailto:dmarc-reports@<domain> to the DMARC record.",
            )
            dmarc_findings.append(finding)

    if has_mx:
        result.findings.extend(dmarc_findings)
        if dmarc_pass:
            result.checks.append(
                check_row(
                    check_id="dns-dmarc",
                    name="DNS DMARC policy",
                    status=PASSED,
                    source="webcheck",
                    evidence=f"p={dmarc_rec.get('p')}" if dmarc_rec else "",
                )
            )
        else:
            evidence = (dmarc_findings[0]["description"][:200] if dmarc_findings else "DMARC failed")
            result.checks.append(
                check_row(
                    check_id="dns-dmarc",
                    name="DNS DMARC policy",
                    status=FAILED,
                    source="webcheck",
                    evidence=evidence,
                )
            )

    # --- DKIM (fixed selector list only) ---
    if not has_mx:
        result.checks.append(
            check_row(
                check_id="dns-dkim",
                name="DNS DKIM on common selectors",
                status=PASSED,
                source="webcheck",
                evidence="not applicable (no MX)",
            )
        )
    else:
        found_good = False
        found_any = False
        weak_findings: list[dict] = []
        for selector in DKIM_SELECTORS:
            name = f"{selector}._domainkey.{apex}"
            texts = [_redact_txt(t) for t in resolve(name, "TXT")]
            for text in texts:
                parsed = _parse_dkim(text)
                if parsed is None:
                    continue
                found_any = True
                bits = parsed.get("rsa_bits")
                if bits is not None and bits < 1024:
                    weak_findings.append(
                        _finding(
                            "dns-dkim-weak-key",
                            "DNS: DKIM RSA key is under 1024 bits",
                            "medium",
                            (
                                f"DKIM selector {selector!r} on {apex} uses an RSA key of about "
                                f"{bits} bits. Replace it with a 2048-bit (or stronger) key."
                            ),
                            apex,
                            recommendation=(
                                "Rotate the DKIM key to RSA 2048-bit or stronger and update "
                                f"the TXT at {selector}._domainkey.<domain>."
                            ),
                            param=selector,
                            variant=f"dns-dkim-weak-key:{selector}",
                        )
                    )
                else:
                    found_good = True
        if not found_any:
            finding = _finding(
                "dns-dkim-none",
                "DNS: no DKIM found on common selectors",
                "info",
                (
                    f"No DKIM TXT was found on common selectors for {apex} "
                    f"({', '.join(DKIM_SELECTORS)}). A custom selector may still exist."
                ),
                apex,
                recommendation=(
                    "Publish DKIM at <selector>._domainkey.<domain> for your mail provider "
                    "selector, using at least a 2048-bit RSA key."
                ),
            )
            result.findings.append(finding)
            result.checks.append(
                check_row(
                    check_id="dns-dkim",
                    name="DNS DKIM on common selectors",
                    status=FAILED,
                    source="webcheck",
                    evidence=finding["description"][:200],
                )
            )
        else:
            result.findings.extend(weak_findings)
            if found_good:
                result.checks.append(
                    check_row(
                        check_id="dns-dkim",
                        name="DNS DKIM on common selectors",
                        status=PASSED,
                        source="webcheck",
                    )
                )
            else:
                evidence = weak_findings[0]["description"][:200] if weak_findings else "weak DKIM"
                result.checks.append(
                    check_row(
                        check_id="dns-dkim",
                        name="DNS DKIM on common selectors",
                        status=FAILED,
                        source="webcheck",
                        evidence=evidence,
                    )
                )

    # --- MTA-STS ---
    if not has_mx:
        result.checks.append(
            check_row(
                check_id="dns-mta-sts",
                name="DNS MTA-STS policy",
                status=PASSED,
                source="webcheck",
                evidence="not applicable (no MX)",
            )
        )
    else:
        mta_txt_name = f"_mta-sts.{apex}"
        mta_host = f"mta-sts.{apex}"
        mta_txts = [_redact_txt(t) for t in resolve(mta_txt_name, "TXT")]
        has_sts_txt = any(_is_mta_sts_txt(t) for t in mta_txts)
        if not has_sts_txt:
            finding = _finding(
                "dns-mta-sts-missing",
                "DNS: no MTA-STS record",
                "low",
                (
                    f"No MTA-STS TXT at {mta_txt_name}. "
                    "Publish MTA-STS so sending MTAs can enforce TLS to your MX hosts."
                ),
                apex,
                recommendation=(
                    "Add TXT at _mta-sts.<domain> (v=STSv1; id=...) and serve "
                    "https://mta-sts.<domain>/.well-known/mta-sts.txt with mode=enforce."
                ),
            )
            result.findings.append(finding)
            result.checks.append(
                check_row(
                    check_id="dns-mta-sts",
                    name="DNS MTA-STS policy",
                    status=FAILED,
                    source="webcheck",
                    evidence=finding["description"][:200],
                )
            )
        elif not _host_allowed(mta_host, scope):
            result.notes.append("policy file not fetched, host not in scope")
            result.checks.append(
                check_row(
                    check_id="dns-mta-sts",
                    name="DNS MTA-STS policy",
                    status=SKIPPED,
                    source="webcheck",
                    evidence="policy file not fetched, host not in scope",
                )
            )
        else:
            policy_url = f"https://{mta_host}/.well-known/mta-sts.txt"
            body = _fetch_mta_sts_policy(policy_url, scope=scope, fetch_url=fetch_url)
            mode = _parse_mta_sts_mode(body) if body is not None else None
            if mode is None:
                finding = _finding(
                    "dns-mta-sts-no-policy",
                    "DNS: MTA-STS TXT without a valid policy file",
                    "medium",
                    (
                        f"MTA-STS TXT exists at {mta_txt_name}, but the policy file at "
                        f"{policy_url} was missing or invalid."
                    ),
                    apex,
                    recommendation=(
                        "Serve a valid STSv1 policy at "
                        "https://mta-sts.<domain>/.well-known/mta-sts.txt with mode=enforce."
                    ),
                )
                result.findings.append(finding)
                result.checks.append(
                    check_row(
                        check_id="dns-mta-sts",
                        name="DNS MTA-STS policy",
                        status=FAILED,
                        source="webcheck",
                        evidence=finding["description"][:200],
                    )
                )
            elif mode == "testing":
                finding = _finding(
                    "dns-mta-sts-testing",
                    "DNS: MTA-STS mode is testing",
                    "info",
                    (
                        f"MTA-STS policy for {apex} uses mode=testing. "
                        "Switch to mode=enforce when ready."
                    ),
                    apex,
                    recommendation="Set mode: enforce in the MTA-STS policy file.",
                )
                result.findings.append(finding)
                result.checks.append(
                    check_row(
                        check_id="dns-mta-sts",
                        name="DNS MTA-STS policy",
                        status=FAILED,
                        source="webcheck",
                        evidence=finding["description"][:200],
                    )
                )
            elif mode == "enforce":
                result.checks.append(
                    check_row(
                        check_id="dns-mta-sts",
                        name="DNS MTA-STS policy",
                        status=PASSED,
                        source="webcheck",
                        evidence="mode=enforce",
                    )
                )
            else:
                finding = _finding(
                    "dns-mta-sts-no-policy",
                    "DNS: MTA-STS TXT without a valid policy file",
                    "medium",
                    (
                        f"MTA-STS policy for {apex} has mode={mode!r}, which is not enforce or testing."
                    ),
                    apex,
                    recommendation="Set mode: enforce (or testing while rolling out) in the policy file.",
                )
                result.findings.append(finding)
                result.checks.append(
                    check_row(
                        check_id="dns-mta-sts",
                        name="DNS MTA-STS policy",
                        status=FAILED,
                        source="webcheck",
                        evidence=finding["description"][:200],
                    )
                )

    # --- TLS-RPT ---
    if not has_mx:
        result.checks.append(
            check_row(
                check_id="dns-tls-rpt",
                name="DNS TLS-RPT record",
                status=PASSED,
                source="webcheck",
                evidence="not applicable (no MX)",
            )
        )
    else:
        tlsrpt_name = f"_smtp._tls.{apex}"
        tlsrpt_txts = [_redact_txt(t) for t in resolve(tlsrpt_name, "TXT")]
        if any(_is_tlsrpt(t) for t in tlsrpt_txts):
            result.checks.append(
                check_row(
                    check_id="dns-tls-rpt",
                    name="DNS TLS-RPT record",
                    status=PASSED,
                    source="webcheck",
                )
            )
        else:
            finding = _finding(
                "dns-tls-rpt-missing",
                "DNS: no TLS-RPT record",
                "info",
                (
                    f"No TLS-RPT TXT at {tlsrpt_name}. "
                    "Publish TLS-RPT so you receive reports about SMTP TLS failures."
                ),
                apex,
                recommendation=(
                    "Add TXT at _smtp._tls.<domain>: v=TLSRPTv1; rua=mailto:tlsrpt@<domain>."
                ),
            )
            result.findings.append(finding)
            result.checks.append(
                check_row(
                    check_id="dns-tls-rpt",
                    name="DNS TLS-RPT record",
                    status=FAILED,
                    source="webcheck",
                    evidence=finding["description"][:200],
                )
            )

    # --- DNSSEC (DS at name + RRSIG evidence) ---
    has_ds = bool(resolve(apex, "DS"))
    has_rrsig = bool(resolve(apex, "RRSIG"))
    if has_ds and has_rrsig:
        result.checks.append(
            check_row(
                check_id="dns-dnssec",
                name="DNSSEC DS and RRSIG",
                status=PASSED,
                source="webcheck",
            )
        )
    else:
        finding = _finding(
            "dns-dnssec-missing",
            "DNS: DNSSEC not detected",
            "low",
            (
                f"No DS and/or RRSIG evidence for {apex} "
                f"(DS={'yes' if has_ds else 'no'}, RRSIG={'yes' if has_rrsig else 'no'}). "
                "Enable DNSSEC at the registry and sign the zone."
            ),
            apex,
            recommendation=(
                "Enable DNSSEC with your DNS host and publish DS records at the parent registry."
            ),
        )
        result.findings.append(finding)
        result.checks.append(
            check_row(
                check_id="dns-dnssec",
                name="DNSSEC DS and RRSIG",
                status=FAILED,
                source="webcheck",
                evidence=finding["description"][:200],
            )
        )


def _finding(
    fid: str,
    title: str,
    severity: str,
    description: str,
    location: str,
    *,
    recommendation: str = "",
    param: str = "",
    variant: str = "",
) -> dict:
    out: dict[str, Any] = {
        "id": fid,
        "title": title,
        "severity": severity,
        "cwe": 16,
        "description": description,
        "location": location,
    }
    if recommendation:
        out["recommendation"] = recommendation
    if param:
        out["param"] = param
    if variant:
        out["variant"] = variant
    else:
        out["variant"] = fid
    return out


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
        import dns.flags  # type: ignore[import-untyped]
        import dns.resolver  # type: ignore[import-untyped]
    except ImportError:
        return None

    res = dns.resolver.Resolver(configure=True)
    res.lifetime = _LOOKUP_TIMEOUT_S
    try:
        res.use_edns(0, dns.flags.DO, 4096)
    except Exception:
        pass

    def resolve(name: str, rdtype: str) -> list[str]:
        rdtype_u = rdtype.upper()
        try:
            if rdtype_u == "RRSIG":
                return _resolve_rrsig_evidence(res, name)
            answers = res.resolve(name, rdtype_u, lifetime=_LOOKUP_TIMEOUT_S)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except Exception:
            return []
        out: list[str] = []
        for rdata in answers:
            if rdtype_u == "TXT":
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


def _resolve_rrsig_evidence(res: Any, name: str) -> list[str]:
    """Return a non-empty list when the zone answer carries RRSIG (DO bit)."""
    import dns.resolver  # type: ignore[import-untyped]

    for qtype in ("DNSKEY", "SOA", "A"):
        try:
            answers = res.resolve(name, qtype, lifetime=_LOOKUP_TIMEOUT_S)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            continue
        except Exception:
            continue
        response = getattr(answers, "response", None)
        if response is None:
            continue
        try:
            for rrset in list(response.answer) + list(getattr(response, "authority", []) or []):
                covers = getattr(rrset, "name", None)
                rdtype = str(getattr(rrset, "rdtype", "") or "")
                # dnspython stores signatures alongside; also accept explicit RRSIG rdtype.
                sigs = getattr(rrset, "sig", None) or getattr(rrset, "rrsig", None)
                if sigs or "RRSIG" in rdtype.upper():
                    return [f"rrsig:{qtype}"]
                # Iterate rdatas looking for rrsig type name
                for rdata in rrset:
                    cls_name = type(rdata).__name__.upper()
                    if "RRSIG" in cls_name:
                        return [f"rrsig:{qtype}"]
                # Fallback: answer.rrset may expose covering signatures via .tsigs / .answer
                if covers is not None and hasattr(answers, "rrset") and answers.rrset is not None:
                    # Presence of AD flag is not enough alone; require sigs when available.
                    pass
        except Exception:
            continue
        # Some resolvers return separate RRSIG rrsets in the answer section.
        try:
            for rrset in response.answer:
                if str(getattr(rrset, "rdtype", "")).endswith("46") or "RRSIG" in str(
                    getattr(rrset, "rdtype", "")
                ):
                    return [f"rrsig:{qtype}"]
                from dns import rdatatype as _rdt  # type: ignore[import-untyped]

                if getattr(rrset, "rdtype", None) == getattr(_rdt, "RRSIG", None):
                    return [f"rrsig:{qtype}"]
        except Exception:
            continue
    return []


def _caa_parents(host: str) -> list[str]:
    """Host then parents down to the registrable-looking apex (exclude bare TLD)."""
    labels = host.strip(".").lower().split(".")
    if len(labels) < 2:
        return [host] if host else []
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


def _apex_domain(host: str) -> str:
    """Simple registrable apex (last two labels)."""
    labels = [p for p in host.strip(".").lower().split(".") if p]
    if len(labels) <= 2:
        return ".".join(labels)
    return ".".join(labels[-2:])


def _has_caa(host: str, resolve: ResolveFn) -> bool:
    return any(bool(resolve(name, "CAA")) for name in _caa_parents(host))


def _is_spf(txt: str) -> bool:
    return txt.lstrip().lower().startswith("v=spf1")


def _host_allowed(host: str, scope: Any) -> bool:
    """True when scope is unset (unit tests) or host is on the allow-list."""
    if scope is None:
        return True
    allowed = getattr(scope, "allowed_hosts", None)
    if allowed is None and isinstance(scope, (set, frozenset, list, tuple)):
        allowed = scope
    if allowed is None:
        return True
    host_l = host.strip(".").lower()
    allowed_l = {str(h).strip(".").lower() for h in allowed}
    if host_l in allowed_l:
        return True
    # Deny patterns win when present.
    for pattern in getattr(scope, "deny_hosts", ()) or ():
        import fnmatch

        if fnmatch.fnmatch(host_l, str(pattern).lower()):
            return False
    return False


def _first_dmarc(txts: list[str]) -> dict[str, str] | None:
    for text in txts:
        cleaned = text.strip().strip('"')
        if not cleaned.lower().startswith("v=dmarc1"):
            continue
        tags = {m.group(1).lower(): m.group(2).strip() for m in _DMARC_TAG_RE.finditer(cleaned)}
        if tags.get("v", "").lower() != "dmarc1":
            continue
        return tags
    return None


def _parse_dkim(text: str) -> dict[str, Any] | None:
    cleaned = text.strip().strip('"')
    if not cleaned:
        return None
    lower = cleaned.lower()
    if "v=dkim1" not in lower and "p=" not in lower and "k=" not in lower:
        return None
    tags = {m.group(1).lower(): m.group(2).strip() for m in _DKIM_TAG_RE.finditer(cleaned)}
    if "p" not in tags:
        return None
    # Empty p= means revoked key — treat as present but not a usable good key.
    p_val = tags.get("p") or ""
    if p_val == "":
        return {"rsa_bits": None, "revoked": True}
    k = (tags.get("k") or "rsa").lower()
    out: dict[str, Any] = {"k": k, "revoked": False, "rsa_bits": None}
    if k == "rsa" or k.startswith("rsa"):
        out["rsa_bits"] = _rsa_bits_from_p(p_val)
    return out


def _rsa_bits_from_p(p_b64: str) -> int | None:
    """Estimate RSA modulus bits from DKIM p= base64 (raw or DER)."""
    try:
        raw = base64.b64decode(re.sub(r"\s+", "", p_b64) + "===")
    except Exception:
        return None
    if not raw:
        return None
    # Heuristic: DER SEQUENCE starts with 0x30; modulus length ≈ total - overhead.
    if raw[0] == 0x30 and len(raw) >= 20:
        # Rough: subtract typical SubjectPublicKeyInfo / RSAPublicKey header (~20–40 bytes).
        return max(0, (len(raw) - 25) * 8)
    return len(raw) * 8


def _is_mta_sts_txt(txt: str) -> bool:
    return "v=stsv1" in txt.lstrip().lower()


def _is_tlsrpt(txt: str) -> bool:
    return txt.lstrip().lower().startswith("v=tlsrptv1")


def _parse_mta_sts_mode(body: str | None) -> str | None:
    if not body:
        return None
    version_ok = False
    mode: str | None = None
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip().lower()
        val = val.strip().lower()
        if key == "version" and val == "stsv1":
            version_ok = True
        elif key == "mode":
            mode = val
    if not version_ok or not mode:
        return None
    return mode


def _fetch_mta_sts_policy(
    url: str,
    *,
    scope: Any,
    fetch_url: FetchFn | None,
) -> str | None:
    """Fetch MTA-STS policy body at most once; injectable ``fetch_url`` for tests."""
    if fetch_url is not None:
        try:
            return fetch_url(url)
        except Exception:
            return None
    if scope is None:
        return None
    try:
        from attestra.runner.http_safe import safe_get

        resp = safe_get(url, scope=scope)
        if resp.status >= 400:
            return None
        body = resp.body
        if isinstance(body, bytes):
            return body.decode("utf-8", errors="replace")
        return str(body) if body is not None else None
    except Exception:
        return None


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
