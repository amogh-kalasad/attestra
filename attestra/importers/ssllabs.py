"""Import a saved Qualys SSL Labs JSON assessment (upload only, no live API).

Accepts the Host / analyze response shape with ``endpoints[].details``.
Findings use variants that align with testssl ids where possible so the same
TLS issue merges instead of doubling.
"""
# @lat: [[import-pipeline#Supported formats]]

from __future__ import annotations

import json
from typing import Any

from attestra.importers.base import NormalizedFinding

_WEAK_PROTOCOLS = {
    ("SSL", "2.0"): ("SSLv2", "high"),
    ("SSL", "3.0"): ("SSLv3", "high"),
    ("TLS", "1.0"): ("TLS1", "medium"),
    ("TLS", "1.1"): ("TLS1_1", "medium"),
}


def _host(doc: dict[str, Any]) -> str:
    h = doc.get("host") or doc.get("hostname") or ""
    return str(h).strip().lower()


def _location(host: str, port: int | None = 443) -> str:
    if not host:
        return ""
    if host.startswith("http://") or host.startswith("https://"):
        return host if host.endswith("/") else host + "/"
    p = port or 443
    if p == 443:
        return f"https://{host}/"
    return f"https://{host}:{p}/"


def _endpoints(doc: dict[str, Any]) -> list[dict[str, Any]]:
    eps = doc.get("endpoints")
    if isinstance(eps, list):
        return [e for e in eps if isinstance(e, dict)]
    # Single endpoint detail export
    if isinstance(doc.get("details"), dict):
        return [doc]
    return []


def _cert_issues(doc: dict[str, Any], details: dict[str, Any]) -> list[NormalizedFinding]:
    out: list[NormalizedFinding] = []
    host = _host(doc)
    loc = _location(host)
    certs = doc.get("certs")
    if not isinstance(certs, list):
        certs = []
    # Prefer leaf from details.certChains / first cert
    for cert in certs:
        if not isinstance(cert, dict):
            continue
        issues = int(cert.get("issues") or 0)
        sig = str(cert.get("sigAlg") or "")
        if issues & 4:  # not after / expired
            out.append(
                NormalizedFinding(
                    tool="ssllabs",
                    rule_id="ssllabs/cert_expired",
                    variant="cert_expirationStatus",
                    title="TLS: certificate expired or not yet valid",
                    severity="high",
                    location=loc,
                    description=f"SSL Labs certificate issues bitfield includes expiry. sigAlg={sig}",
                    recommendation="Replace the certificate before it expires.",
                    cwe=298,
                )
            )
        if issues & 1:  # no chain of trust
            out.append(
                NormalizedFinding(
                    tool="ssllabs",
                    rule_id="ssllabs/cert_chain",
                    variant="cert_chain_of_trust",
                    title="TLS: certificate chain of trust incomplete",
                    severity="high",
                    location=loc,
                    description="SSL Labs reports no chain of trust for the server certificate.",
                    recommendation="Serve the full intermediate chain with the leaf certificate.",
                    cwe=295,
                )
            )
        if issues & 256 or any(x in sig.upper() for x in ("SHA1", "MD5", "SHA224")):
            out.append(
                NormalizedFinding(
                    tool="ssllabs",
                    rule_id="ssllabs/cert_sig",
                    variant="cert_signatureAlgorithm",
                    title="TLS: weak signature or hash algorithm offered (SHA224/SHA1/MD5)",
                    severity="low",
                    location=loc,
                    description=f"Certificate signature algorithm: {sig or 'insecure signature flag'}",
                    recommendation="Prefer SHA256+ signature algorithms; disable SHA224/SHA1/MD5.",
                    cwe=327,
                )
            )
        break  # leaf / first cert only
    return out


def _detail_findings(doc: dict[str, Any], ep: dict[str, Any]) -> list[NormalizedFinding]:
    details = ep.get("details") if isinstance(ep.get("details"), dict) else {}
    if not details and isinstance(ep.get("protocols"), list):
        details = ep
    host = _host(doc)
    port = ep.get("port")
    try:
        port_i = int(port) if port is not None else 443
    except (TypeError, ValueError):
        port_i = 443
    loc = _location(host, port_i)
    out: list[NormalizedFinding] = []

    for proto in details.get("protocols") or []:
        if not isinstance(proto, dict):
            continue
        key = (str(proto.get("name") or "").upper(), str(proto.get("version") or ""))
        mapped = _WEAK_PROTOCOLS.get(key)
        if not mapped:
            # Also match "TLSv1.0" style in version alone
            ver = str(proto.get("version") or "")
            name = str(proto.get("name") or "")
            if name.upper() == "TLS" and ver in ("1.0", "1.1"):
                mapped = ("TLS1" if ver == "1.0" else "TLS1_1", "medium")
            elif "SSL" in name.upper() and ver.startswith("2"):
                mapped = ("SSLv2", "high")
            elif "SSL" in name.upper() and ver.startswith("3"):
                mapped = ("SSLv3", "high")
        if not mapped:
            continue
        variant, severity = mapped
        out.append(
            NormalizedFinding(
                tool="ssllabs",
                rule_id=f"ssllabs/{variant}",
                variant=variant,
                title=f"TLS: weak protocol {proto.get('name')} {proto.get('version')} offered",
                severity=severity,
                location=loc,
                description=f"SSL Labs lists protocol {proto.get('name')} {proto.get('version')} as supported.",
                recommendation="Disable SSLv2/SSLv3 and TLS 1.0/1.1; offer TLS 1.2+ only.",
                cwe=326,
            )
        )

    if details.get("heartbleed") is True:
        out.append(
            NormalizedFinding(
                tool="ssllabs",
                rule_id="ssllabs/heartbleed",
                variant="heartbleed",
                title="TLS: Heartbleed vulnerability",
                severity="critical",
                location=loc,
                description="SSL Labs reports the endpoint as vulnerable to Heartbleed.",
                recommendation="Upgrade OpenSSL / the TLS stack and reissue certificates if needed.",
                cwe=119,
            )
        )

    if details.get("ocspStapling") is False:
        out.append(
            NormalizedFinding(
                tool="ssllabs",
                rule_id="ssllabs/OCSP_stapling",
                variant="OCSP_stapling",
                title="TLS: OCSP stapling not offered",
                severity="info",
                location=loc,
                description="SSL Labs reports OCSP stapling is not offered.",
                recommendation="Enable OCSP stapling on the TLS terminator.",
                cwe=299,
            )
        )

    # Weak RC4
    if details.get("supportsRc4") is True or details.get("rc4Only") is True:
        out.append(
            NormalizedFinding(
                tool="ssllabs",
                rule_id="ssllabs/rc4",
                variant="rc4",
                title="TLS: RC4 cipher suites offered",
                severity="high",
                location=loc,
                description="SSL Labs reports RC4 support on this endpoint.",
                recommendation="Disable all RC4 cipher suites.",
                cwe=326,
            )
        )

    out.extend(_cert_issues(doc, details))
    return out


def parse(raw: bytes) -> list[NormalizedFinding]:
    doc = json.loads(raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw)
    if isinstance(doc, list):
        # ssllabs-scan default: array of host reports
        findings: list[NormalizedFinding] = []
        for item in doc:
            if isinstance(item, dict):
                findings.extend(_parse_host(item))
        return findings
    if not isinstance(doc, dict):
        return []
    return _parse_host(doc)


def _parse_host(doc: dict[str, Any]) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    seen: set[str] = set()
    for ep in _endpoints(doc):
        for nf in _detail_findings(doc, ep):
            key = f"{nf.variant}|{nf.location}|{nf.title}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(nf)
    return findings
