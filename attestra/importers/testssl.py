"""testssl.sh importer: `--jsonfile` (flat list) and `--jsonfile-pretty` output."""

from __future__ import annotations

import re

from attestra.importers._jsonutil import load_json_or_lines
from attestra.importers.base import NormalizedFinding, norm_severity, parse_cwe

_SKIP = {"OK", "INFO", "DEBUG", "FATAL", ""}

# Weak cert / handshake signature hashes kept even at INFO/OK (R17).
_WEAK_SIG_RE = re.compile(r"\b(SHA224|SHA1|MD5)\b", re.IGNORECASE)
_SIG_IDS = {"cert_signatureAlgorithm", "signature_algorithm"}
_OCSP_STAPLING_IDS = {"OCSP_stapling", "ocsp_stapling"}
_EMPTY_OCSP = {"", "--", "none", "n/a"}


def _entries(doc) -> list[tuple[dict, str, str]]:
    """Yield (entry, host, port) for both output shapes."""
    out: list[tuple[dict, str, str]] = []
    if isinstance(doc, list):
        for e in doc:
            if isinstance(e, dict):
                host = str(e.get("ip", "")).split("/")[0]
                out.append((e, host, str(e.get("port", ""))))
        return out
    if isinstance(doc, dict):
        for target in doc.get("scanResult") or []:
            host = target.get("targetHost") or str(target.get("ip", "")).split("/")[0]
            port = str(target.get("port", ""))
            for value in target.values():
                if isinstance(value, list):
                    out += [(e, host, port) for e in value if isinstance(e, dict)]
    return out


def _has_ocsp_url(entries: list[tuple[dict, str, str]]) -> bool:
    for e, _, _ in entries:
        if str(e.get("id", "")) != "cert_ocspURL":
            continue
        finding = str(e.get("finding", "")).strip()
        if finding.lower() not in _EMPTY_OCSP:
            return True
    return False


def _is_r17(check: str, finding: str) -> bool:
    if check in _SIG_IDS and _WEAK_SIG_RE.search(finding):
        return True
    # Broader text match for signature-algorithm findings naming weak hashes.
    if "signature" in check.lower() and _WEAK_SIG_RE.search(finding):
        return True
    if re.search(r"signature\s+algorithm", finding, re.IGNORECASE) and _WEAK_SIG_RE.search(finding):
        return True
    return False


def _is_r18(check: str, finding: str) -> bool:
    if check not in _OCSP_STAPLING_IDS:
        return False
    return "not offered" in finding.lower()


def parse(raw: bytes) -> list[NormalizedFinding]:
    doc = load_json_or_lines(raw)
    entries = _entries(doc)
    has_ocsp = _has_ocsp_url(entries)
    out: list[NormalizedFinding] = []
    for e, host, port in entries:
        sev = str(e.get("severity", "")).upper()
        check = str(e.get("id", ""))
        finding = str(e.get("finding", ""))
        location = f"{host}:{port}" if port else host
        cves = [c for c in str(e.get("cve", "")).split() if c.upper().startswith("CVE-")]

        if _is_r17(check, finding):
            out.append(
                NormalizedFinding(
                    tool="testssl",
                    rule_id=check,
                    title="TLS: weak signature or hash algorithm offered (SHA224/SHA1/MD5)",
                    severity="low",
                    location=location,
                    description=finding,
                    recommendation="Prefer SHA256+ signature algorithms; disable SHA224/SHA1/MD5.",
                    cwe=327,
                    cves=cves,
                    param=check,
                    variant=check,
                )
            )
            continue

        if _is_r18(check, finding) and has_ocsp:
            out.append(
                NormalizedFinding(
                    tool="testssl",
                    rule_id=check,
                    title="TLS: OCSP stapling not offered",
                    severity="info",
                    location=location,
                    description=finding,
                    recommendation="Enable OCSP stapling when an OCSP responder URL is present on the certificate.",
                    cwe=299,
                    cves=cves,
                    param=check,
                    variant=check,
                )
            )
            continue

        if sev in _SKIP:
            continue
        severity = "low" if sev == "WARN" else norm_severity(sev)
        out.append(
            NormalizedFinding(
                tool="testssl",
                rule_id=check,
                title=f"TLS: {check} - {e.get('finding', '')}"[:500],
                severity=severity,
                location=location,
                description=finding,
                recommendation="Review the TLS configuration against PCI DSS 4.2.1 and current Mozilla guidance.",
                cwe=parse_cwe(e.get("cwe")) or 326,
                cves=cves,
                param=check,
            )
        )
    return out
