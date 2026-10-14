"""testssl.sh importer: `--jsonfile` (flat list) and `--jsonfile-pretty` output."""

from __future__ import annotations

from attestra.importers._jsonutil import load_json_or_lines
from attestra.importers.base import NormalizedFinding, norm_severity, parse_cwe

_SKIP = {"OK", "INFO", "DEBUG", "FATAL", ""}


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


def parse(raw: bytes) -> list[NormalizedFinding]:
    doc = load_json_or_lines(raw)
    out: list[NormalizedFinding] = []
    for e, host, port in _entries(doc):
        sev = str(e.get("severity", "")).upper()
        if sev in _SKIP:
            continue
        severity = "low" if sev == "WARN" else norm_severity(sev)
        cves = [c for c in str(e.get("cve", "")).split() if c.upper().startswith("CVE-")]
        check = str(e.get("id", ""))
        out.append(
            NormalizedFinding(
                tool="testssl",
                rule_id=check,
                title=f"TLS: {check} - {e.get('finding', '')}"[:500],
                severity=severity,
                location=f"{host}:{port}" if port else host,
                description=str(e.get("finding", "")),
                recommendation="Review the TLS configuration against PCI DSS 4.2.1 and current Mozilla guidance.",
                cwe=parse_cwe(e.get("cwe")) or 326,
                cves=cves,
                param=check,
            )
        )
    return out
