"""Burp Suite import façade for Elite workflows (reuses attestra.importers.burp)."""

from __future__ import annotations

from typing import Any

from attestra.importers import burp as burp_importer
from attestra.proof.capture import extract_pairs
from attestra.proof.pair import HttpPair

# @lat: [[architecture#Elite automated security testing#Burp import]]


def import_burp_bytes(data: bytes) -> dict[str, Any]:
    """Parse Burp Issues XML into normalized findings plus HTTP pairs when present."""
    findings = list(burp_importer.parse(data))
    pairs: list[HttpPair] = []
    try:
        pairs = extract_pairs("burp", data)
    except Exception:
        pairs = []
    return {
        "finding_count": len(findings),
        "findings": [
            {
                "title": f.title,
                "severity": f.severity,
                "cwe": f.cwe,
                "location": f.location,
                "confidence": getattr(f, "confidence", "") or "",
            }
            for f in findings
        ],
        "http_pair_count": len(pairs),
        "http_pairs_redacted": [p.redacted().to_bytes().decode("utf-8", "replace") for p in pairs[:20]],
    }
