"""Importers turn existing scanner result files into NormalizedFinding records.

Attestra does not run scanners. Testers run them under their own signed
authorization and import the results here.
"""
# @lat: [[architecture#Import do not execute]]
# @lat: [[import-pipeline#Supported formats]]

from __future__ import annotations

from collections.abc import Callable

from attestra.importers import (
    burp,
    checkov,
    cyclonedx,
    dependency_track,
    dnsx,
    garak,
    gitleaks,
    httpx_probe,
    kube_bench,
    naabu,
    nessus,
    nuclei,
    observatory,
    promptfoo,
    prowler,
    pyrit,
    safelabs,
    sarif,
    ssllabs,
    subfinder,
    testssl,
    trivy,
    webcheck,
    zap,
)
from attestra.importers.base import NormalizedFinding

PARSERS: dict[str, Callable[[bytes], list[NormalizedFinding]]] = {
    "zap": zap.parse,
    "nuclei": nuclei.parse,
    "trivy": trivy.parse,
    "sarif": sarif.parse,
    "cyclonedx": cyclonedx.parse,
    "dependency_track": dependency_track.parse,
    # Phase 7.3 scanners
    "prowler": prowler.parse,
    "kube_bench": kube_bench.parse,
    "testssl": testssl.parse,
    "gitleaks": gitleaks.parse,
    "checkov": checkov.parse,
    "naabu": naabu.parse,
    "webcheck": webcheck.parse,
    "observatory": observatory.parse,
    "ssllabs": ssllabs.parse,
    "burp": burp.parse,
    "nessus": nessus.parse,
    # AASI Phase 1 — AI-security result importers (parse only; adapters in Phase 2)
    "garak": garak.parse,
    "promptfoo": promptfoo.parse,
    "safelabs": safelabs.parse,
    "pyrit": pyrit.parse,
    # WP4 discovery importers: always return [] (observations go through attestra.discovery)
    "subfinder": subfinder.parse,
    "dnsx": dnsx.parse,
    "httpx_probe": httpx_probe.parse,
}

# Parsers that never produce findings (discovery observations only); hidden from import pickers.
DISCOVERY_PARSERS: frozenset[str] = frozenset({"subfinder", "dnsx", "httpx_probe"})


def parse(tool: str, raw: bytes) -> list[NormalizedFinding]:
    try:
        parser = PARSERS[tool.lower()]
    except KeyError:
        raise ValueError(f"Unsupported format '{tool}'. Supported: {', '.join(sorted(PARSERS))}") from None
    return parser(raw)


__all__ = ["DISCOVERY_PARSERS", "NormalizedFinding", "PARSERS", "parse"]
