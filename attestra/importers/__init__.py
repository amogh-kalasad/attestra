"""Importers turn existing scanner result files into NormalizedFinding records.

Attestra does not run scanners. Testers run them under their own signed
authorization and import the results here.
"""
# @lat: [[architecture#Import do not execute]]
# @lat: [[import-pipeline#Supported formats]]

from __future__ import annotations

from collections.abc import Callable

from attestra.importers import nuclei, sarif, trivy, zap
from attestra.importers.base import NormalizedFinding

PARSERS: dict[str, Callable[[bytes], list[NormalizedFinding]]] = {
    "zap": zap.parse,
    "nuclei": nuclei.parse,
    "trivy": trivy.parse,
    "sarif": sarif.parse,
}


def parse(tool: str, raw: bytes) -> list[NormalizedFinding]:
    try:
        parser = PARSERS[tool.lower()]
    except KeyError:
        raise ValueError(f"Unsupported format '{tool}'. Supported: {', '.join(sorted(PARSERS))}") from None
    return parser(raw)


__all__ = ["NormalizedFinding", "PARSERS", "parse"]
