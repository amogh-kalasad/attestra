"""Name → scanner adapter registry."""

from __future__ import annotations

from attestra.runner.scanners.base import ScannerAdapter
from attestra.runner.scanners.nuclei import NucleiAdapter
from attestra.runner.scanners.semgrep import SemgrepAdapter
from attestra.runner.scanners.trivy import TrivyAdapter
from attestra.runner.scanners.zap import ZapAdapter

_ADAPTERS: dict[str, ScannerAdapter] = {
    "trivy": TrivyAdapter(),
    "semgrep": SemgrepAdapter(),
    "nuclei": NucleiAdapter(),
    "zap": ZapAdapter(),
}


def get_adapter(name: str) -> ScannerAdapter:
    try:
        return _ADAPTERS[name.lower()]
    except KeyError as exc:
        raise KeyError(f"unknown scanner {name!r}; choose from {sorted(_ADAPTERS)}") from exc


def list_adapters() -> list[str]:
    return sorted(_ADAPTERS)
