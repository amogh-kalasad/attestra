"""Name → scanner adapter registry."""

from __future__ import annotations

from attestra.runner.scanners.base import ScannerAdapter
from attestra.runner.scanners.checkov import CheckovAdapter
from attestra.runner.scanners.gitleaks import GitleaksAdapter
from attestra.runner.scanners.kube_bench import KubeBenchAdapter
from attestra.runner.scanners.naabu import NaabuAdapter
from attestra.runner.scanners.nuclei import NucleiAdapter
from attestra.runner.scanners.prowler import ProwlerAdapter
from attestra.runner.scanners.semgrep import SemgrepAdapter
from attestra.runner.scanners.testssl import TlsTestsslAdapter
from attestra.runner.scanners.trivy import TrivyAdapter
from attestra.runner.scanners.webcheck import WebcheckAdapter
from attestra.runner.scanners.zap import ZapAdapter

_ADAPTERS: dict[str, ScannerAdapter] = {
    "trivy": TrivyAdapter(),
    "semgrep": SemgrepAdapter(),
    "nuclei": NucleiAdapter(),
    "zap": ZapAdapter(),
    "prowler": ProwlerAdapter(),
    "kube_bench": KubeBenchAdapter(),
    "testssl": TlsTestsslAdapter(),
    "gitleaks": GitleaksAdapter(),
    "checkov": CheckovAdapter(),
    "naabu": NaabuAdapter(),
    "webcheck": WebcheckAdapter(),
}


def get_adapter(name: str) -> ScannerAdapter:
    try:
        return _ADAPTERS[name.lower()]
    except KeyError as exc:
        raise KeyError(f"unknown scanner {name!r}; choose from {sorted(_ADAPTERS)}") from exc


def list_adapters() -> list[str]:
    return sorted(_ADAPTERS)
