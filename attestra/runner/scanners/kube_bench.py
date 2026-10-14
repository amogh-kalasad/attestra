"""kube-bench adapter: CIS Kubernetes benchmark, JSON imported via kube_bench importer."""

from __future__ import annotations

from pathlib import Path

from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import ScannerAdapter, which

TARGETS = ("master", "node", "controlplane", "etcd", "policies")


class KubeBenchAdapter(ScannerAdapter):
    name = "kube_bench"
    import_tool = "kube_bench"

    def available(self) -> bool:
        return which("kube-bench") is not None

    def version(self) -> str:
        return "kube-bench"

    def build_argv(self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline") -> list[str]:
        if isinstance(target, PinnedTarget):
            raise ValueError("kube-bench runs on the cluster node; pass a benchmark target such as 'node'")
        targets = [t.strip().lower() for t in str(target or "node").split(",") if t.strip()]
        bad = [t for t in targets if t not in TARGETS]
        if bad:
            raise ValueError(f"unknown kube-bench targets {bad}; choose from {TARGETS}")
        return ["kube-bench", "run", "--targets", ",".join(targets), "--json", "--outputfile", str(out_file)]
