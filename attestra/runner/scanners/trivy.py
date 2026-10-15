"""Trivy adapter: filesystem (repo path) or container image scans; output imported via trivy importer."""

from __future__ import annotations

from pathlib import Path

from attestra import config
from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import CONTAINER_OUT, CONTAINER_SRC, ScannerAdapter, which


def trivy_mode(target: str) -> str:
    """``fs`` for a folder on this machine, ``image`` for a registry reference like repo/name:tag."""
    if Path(target).exists():
        return "fs"
    last = target.split("/")[-1]
    if "/" in target and (":" in last or "@sha256:" in target):
        return "image"
    if "@sha256:" in target:
        return "image"
    return "fs"


def _src_dir(target: str) -> Path:
    path = Path(target).expanduser().resolve()
    if not path.exists():
        raise ValueError(f"path {target!r} was not found on the scanning machine")
    return path


class TrivyAdapter(ScannerAdapter):
    name = "trivy"
    import_tool = "trivy"
    image_key = "trivy"

    def available(self) -> bool:
        return which("trivy") is not None

    def version(self) -> str:
        return "trivy"

    def build_argv(self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline") -> list[str]:
        if isinstance(target, PinnedTarget):
            raise ValueError("trivy fs/image adapters expect a path or image string, not a URL pin")
        target_s = str(target)
        return ["trivy", trivy_mode(target_s), "--format", "json", "--output", str(out_file), "--quiet", target_s]

    def docker_mounts(self, target, *, out_file: Path):
        if isinstance(target, PinnedTarget):
            raise ValueError("trivy fs/image adapters expect a path or image string, not a URL pin")
        cache = config.SCANNER_CACHE_DIR / "trivy"
        cache.mkdir(parents=True, exist_ok=True)
        mounts = [(out_file.parent, CONTAINER_OUT, "rw"), (cache, "/root/.cache/trivy", "rw")]
        if trivy_mode(str(target)) == "fs":
            mounts.append((_src_dir(str(target)), CONTAINER_SRC, "ro"))
        return mounts

    def docker_args(self, target, *, out_file: Path, profile: str = "baseline", **_):
        target_s = str(target)
        mode = trivy_mode(target_s)
        scan_target = CONTAINER_SRC if mode == "fs" else target_s
        return [mode, "--format", "json", "--output", f"{CONTAINER_OUT}/{out_file.name}", "--quiet", scan_target]
