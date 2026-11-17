"""Semgrep adapter: SARIF output imported via sarif importer.

F-03: Attestra's own GitHub Actions rules (``semgrep_rules/gha-*.yml`` next to this
module: script
injection, pull_request_target head checkout, unpinned third-party actions,
``permissions: write-all``) are added as a second ``--config`` when the rules
directory exists. Set ``ATTESTRA_SEMGREP_GHA_RULES=0`` to scan with the registry
pack only (previous behaviour).
"""
# @lat: [[intel-and-reporting#Semgrep GitHub Actions rules]]

from __future__ import annotations

import os
from pathlib import Path

from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import CONTAINER_OUT, CONTAINER_SRC, ScannerAdapter, which
from attestra.runner.scanners.trivy import _src_dir

# Registry rule pack; unlike "auto" it works with metrics turned off.
RULES = "p/default"
# Versioned GitHub Actions rules shipped inside the package. They are deliberately NOT in
# policy/: `opa eval -d policy/` loads every *.yml there as OPA data and the rule files
# collide ("merge error ... data.semgrep.rules"). Wheel/image packaging needs the
# package-data glob added by INT (WIRING_WP3.md); a missing dir => registry pack only.
GHA_RULES_DIR = Path(__file__).resolve().parent / "semgrep_rules"
RULES_SUBDIR = "attestra-gha-rules"


def gha_rules_enabled() -> bool:
    if os.environ.get("ATTESTRA_SEMGREP_GHA_RULES", "1").strip().lower() in ("0", "false", "no", "off"):
        return False
    return GHA_RULES_DIR.is_dir() and any(GHA_RULES_DIR.glob("gha-*.yml"))


def stage_rules(out_dir: Path) -> Path | None:
    """Copy the GHA rules next to the scan output so the already-mounted /out dir carries
    them into the scanner container (no extra host bind mount / path translation)."""
    if not gha_rules_enabled():
        return None
    dest = Path(out_dir) / RULES_SUBDIR
    dest.mkdir(parents=True, exist_ok=True)
    for f in sorted(GHA_RULES_DIR.glob("gha-*.yml")):
        (dest / f.name).write_bytes(f.read_bytes())
    return dest


def _config_args(rules_path: str | None) -> list[str]:
    args = ["--config", RULES]
    if rules_path:
        args += ["--config", rules_path]
    return args


class SemgrepAdapter(ScannerAdapter):
    name = "semgrep"
    import_tool = "sarif"
    image_key = "semgrep"
    out_name = "semgrep-out.sarif"

    def available(self) -> bool:
        return which("semgrep") is not None

    def version(self) -> str:
        return "semgrep"

    def build_argv(self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline") -> list[str]:
        if isinstance(target, PinnedTarget):
            raise ValueError("semgrep expects a filesystem path")
        rules = str(GHA_RULES_DIR) if gha_rules_enabled() else None
        return ["semgrep", "scan", *_config_args(rules), "--metrics", "off", "--sarif", "--output", str(out_file), str(target)]

    def docker_mounts(self, target, *, out_file: Path):
        if isinstance(target, PinnedTarget):
            raise ValueError("semgrep expects a filesystem path")
        return [(out_file.parent, CONTAINER_OUT, "rw"), (_src_dir(str(target)), CONTAINER_SRC, "ro")]

    def docker_args(self, target, *, out_file: Path, profile: str = "baseline", **_):
        staged = stage_rules(out_file.parent)
        rules = f"{CONTAINER_OUT}/{RULES_SUBDIR}" if staged else None
        return [
            "semgrep", "scan", *_config_args(rules), "--metrics", "off", "--sarif",
            "--output", f"{CONTAINER_OUT}/{out_file.name}", CONTAINER_SRC,
        ]
