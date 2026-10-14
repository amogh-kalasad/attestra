"""Nuclei adapter — JSONL output imported via nuclei importer."""

from __future__ import annotations

from pathlib import Path

from attestra import config
from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import ScannerAdapter, require_digest_image, which
from attestra.runner.scanners.nuclei_policy import templates_allowed


class NucleiAdapter(ScannerAdapter):
    name = "nuclei"
    import_tool = "nuclei"

    def available(self) -> bool:
        return which("nuclei") is not None

    def version(self) -> str:
        return "nuclei"

    def image_ref(self) -> str:
        return require_digest_image(config.SCANNER_IMAGES["nuclei"])

    def build_argv(
        self,
        target: PinnedTarget | str,
        *,
        out_file: Path,
        profile: str = "baseline",
        intrusive_allowed: bool = False,
    ) -> list[str]:
        if isinstance(target, PinnedTarget):
            url = f"{target.scheme}://{target.host_header}/"
        else:
            url = str(target)
        tags = templates_allowed(profile=profile, intrusive_allowed=intrusive_allowed)
        return [
            "nuclei",
            "-u",
            url,
            "-jsonl",
            "-o",
            str(out_file),
            "-tags",
            tags[0],
            "-silent",
        ]

    def scan(self, pin, *, out_dir, cancel=None, profile="baseline", intrusive_allowed=False):  # type: ignore[override]
        # Custom scan to pass intrusive_allowed into argv builder
        from attestra import config as cfg
        from attestra.runner.scanners.base import ScannerResult, run_process

        cfg.ensure_dirs()
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"{self.name}-out.jsonl"
        argv = self.build_argv(pin, out_file=out_file, profile=profile, intrusive_allowed=intrusive_allowed)
        result = run_process(argv, cancel=cancel)
        raw = out_file.read_bytes() if out_file.exists() else result.stdout
        if not out_file.exists():
            out_file.write_bytes(raw)
        return ScannerResult(
            tool=self.name,
            tool_version=self.version(),
            raw_path=out_file,
            import_tool=self.import_tool,
            extra={"returncode": result.returncode},
        )
