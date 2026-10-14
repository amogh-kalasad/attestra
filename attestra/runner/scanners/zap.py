"""ZAP adapter — pinned host via --add-host; quarantine if report sites leave scope."""

from __future__ import annotations

import json
from pathlib import Path

from attestra import config
from attestra.runner.authorization import AuthorizedScope, authorize_target
from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import ScannerAdapter, ScannerResult, require_digest_image, run_process, which


class ZapAdapter(ScannerAdapter):
    name = "zap"
    import_tool = "zap"

    def available(self) -> bool:
        return which("docker") is not None or which("zap-baseline.py") is not None

    def version(self) -> str:
        return "zap"

    def image_ref(self) -> str:
        return require_digest_image(config.SCANNER_IMAGES["zap"])

    def build_argv(self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline") -> list[str]:
        if not isinstance(target, PinnedTarget):
            raise ValueError("ZAP requires a PinnedTarget")
        image = self.image_ref()
        target_url = f"{target.scheme}://{target.host_header}/"
        # Always pin host → IP so ZAP cannot resolve elsewhere.
        return [
            "docker",
            "run",
            "--rm",
            "--add-host",
            f"{target.host}:{target.ip}",
            image,
            "zap-baseline.py",
            "-t",
            target_url,
            "-J",
            str(out_file.name),
        ]

    def quarantine_if_out_of_scope(self, report: bytes, scope: AuthorizedScope) -> str | None:
        """Return reason string if any site URL is out of scope."""
        try:
            doc = json.loads(report)
        except json.JSONDecodeError:
            return "invalid ZAP JSON"
        sites = doc.get("site", [])
        if isinstance(sites, dict):
            sites = [sites]
        for site in sites:
            name = site.get("@name") or site.get("name") or ""
            if not name:
                continue
            try:
                authorize_target(scope, name, "url")
                # Also check instance URIs
                for alert in site.get("alerts") or []:
                    for inst in alert.get("instances") or []:
                        uri = inst.get("uri") or ""
                        if uri:
                            authorize_target(scope, uri, "url")
            except Exception as exc:
                return str(exc)
        return None

    def scan(  # type: ignore[override]
        self,
        pin: PinnedTarget | str,
        *,
        out_dir: Path,
        cancel=None,
        profile: str = "baseline",
        scope: AuthorizedScope | None = None,
    ) -> ScannerResult:
        config.ensure_dirs()
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / "zap-report.json"
        argv = self.build_argv(pin, out_file=out_file, profile=profile)
        # Prefer writing into a mounted path; for argv tests we only care about flags.
        result = run_process(argv, cancel=cancel)
        raw = out_file.read_bytes() if out_file.exists() else result.stdout
        if not out_file.exists() and raw:
            out_file.write_bytes(raw)
        digest = ""
        try:
            digest = self.image_ref().split("@", 1)[-1]
        except ValueError:
            digest = ""
        sr = ScannerResult(
            tool=self.name,
            tool_version=self.version(),
            image_digest=digest,
            raw_path=out_file if out_file.exists() else None,
            import_tool=self.import_tool,
            extra={"returncode": result.returncode, "argv": argv},
        )
        if scope is not None and out_file.exists():
            reason = self.quarantine_if_out_of_scope(out_file.read_bytes(), scope)
            if reason:
                sr.quarantine = True
                sr.quarantine_reason = reason
        return sr
