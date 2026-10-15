"""ZAP adapter: runs the ZAP Docker image against the pinned target and quarantines out-of-scope reports.

The report folder is mounted at /zap/wrk, the only place zap-baseline.py / zap-full-scan.py
write their -J report. Exit codes 1 (WARN) and 2 (FAIL) still come with a valid report.
"""

from __future__ import annotations

import json
from pathlib import Path

from attestra.runner.authorization import AuthorizedScope, authorize_target
from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import (
    ScannerAdapter,
    ScannerResult,
    docker_available,
    docker_run_argv,
    new_container_name,
)
from attestra.runner.scanners.nuclei_policy import is_active_profile

ZAP_WRK = "/zap/wrk"
REPORT_NAME = "zap-report.json"
# Baseline spiders for at most 1 minute and only runs passive rules; full adds the active scan.
SCRIPTS = {"baseline": "zap-baseline.py", "active": "zap-full-scan.py"}


def zap_script(profile: str) -> str:
    return SCRIPTS["active"] if is_active_profile(profile) else SCRIPTS["baseline"]


class ZapAdapter(ScannerAdapter):
    name = "zap"
    import_tool = "zap"
    image_key = "zap"
    out_name = REPORT_NAME
    default_timeout_s = 1800  # the active (full) scan takes much longer than the baseline

    def available(self) -> bool:
        # ZAP only runs in Docker, from a configured digest-pinned image.
        return docker_available() and self.image_configured()

    def version(self) -> str:
        return "zap"

    def build_argv(
        self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline", name: str = ""
    ) -> list[str]:
        if not isinstance(target, PinnedTarget):
            raise ValueError("ZAP requires a PinnedTarget")
        image = self.image_ref()
        target_url = f"{target.scheme}://{target.host_header}/"
        args = [zap_script(profile), "-t", target_url, "-J", out_file.name, "-m", "1", "-T", "10"]
        # The host name is always pinned to the gate's IP (--add-host) so ZAP cannot resolve elsewhere.
        return docker_run_argv(
            image,
            name=name or new_container_name(self.name),
            mounts=[(out_file.parent, ZAP_WRK, "rw")],
            add_hosts=[(target.host, target.ip)],
            args=args,
        )

    def build_docker_argv(self, target, *, out_file: Path, profile: str = "baseline", name: str = "", **opts):
        return self.build_argv(target, out_file=out_file, profile=profile, name=name)

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
        sr = super().scan(pin, out_dir=out_dir, cancel=cancel, profile=profile)
        if scope is not None and sr.raw_path is not None and sr.raw_path.exists():
            reason = self.quarantine_if_out_of_scope(sr.raw_path.read_bytes(), scope)
            if reason:
                sr.quarantine = True
                sr.quarantine_reason = reason
        return sr
