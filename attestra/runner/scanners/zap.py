"""ZAP adapter: runs the ZAP Docker image against the pinned target and quarantines out-of-scope reports.

The report folder is mounted at /zap/wrk, the only place zap-baseline.py / zap-full-scan.py
write their -J report. Exit codes 1 (WARN) and 2 (FAIL) still come with a valid report.

Optional authenticated scans (Phase 7 / auth-web): when ``ATTESTRA_AUTH_WEB_ENABLED`` is on and
``auth_context_path`` / ``auth_opts`` point at a prepared context under ``out_dir``, the adapter
adds ``-n /zap/wrk/<file>`` (and optional ``-U <user>``). Secrets must already live in that
mounted file — never pass passwords via ``-z`` or other argv that ScanRun/extra would log.
Without auth opts (or with the feature flag off), behavior matches the unauthenticated baseline.
"""
# @lat: [[runner#ZAP authentication]]

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from attestra import config
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


def _resolve_auth_wiring(
    *,
    out_file: Path,
    auth_context_path: Path | str | None = None,
    auth_opts: dict[str, Any] | None = None,
) -> tuple[str | None, str]:
    """Return ``(container_context_path, zap_user)`` when auth wiring is active.

    Auth is a no-op unless ``AUTH_WEB_ENABLED`` and a context file path is provided.
    Only ``.context`` files get ``-n``; JSON/YAML auth payloads stay on the mount for
    hooks/automation without putting secrets on argv.
    """
    if not config.AUTH_WEB_ENABLED:
        return None, ""
    opts = dict(auth_opts or {})
    raw_path = auth_context_path if auth_context_path is not None else opts.get("context_path") or opts.get(
        "auth_context_path"
    )
    zap_user = str(opts.get("user") or opts.get("zap_user") or "").strip()
    if not raw_path:
        return None, zap_user
    path = Path(raw_path)
    if not path.is_file():
        # Allow a bare filename that already lives next to the report.
        alt = out_file.parent / path.name
        path = alt if alt.is_file() else path
    if not path.is_file():
        return None, zap_user
    # Only wire -n for classic context files; never embed secrets via -z.
    if path.suffix.lower() != ".context":
        return None, zap_user
    # Context must sit on the /zap/wrk mount (report parent).
    try:
        path.resolve().relative_to(out_file.parent.resolve())
    except ValueError:
        return None, zap_user
    return f"{ZAP_WRK}/{path.name}", zap_user


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
        self,
        target: PinnedTarget | str,
        *,
        out_file: Path,
        profile: str = "baseline",
        name: str = "",
        auth_context_path: Path | str | None = None,
        auth_opts: dict[str, Any] | None = None,
        **_opts,
    ) -> list[str]:
        if not isinstance(target, PinnedTarget):
            raise ValueError("ZAP requires a PinnedTarget")
        image = self.image_ref()
        target_url = f"{target.scheme}://{target.host_header}/"
        args = [zap_script(profile), "-t", target_url, "-J", out_file.name, "-m", "1", "-T", "10"]
        ctx_path, zap_user = _resolve_auth_wiring(
            out_file=out_file,
            auth_context_path=auth_context_path,
            auth_opts=auth_opts,
        )
        if ctx_path:
            args += ["-n", ctx_path]
            if zap_user:
                args += ["-U", zap_user]
        # The host name is always pinned to the gate's IP (--add-host) so ZAP cannot resolve elsewhere.
        return docker_run_argv(
            image,
            name=name or new_container_name(self.name),
            mounts=[(out_file.parent, ZAP_WRK, "rw")],
            add_hosts=[(target.host, target.ip)],
            args=args,
        )

    def build_docker_argv(self, target, *, out_file: Path, profile: str = "baseline", name: str = "", **opts):
        return self.build_argv(target, out_file=out_file, profile=profile, name=name, **opts)

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
        auth_context_path: Path | str | None = None,
        auth_opts: dict[str, Any] | None = None,
        **opts,
    ) -> ScannerResult:
        sr = super().scan(
            pin,
            out_dir=out_dir,
            cancel=cancel,
            profile=profile,
            auth_context_path=auth_context_path,
            auth_opts=auth_opts,
            **opts,
        )
        if scope is not None and sr.raw_path is not None and sr.raw_path.exists():
            reason = self.quarantine_if_out_of_scope(sr.raw_path.read_bytes(), scope)
            if reason:
                sr.quarantine = True
                sr.quarantine_reason = reason
        return sr
