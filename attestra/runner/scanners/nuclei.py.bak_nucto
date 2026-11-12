"""Nuclei adapter: JSONL output imported via the nuclei importer.

Runs the digest-pinned nuclei image when configured (templates cached under the scanner cache
folder), else a local ``nuclei`` binary. Baseline excludes intrusive / DoS / fuzz / brute-force
templates and never uses out-of-band (interactsh) callbacks.
"""

from __future__ import annotations

from pathlib import Path

from attestra import config
from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import (
    CONTAINER_OUT,
    ScannerAdapter,
    docker_run_argv,
    new_container_name,
    prepare_docker_bind_mounts,
    which,
)
from attestra.runner.scanners.nuclei_policy import excluded_tags, templates_allowed

DEFAULT_RATE_LIMIT = "50"


def rate_limit() -> str:
    """Nuclei -rl (requests/sec). Lower it for Cloudflare/WAF-fronted targets that reset
    connections under burst: ATTESTRA_NUCLEI_RATE_LIMIT=N (1..150); default 50.
    """
    import os as _os

    raw = (_os.environ.get("ATTESTRA_NUCLEI_RATE_LIMIT") or "").strip()
    if raw.isdigit():
        n = int(raw)
        if n >= 1:
            return str(min(n, 150))
    return DEFAULT_RATE_LIMIT


# Backwards-compatible module constant (static default; call rate_limit() for the live value).
RATE_LIMIT = DEFAULT_RATE_LIMIT
# Authenticated scans: the per-scan secret dir (outside data/raw) is mounted here read-only.
CONTAINER_SECRETS = "/attestra-secrets"
STDERR_LOG_NAME = "nuclei-stderr.log"
STATS_INTERVAL_S = "60"


def _url(target: PinnedTarget | str) -> str:
    if isinstance(target, PinnedTarget):
        return f"{target.scheme}://{target.host_header}/"
    return str(target)


def nuclei_flags(
    target,
    *,
    out_path: str,
    profile: str,
    intrusive_allowed: bool,
    list_path: str | None = None,
    auth_secret_file: str | None = None,
    max_host_errors: int | None = None,
) -> list[str]:
    tags = templates_allowed(profile=profile, intrusive_allowed=intrusive_allowed)
    if max_host_errors is None:
        from attestra.runner import crawl as crawl_settings

        max_host_errors = crawl_settings.nuclei_max_host_errors()
    # -list: the root plus the target's start URLs (typed path, Extra Start URLs), same host only.
    target_args = ["-list", list_path] if list_path else ["-u", _url(target)]
    flags = [
        *target_args,
        "-jsonl",
        "-o",
        out_path,
        "-tags",
        tags[0],
        "-etags",
        excluded_tags(profile=profile),
        "-ni",  # no interactsh: never send data to out-of-band servers
        "-rl",
        rate_limit(),
        # No -silent: the banner, template/target counts, warnings, [FTL] errors and the
        # periodic -stats lines go to stderr, which is kept (redacted) as nuclei-stderr.log.
        "-stats",
        "-si",
        STATS_INTERVAL_S,
        "-nc",
    ]
    # By default nuclei skips a host for the rest of the scan after 30 errors ("found
    # unresponsive permanently"), e.g. when templates follow a redirect to a third-party login
    # page. -nmhe keeps scanning; ATTESTRA_NUCLEI_MAX_HOST_ERRORS=N restores a limit of N.
    flags += ["-mhe", str(max_host_errors)] if max_host_errors > 0 else ["-nmhe"]
    # Authenticated scan: session headers/cookies ride in a mounted authx file,
    # never on argv (keeps secrets out of process lists / audit).
    if auth_secret_file:
        flags += ["-sf", auth_secret_file]
    return flags


class NucleiAdapter(ScannerAdapter):
    name = "nuclei"
    import_tool = "nuclei"
    image_key = "nuclei"
    out_name = "nuclei-out.jsonl"
    empty_report_ok = True  # nuclei writes nothing when no template matched
    tool_log_name = STDERR_LOG_NAME
    tool_log_streams = ("stderr",)
    # The first run downloads the template library; a full baseline sends about 13,000 requests.
    default_timeout_s = 1800

    def available(self) -> bool:
        return which("nuclei") is not None

    def version(self) -> str:
        return "nuclei"

    def build_argv(
        self,
        target: PinnedTarget | str,
        *,
        out_file: Path,
        profile: str = "baseline",
        intrusive_allowed: bool = False,
        crawl=None,
        auth_secret_file: str | None = None,
        target_urls: list[str] | None = None,
        **_,
    ) -> list[str]:
        list_file = _write_targets(target, out_file.parent, crawl, urls=target_urls)
        return [
            "nuclei",
            *nuclei_flags(
                target, out_path=str(out_file), profile=profile, intrusive_allowed=intrusive_allowed,
                list_path=str(list_file) if list_file else None,
                auth_secret_file=auth_secret_file,
            ),
        ]

    def docker_mounts(self, target, *, out_file: Path):
        cache = config.SCANNER_CACHE_DIR / "nuclei"
        (cache / "templates").mkdir(parents=True, exist_ok=True)
        (cache / "config").mkdir(parents=True, exist_ok=True)
        return [
            (out_file.parent, CONTAINER_OUT, "rw"),
            (cache / "templates", "/root/nuclei-templates", "rw"),
            (cache / "config", "/root/.config/nuclei", "rw"),
        ]

    def docker_args(
        self,
        target,
        *,
        out_file: Path,
        profile: str = "baseline",
        intrusive_allowed: bool = False,
        crawl=None,
        auth_secret_file: str | None = None,
        target_urls: list[str] | None = None,
        **_,
    ):
        list_file = _write_targets(target, out_file.parent, crawl, urls=target_urls)
        # The auth file lives in the per-scan secret dir, mounted read-only at CONTAINER_SECRETS.
        sf = f"{CONTAINER_SECRETS}/{Path(auth_secret_file).name}" if auth_secret_file else None
        return nuclei_flags(
            target, out_path=f"{CONTAINER_OUT}/{out_file.name}", profile=profile, intrusive_allowed=intrusive_allowed,
            list_path=f"{CONTAINER_OUT}/{list_file.name}" if list_file else None,
            auth_secret_file=sf,
        )

    def build_docker_argv(self, target, *, out_file: Path, profile: str = "baseline", name: str = "", **opts):
        auth_secret_file = opts.get("auth_secret_file")
        mounts = list(self.docker_mounts(target, out_file=out_file))
        if auth_secret_file:
            secret_dir = Path(auth_secret_file).parent
            if secret_dir.resolve() == out_file.parent.resolve():
                raise ValueError("nuclei auth secret file must not live in the raw artifact dir")
            mounts.append((secret_dir, CONTAINER_SECRETS, "ro"))
        # Nuclei image is root today; still prep so auth secrets stay readable if the image uid changes.
        prepare_docker_bind_mounts(mounts)
        hosts = [(target.host, target.ip)] if isinstance(target, PinnedTarget) else []
        return docker_run_argv(
            config.SCANNER_IMAGES[self.image_key],
            name=name or new_container_name(self.name),
            mounts=mounts,
            add_hosts=hosts,
            entrypoint=self.docker_entrypoint,
            args=self.docker_args(target, out_file=out_file, profile=profile, **opts),
        )

    def _scan_nuclei(self, pin, *, out_dir, cancel=None, profile="baseline", intrusive_allowed=False, crawl=None, auth_secret_file=None, redact_values=(), target_urls=None):
        opts = {"crawl": crawl} if crawl is not None else {}
        if auth_secret_file is not None:
            opts["auth_secret_file"] = auth_secret_file
        if redact_values:
            opts["redact_values"] = tuple(redact_values)
        if target_urls:
            opts["target_urls"] = list(target_urls)
        sr = super().scan(
            pin, out_dir=out_dir, cancel=cancel, profile=profile, intrusive_allowed=intrusive_allowed, **opts
        )
        _fail_on_fatal_empty(sr)
        return sr

    def scan(self, pin, *, out_dir, cancel=None, profile="baseline", intrusive_allowed=False, crawl=None, auth_secret_file=None, redact_values=(), session_guard=None):  # type: ignore[override]
        """Find more same-host URLs (ZAP list or a quick crawl), then run nuclei.

        Authenticated scans with a live :class:`~attestra.auth_web.session_guard.SessionGuard`
        run the URL list in chunks and re-verify the session between chunks (re-login and
        rewrite the ``-sf`` file when it died; stop and report the rest as blocked when
        recovery fails). Everything else is a single nuclei run.
        """
        try:
            _discover_urls(pin, crawl, auth_secret_file, cancel)
        except Exception:  # noqa: BLE001 - discovery never stops the scan
            pass
        urls = _target_urls(pin, crawl) or [_url(pin)]
        chunk = auth_chunk_size()
        if session_guard is not None and getattr(session_guard, "enabled", False) and auth_secret_file and len(urls) > chunk:
            sr = self._scan_chunked(
                pin, urls, out_dir=out_dir, cancel=cancel, profile=profile, intrusive_allowed=intrusive_allowed,
                crawl=crawl, auth_secret_file=auth_secret_file, redact_values=redact_values, guard=session_guard,
                chunk=chunk,
            )
        else:
            sr = self._scan_nuclei(
                pin, out_dir=out_dir, cancel=cancel, profile=profile, intrusive_allowed=intrusive_allowed,
                crawl=crawl, auth_secret_file=auth_secret_file, redact_values=redact_values,
            )
            if session_guard is not None and getattr(session_guard, "enabled", False) and auth_secret_file:
                # Single run: one post-scan liveness check tells the report whether the session
                # was still alive at the end (cannot re-run, so a loss is recorded, not fixed).
                ok, note = session_guard.alive()
                if not ok:
                    session_guard.recover(note)
                sr.extra["auth"] = session_guard.public()
        _record_nuclei_summary(pin, out_dir, crawl, sr)
        return sr

    def _scan_chunked(self, pin, urls, *, out_dir, cancel, profile, intrusive_allowed, crawl, auth_secret_file, redact_values, guard, chunk):
        out_dir.mkdir(parents=True, exist_ok=True)
        merged = out_dir / self.out_name
        if merged.exists():
            merged.unlink()
        chunks = [urls[i:i + chunk] for i in range(0, len(urls), chunk)]
        done: list[dict] = []
        blocked: list[str] = []
        last = None
        redact = tuple(redact_values or ())
        for idx, part in enumerate(chunks, 1):
            if cancel is not None and cancel.is_set():
                blocked.extend(u for rest in chunks[idx - 1:] for u in rest)
                break
            if idx > 1:
                ok, note = guard.check_and_recover()
                if not ok:
                    blocked.extend(u for rest in chunks[idx - 1:] for u in rest)
                    done.append({"chunk": idx, "urls": len(part), "status": "blocked", "note": note[:300]})
                    break
                redact = tuple(sorted(set(redact) | set(getattr(guard, "redact_values", ()) or ()), key=len, reverse=True))
            sub = out_dir / f"chunk-{idx:02d}"
            sr = self._scan_nuclei(
                pin, out_dir=sub, cancel=cancel, profile=profile, intrusive_allowed=intrusive_allowed,
                crawl=crawl, auth_secret_file=auth_secret_file, redact_values=redact, target_urls=part,
            )
            last = sr
            _append_chunk_outputs(sub, out_dir, self)
            done.append({"chunk": idx, "urls": len(part), "status": "error" if sr.error else "done", "returncode": sr.extra.get("returncode")})
            if sr.error or sr.extra.get("cancelled") or sr.extra.get("timed_out"):
                blocked.extend(u for rest in chunks[idx:] for u in rest)
                break
        from attestra.runner.scanners.base import ScannerResult

        if last is None:
            return ScannerResult(tool=self.name, tool_version=self.version(), error="nuclei did not run (cancelled before first chunk)")
        out = ScannerResult(
            tool=self.name, tool_version=last.tool_version, image_digest=last.image_digest,
            import_tool=self.import_tool, extra=dict(last.extra), error=last.error,
        )
        if not out.error and merged.exists():
            out.raw_path = merged
        elif not out.error:
            merged.write_bytes(b"")
            out.raw_path = merged
        out.extra["chunks"] = done
        out.extra["auth"] = guard.public()
        if blocked:
            out.extra["auth_blocked_urls"] = blocked
        return out


def _fail_on_fatal_empty(sr) -> None:
    """nuclei creates its -o file before it can die with [FTL]; an empty report after a
    non-zero exit (or an [FTL] line) is a failed run, not "0 findings"."""
    if sr.error or sr.raw_path is None or not sr.raw_path.exists():
        return
    rc = sr.extra.get("returncode")
    stderr = str(sr.extra.get("stderr") or "")
    fatal = "[FTL]" in stderr
    try:
        empty = sr.raw_path.stat().st_size == 0
    except OSError:
        empty = True
    if empty and (fatal or (rc not in (0, None))):
        line = next((ln for ln in stderr.splitlines() if "[FTL]" in ln), stderr.strip().splitlines()[-1] if stderr.strip() else "")
        sr.error = (
            f"nuclei failed (exit code {rc}) and produced no results; see {STDERR_LOG_NAME}: {line}"
        )[:1500]
        sr.raw_path = None


# ------------------------------------------------------------------ start URLs (crawl settings)

TARGETS_NAME = "nuclei-targets.txt"


def _all_urls(target, crawl) -> list[str]:
    """Root, then the start URLs (typed path, Extra Start URLs), then discovered URLs; deduped."""
    root = _url(target)
    urls = [root]
    seen = {root.rstrip("/")}
    for u in [*(getattr(crawl, "start_urls", None) or []), *(getattr(crawl, "discovered_urls", None) or [])]:
        key = str(u).rstrip("/")
        if key and key not in seen:
            seen.add(key)
            urls.append(str(u))
    return urls


def _target_urls(target, crawl) -> list[str]:
    """Root plus start URLs plus discovered URLs (capped: every URL multiplies the request count)."""
    if crawl is None:
        return []
    from attestra.runner import crawl as crawl_settings

    urls = _all_urls(target, crawl)
    if len(urls) < 2:
        return []
    return urls[: crawl_settings.nuclei_max_urls()]


def _discover_urls(pin, crawl, auth_secret_file, cancel) -> None:
    """Fill ``crawl.discovered_urls`` with a quick same-host crawl when no ZAP list was reused."""
    from attestra.runner import nuclei_urls

    if crawl is None or not isinstance(pin, PinnedTarget):
        return
    if getattr(crawl, "discovered_urls", None):
        return  # a finished ZAP scan's URL list was attached by crawl.scan_kwargs
    if not nuclei_urls.crawl_enabled():
        crawl.url_source = crawl.url_source or "root-only (quick crawl off: ATTESTRA_NUCLEI_CRAWL=0)"
        return
    root = _url(pin)
    headers = nuclei_urls.auth_headers_from_secret_file(auth_secret_file, pin.host)
    found, notes = nuclei_urls.crawl_site(
        root, list(getattr(crawl, "start_urls", []) or []), fetch=nuclei_urls.pinned_fetch(pin), headers=headers,
        scope=getattr(crawl, "scope", None), cancel=cancel,
    )
    crawl.notes = list(getattr(crawl, "notes", []) or []) + notes
    if found:
        crawl.discovered_urls = found
        crawl.url_source = "nuclei-crawl"
    else:
        crawl.url_source = "root-only"


def _write_targets(target, out_dir: Path, crawl, *, urls: list[str] | None = None) -> Path | None:
    """Write the ``-list`` file. Explicit ``urls`` (chunked auth scans) are written as given."""
    if urls is None:
        urls = _target_urls(target, crawl)
        if len(urls) < 2:
            return None
    elif not urls:
        return None
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / TARGETS_NAME
    path.write_text("\n".join(urls) + "\n", encoding="utf-8")
    return path


def auth_chunk_size() -> int:
    """URLs per nuclei run between session checks (``ATTESTRA_AUTH_NUCLEI_CHUNK``, default 25)."""
    import os

    try:
        n = int(os.environ.get("ATTESTRA_AUTH_NUCLEI_CHUNK", "25"))
    except ValueError:
        n = 25
    return max(1, n)


def _append_chunk_outputs(sub: Path, out_dir: Path, adapter) -> None:
    """Concatenate a chunk's JSONL report and stderr log onto the merged files in ``out_dir``."""
    try:
        part = sub / adapter.out_name
        if part.exists():
            data = part.read_bytes()
            if data and not data.endswith(b"\n"):
                data += b"\n"
            with (out_dir / adapter.out_name).open("ab") as fh:
                fh.write(data)
        log = sub / adapter.tool_log_name
        if log.exists():
            with (out_dir / adapter.tool_log_name).open("a", encoding="utf-8") as fh:
                fh.write(f"===== {sub.name} =====\n")
                fh.write(log.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        pass


def _record_nuclei_summary(target, out_dir: Path, crawl, sr) -> None:
    try:
        import json

        from attestra.runner import crawl as crawl_settings

        if not isinstance(target, PinnedTarget):
            return
        urls = _target_urls(target, crawl) or [_url(target)]
        start = list(getattr(crawl, "start_urls", []) or [])
        discovered = list(getattr(crawl, "discovered_urls", []) or [])
        mhe = crawl_settings.nuclei_max_host_errors()
        summary = {
            "tool": "nuclei",
            "root_url": _url(target),
            "start_urls": [u for u in urls[1:] if u in start],
            "url_source": getattr(crawl, "url_source", "") or "root-only",
            "urls_discovered": len(discovered),
            "urls_scanned": len(urls),
            "urls": urls,
            "max_host_errors": mhe if mhe > 0 else "off (-nmhe)",
            "notes": list(getattr(crawl, "notes", []) or []),
        }
        skipped = len(_all_urls(target, crawl)) - len(urls) if crawl is not None else 0
        if skipped > 0:
            summary["notes"].append(
                f"{skipped} URL(s) not sent to nuclei (limit ATTESTRA_NUCLEI_MAX_URLS={crawl_settings.nuclei_max_urls()})"
            )
        auth = sr.extra.get("auth") if isinstance(sr.extra, dict) else None
        if isinstance(auth, dict):
            summary["auth"] = auth
            if sr.extra.get("chunks"):
                summary["auth_chunks"] = sr.extra["chunks"]
            blocked = sr.extra.get("auth_blocked_urls") or []
            if auth.get("status") == "lost":
                summary["notes"].append(
                    f"authenticated session lost mid-scan and re-login failed; "
                    f"{len(blocked)} URL(s) not scanned authenticated (blocked): {auth.get('lost_reason') or ''}"
                )
                summary["auth_blocked_urls"] = list(blocked)[:200]
                summary["urls_scanned"] = max(0, len(urls) - len(blocked))
            elif int(auth.get("relogins") or 0) > 0:
                summary["notes"].append(f"authenticated session re-established {auth.get('relogins')}x mid-scan")
        (out_dir / crawl_settings.SUMMARY_NAME).write_text(json.dumps(summary, indent=2), encoding="utf-8")
        sr.extra["crawl"] = summary
    except Exception:  # noqa: BLE001 - display data only
        pass
