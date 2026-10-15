"""Process runner and scanner adapter base."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from attestra import config
from attestra.runner.authorization import assert_safe_cli_arg
from attestra.runner.dns_pin import PinnedTarget


@dataclass
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    cancelled: bool = False


@dataclass
class ScannerResult:
    tool: str
    tool_version: str = ""
    image_digest: str = ""
    raw_path: Path | None = None
    raw_sha256: str = ""
    quarantine: bool = False
    quarantine_reason: str = ""
    import_tool: str = ""  # tool name for services.import_results (e.g. sarif for semgrep)
    extra: dict = field(default_factory=dict)
    error: str = ""  # set when the scanner did not produce a usable report


def which(name: str) -> str | None:
    return shutil.which(name)


def docker_available() -> bool:
    return which("docker") is not None


def _kill_process_tree(proc: subprocess.Popen) -> None:
    """Best-effort kill of the process and its children (Windows + POSIX)."""
    if proc.poll() is not None:
        return
    try:
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                capture_output=True,
                check=False,
            )
        else:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                proc.kill()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def run_process(
    argv: list[str],
    *,
    timeout: float | None = None,
    cancel: threading.Event | None = None,
    cwd: str | Path | None = None,
    env: dict | None = None,
) -> ProcessResult:
    """Run argv without a shell; kill the process tree on timeout or cancel."""
    for a in argv:
        assert_safe_cli_arg(a)
    timeout = timeout if timeout is not None else config.SCANNER_TIMEOUT_S
    # Output goes to temporary files, not pipes: a scanner that prints more than the pipe
    # buffer (about 4 KB on Windows) would otherwise block forever while we only poll.
    out_fh = tempfile.TemporaryFile()
    err_fh = tempfile.TemporaryFile()
    kwargs: dict = {
        "args": argv,
        "stdin": subprocess.DEVNULL,
        "stdout": out_fh,
        "stderr": err_fh,
        "cwd": str(cwd) if cwd else None,
        "env": env,
    }
    if sys.platform != "win32":
        kwargs["start_new_session"] = True
    else:
        # New process group (tree kill) and no console window for the hidden worker.
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(
            subprocess, "CREATE_NO_WINDOW", 0
        )

    try:
        proc = subprocess.Popen(**kwargs)
        deadline = time.monotonic() + timeout
        cancelled = timed_out = False
        while proc.poll() is None:
            if cancel is not None and cancel.is_set():
                cancelled = True
                _kill_process_tree(proc)
                break
            if time.monotonic() >= deadline:
                timed_out = True
                _kill_process_tree(proc)
                break
            time.sleep(0.5)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _kill_process_tree(proc)
            proc.wait(timeout=10)
        out_fh.seek(0)
        err_fh.seek(0)
        stdout, stderr = out_fh.read(), err_fh.read()
    finally:
        out_fh.close()
        err_fh.close()
    return ProcessResult(
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=stdout or b"",
        stderr=stderr or b"",
        timed_out=timed_out,
        cancelled=cancelled,
    )


# ------------------------------------------------------------------ docker helpers

CONTAINER_OUT = "/out"
CONTAINER_SRC = "/src"


def is_ip_literal(host: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def docker_host_path(path: Path | str) -> str:
    """Absolute host path for ``docker run -v`` (Docker Desktop accepts ``E:\\dir`` on Windows)."""
    return str(Path(path).resolve())


def new_container_name(tool: str) -> str:
    return f"attestra-{tool.replace('_', '-')}-{uuid.uuid4().hex[:12]}"


def docker_run_argv(
    image: str,
    *,
    name: str,
    mounts: list[tuple[Path | str, str, str]] = (),
    add_hosts: list[tuple[str, str]] = (),
    entrypoint: str | None = None,
    args: list[str] = (),
) -> list[str]:
    """``docker run`` for one scanner container: removed afterwards, named so it can be stopped.

    ``mounts`` is (host path, container path, "ro"|"rw"). ``add_hosts`` pins a host name to the
    gate's resolved IP inside the container; IP literals need no pin.
    """
    argv = ["docker", "run", "--rm", "--name", name, "--security-opt", "no-new-privileges"]
    for host, ip in add_hosts:
        if host and not is_ip_literal(host):
            argv += ["--add-host", f"{host}:{ip}"]
    for src, dst, mode in mounts:
        argv += ["-v", f"{docker_host_path(src)}:{dst}:{mode}"]
    if entrypoint:
        argv += ["--entrypoint", entrypoint]
    argv.append(require_digest_image(image))
    argv += list(args)
    return argv


def stop_container(name: str) -> None:
    """Stop and remove one named scanner container (only ever the one this run started)."""
    if not name or not name.startswith("attestra-"):
        return
    try:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False, timeout=60)
    except Exception:
        pass


def _tail(data: bytes, n: int = 1500) -> str:
    return data.decode("utf-8", errors="replace").strip()[-n:]


class ScannerAdapter(ABC):
    name: str
    import_tool: str  # zap|nuclei|trivy|sarif
    out_name: str = ""  # report file name inside out_dir (default <name>-out.json)
    image_key: str = ""  # key in config.SCANNER_IMAGES when the tool can run in Docker
    default_timeout_s: int | None = None  # per-tool default; None uses ATTESTRA_SCANNER_TIMEOUT_S
    report_on_stdout: bool = False  # the tool prints its report instead of writing a file
    empty_report_ok: bool = False  # an empty report with exit code 0 means "no findings"

    @abstractmethod
    def available(self) -> bool: ...

    @abstractmethod
    def version(self) -> str: ...

    @abstractmethod
    def build_argv(self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline") -> list[str]: ...

    def resolve_output(self, out_file: Path) -> Path:
        """Where the tool actually wrote its report (some tools add their own suffix)."""
        return out_file

    def timeout_s(self) -> int:
        """ATTESTRA_SCANNER_TIMEOUT_<TOOL>, else the tool default, else ATTESTRA_SCANNER_TIMEOUT_S."""
        own = os.environ.get(f"ATTESTRA_SCANNER_TIMEOUT_{self.name.upper()}", "").strip()
        if own.isdigit():
            return int(own)
        return max(self.default_timeout_s or 0, config.SCANNER_TIMEOUT_S)

    # -------------------------------------------------------------- docker mode

    def image_ref(self) -> str:
        return require_digest_image(config.SCANNER_IMAGES[self.image_key])

    def image_configured(self) -> bool:
        if not self.image_key or self.image_key not in config.SCANNER_IMAGES:
            return False
        image = config.SCANNER_IMAGES[self.image_key]
        return "@sha256:" in image and not config.image_is_placeholder(image)

    def uses_docker(self) -> bool:
        return self.image_configured() and docker_available()

    def docker_args(self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline", **opts) -> list[str]:
        """Arguments after the image name (report written under /out)."""
        raise NotImplementedError

    def docker_mounts(self, target: PinnedTarget | str, *, out_file: Path) -> list[tuple[Path | str, str, str]]:
        return [(out_file.parent, CONTAINER_OUT, "rw")]

    docker_entrypoint: str | None = None

    def build_docker_argv(
        self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline", name: str = "", **opts
    ) -> list[str]:
        hosts = [(target.host, target.ip)] if isinstance(target, PinnedTarget) else []
        return docker_run_argv(
            config.SCANNER_IMAGES[self.image_key],
            name=name or new_container_name(self.name),
            mounts=self.docker_mounts(target, out_file=out_file),
            add_hosts=hosts,
            entrypoint=self.docker_entrypoint,
            args=self.docker_args(target, out_file=out_file, profile=profile, **opts),
        )

    def unavailable_reason(self) -> str:
        if self.image_key and docker_available() and not self.image_configured():
            return (
                f"{self.name} cannot run: set ATTESTRA_IMAGE_{self.image_key.upper()} to a digest-pinned image "
                "(name@sha256:...) and restart the worker"
            )
        hint = "start Docker Desktop" if self.image_key else f"install {self.name}"
        return f"{self.name} cannot run on this machine: docker was not found and the {self.name} tool is not installed ({hint})"

    def validate_report(self, raw: bytes) -> str | None:
        """Return an error when the report cannot be read by the importer."""
        from attestra import importers

        try:
            importers.parse(self.import_tool, raw)
        except Exception as exc:  # noqa: BLE001 - any parse error means an unusable report
            return f"{self.name} output could not be read as {self.import_tool}: {exc}"[:500]
        return None

    def scan(
        self,
        pin: PinnedTarget | str,
        *,
        out_dir: Path,
        cancel: threading.Event | None = None,
        profile: str = "baseline",
        **opts,
    ) -> ScannerResult:
        config.ensure_dirs()
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / (self.out_name or f"{self.name}-out.json")
        if out_file.exists():
            out_file.unlink()  # never import a report left over from an earlier attempt
        container = ""
        digest = ""
        if self.uses_docker():
            container = new_container_name(self.name)
            argv = self.build_docker_argv(pin, out_file=out_file, profile=profile, name=container, **opts)
            digest = self.image_ref().split("@", 1)[-1]
        elif self.available():
            argv = self.build_argv(pin, out_file=out_file, profile=profile, **opts)
        else:
            return ScannerResult(tool=self.name, tool_version=self.version(), error=self.unavailable_reason())
        version = self.version() if not container else f"{self.name} (docker)"
        timeout = self.timeout_s()
        result = run_process(argv, cancel=cancel, timeout=timeout)
        if result.cancelled or result.timed_out:
            stop_container(container)
            return ScannerResult(
                tool=self.name,
                tool_version=version,
                image_digest=digest,
                error="" if result.cancelled else f"{self.name} timed out after {timeout}s",
                extra={"cancelled": result.cancelled, "timed_out": result.timed_out, "stderr": _tail(result.stderr)},
            )
        out_file = self.resolve_output(out_file)
        if not out_file.exists():
            if self.report_on_stdout and result.stdout.strip():
                out_file.write_bytes(result.stdout)
            elif self.empty_report_ok and result.returncode == 0:
                out_file.write_bytes(b"")
        extra = {"returncode": result.returncode, "argv": argv, "stderr": _tail(result.stderr)}
        sr = ScannerResult(
            tool=self.name, tool_version=version, image_digest=digest, import_tool=self.import_tool, extra=extra
        )
        if not out_file.exists():
            detail = _tail(result.stderr) or _tail(result.stdout)
            sr.error = f"{self.name} wrote no report (exit code {result.returncode}): {detail}"[:1500]
            return sr
        problem = self.validate_report(out_file.read_bytes())
        if problem:
            detail = _tail(result.stderr) or _tail(result.stdout)
            sr.error = f"{problem} (exit code {result.returncode}). {detail}"[:1500]
            return sr
        # A valid report is success even with a non-zero exit code (ZAP 1/2 on WARN/FAIL, semgrep 1 on findings).
        sr.raw_path = out_file
        return sr


def require_digest_image(image: str) -> str:
    return config.require_image_digest(image)
